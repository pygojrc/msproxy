package mspx

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net"
	"sync"
	"unicode/utf8"

	"github.com/xtls/xray-core/common/protocol"
)

const (
	magic          = "MSPX"
	window         = 262144
	dataMax        = 16384
	recordMax      = dataMax + 25
	opConnect byte = 1
	opResult  byte = 2
	opData    byte = 3
	opWindow  byte = 4
	opEOF     byte = 5
	opClose   byte = 6
)

var errProtocol = errors.New("MSPX 协议错误")

type target struct {
	Host string `json:"host"`
	Port uint16 `json:"port"`
}

type result struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

type wire struct {
	conn         net.Conn
	tx, rx       cipher.AEAD
	txSeq, rxSeq uint64
	txDir, rxDir byte
	mu           sync.Mutex
	touch        func()
}

func mac(key []byte, parts ...[]byte) []byte {
	h := hmac.New(sha256.New, key)
	for _, part := range parts {
		h.Write(part)
	}
	return h.Sum(nil)
}

// 分帧属于 MSPX；底层 TCP、TLS、WS 等只提供有序字节流。
func readFrame(r io.Reader, min, max int) ([]byte, error) {
	var header [2]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(header[:]))
	if n < min || n > max {
		return nil, errProtocol
	}
	b := make([]byte, n)
	_, err := io.ReadFull(r, b)
	return b, err
}

func writeFrame(w io.Writer, body []byte) error {
	if len(body) == 0 || len(body) > recordMax {
		return errProtocol
	}
	b := make([]byte, 2+len(body))
	binary.BigEndian.PutUint16(b, uint16(len(body)))
	copy(b[2:], body)
	for len(b) > 0 {
		n, err := w.Write(b)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	return nil
}

func newWire(conn net.Conn, key, cn, sn []byte, client bool) (*wire, error) {
	salt := sha256.Sum256(append(append([]byte("MSPX keys\x00"), cn...), sn...))
	derive := func(info string) (cipher.AEAD, error) {
		k, err := hkdf.Key(sha256.New, key, salt[:], info, 32)
		if err != nil {
			return nil, err
		}
		block, err := aes.NewCipher(k)
		if err != nil {
			return nil, err
		}
		return cipher.NewGCM(block)
	}
	c2s, err := derive("MSPX c2s")
	if err != nil {
		return nil, err
	}
	s2c, err := derive("MSPX s2c")
	if err != nil {
		return nil, err
	}
	w := &wire{conn: conn, tx: c2s, rx: s2c, txDir: 0, rxDir: 1}
	if !client {
		w.tx, w.rx, w.txDir, w.rxDir = s2c, c2s, 1, 0
	}
	return w, nil
}

func clientHandshake(conn net.Conn, key []byte) (*wire, error) {
	cn := make([]byte, 32)
	if _, err := rand.Read(cn); err != nil {
		return nil, err
	}
	hello := append([]byte(magic), cn...)
	hello = append(hello, mac(key, []byte("MSPX client\x00"), cn)...)
	if err := writeFrame(conn, hello); err != nil {
		return nil, err
	}
	b, err := readFrame(conn, 68, 68)
	if err != nil {
		return nil, err
	}
	if string(b[:4]) != magic || !hmac.Equal(b[36:], mac(key, []byte("MSPX server\x00"), cn, b[4:36])) {
		return nil, errProtocol
	}
	return newWire(conn, key, cn, b[4:36], true)
}

func serverHandshake(conn net.Conn, users []*protocol.MemoryUser) (*wire, *protocol.MemoryUser, error) {
	b, err := readFrame(conn, 68, 68)
	if err != nil {
		return nil, nil, err
	}
	if string(b[:4]) != magic {
		return nil, nil, errProtocol
	}
	var selected *protocol.MemoryUser
	var key []byte
	// 沿用原握手，没有明文用户标识；配置账户通过 HMAC 匹配。
	for _, user := range users {
		a := user.Account.(*MemoryAccount)
		if hmac.Equal(b[36:], mac(a.Key, []byte("MSPX client\x00"), b[4:36])) {
			selected, key = user, a.Key
		}
	}
	if selected == nil {
		return nil, nil, errProtocol
	}
	sn := make([]byte, 32)
	if _, err := rand.Read(sn); err != nil {
		return nil, nil, err
	}
	hello := append([]byte(magic), sn...)
	hello = append(hello, mac(key, []byte("MSPX server\x00"), b[4:36], sn)...)
	if err := writeFrame(conn, hello); err != nil {
		return nil, nil, err
	}
	w, err := newWire(conn, key, b[4:36], sn, false)
	return w, selected, err
}

func valid(op byte, p []byte) bool {
	if op == opData {
		return len(p) > 0 && len(p) <= dataMax
	}
	if len(p) > 1024 {
		return false
	}
	switch op {
	case opConnect, opResult:
		return len(p) > 0 && utf8.Valid(p)
	case opWindow:
		return len(p) == 4
	case opEOF:
		return len(p) == 0
	case opClose:
		return utf8.Valid(p)
	}
	return false
}

func aad(dir byte, seq []byte) []byte {
	return append(append([]byte(magic), dir), seq...)
}

func (w *wire) send(op byte, p []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !valid(op, p) || w.txSeq == math.MaxUint64 {
		return errProtocol
	}
	seq := make([]byte, 8)
	binary.BigEndian.PutUint64(seq, w.txSeq)
	nonce := append(make([]byte, 4), seq...)
	body := w.tx.Seal(seq, nonce, append([]byte{op}, p...), aad(w.txDir, seq))
	if err := writeFrame(w.conn, body); err != nil {
		return err
	}
	w.txSeq++
	if w.touch != nil {
		w.touch()
	}
	return nil
}

func (w *wire) receive() (byte, []byte, error) {
	b, err := readFrame(w.conn, 25, recordMax)
	if err != nil {
		return 0, nil, err
	}
	if w.rxSeq == math.MaxUint64 || binary.BigEndian.Uint64(b[:8]) != w.rxSeq {
		return 0, nil, errProtocol
	}
	nonce := append(make([]byte, 4), b[:8]...)
	p, err := w.rx.Open(nil, nonce, b[8:], aad(w.rxDir, b[:8]))
	if err != nil || len(p) == 0 || !valid(p[0], p[1:]) {
		return 0, nil, errProtocol
	}
	w.rxSeq++
	if w.touch != nil {
		w.touch()
	}
	return p[0], p[1:], nil
}

func (w *wire) sendJSON(op byte, value any) error {
	b, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return w.send(op, b)
}
