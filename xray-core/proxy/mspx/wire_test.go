package mspx

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/protocol"
)

type fragmentedConn struct{ net.Conn }

func (c fragmentedConn) Write(b []byte) (int, error) { return c.Conn.Write(b[:min(3, len(b))]) }
func (c fragmentedConn) Read(b []byte) (int, error)  { return c.Conn.Read(b[:min(2, len(b))]) }

func TestHandshakeWithStreamFragmentationAndMultipleUsers(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	a.SetDeadline(time.Now().Add(5 * time.Second))
	b.SetDeadline(time.Now().Add(5 * time.Second))
	users := []*protocol.MemoryUser{}
	for _, value := range []byte{1, 2} {
		account, err := (&Account{Psk: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{value}, 32))}).AsAccount()
		if err != nil {
			t.Fatal(err)
		}
		users = append(users, &protocol.MemoryUser{Account: account, Email: string([]byte{value})})
	}
	done := make(chan error, 1)
	go func() {
		w, user, err := serverHandshake(fragmentedConn{b}, users)
		if err == nil && user != users[1] {
			err = errProtocol
		}
		if err == nil {
			var op byte
			var p []byte
			op, p, err = w.receive()
			if err == nil && (op != opConnect || string(p) != `{"host":"::1","port":1234}`) {
				err = errProtocol
			}
		}
		done <- err
	}()
	w, err := clientHandshake(fragmentedConn{a}, users[1].Account.(*MemoryAccount).Key)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.send(opConnect, []byte(`{"host":"::1","port":1234}`)); err != nil {
		t.Fatal(err)
	}
	await(t, done)
}

func TestFramingAndAuthenticationFailures(t *testing.T) {
	for _, header := range []uint16{0, recordMax + 1} {
		var b [2]byte
		binary.BigEndian.PutUint16(b[:], header)
		if _, err := readFrame(bytes.NewReader(b[:]), 25, recordMax); err == nil {
			t.Fatal("非法长度被接受")
		}
	}
	if _, err := readFrame(bytes.NewReader([]byte{0, 68, 1}), 68, 68); err != io.ErrUnexpectedEOF {
		t.Fatalf("截断帧: %v", err)
	}
	for _, mode := range []string{"tamper", "repeat", "cross-session"} {
		t.Run(mode, func(t *testing.T) {
			cw, sw := testWires(t)
			var seq [8]byte
			body := cw.tx.Seal(seq[:], append(make([]byte, 4), seq[:]...), []byte{opData, 5}, aad(0, seq[:]))
			if mode == "tamper" {
				body[len(body)-1] ^= 1
			}
			if mode == "cross-session" {
				var err error
				sw, err = newWire(sw.conn, bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32), bytes.Repeat([]byte{4}, 32), false)
				if err != nil {
					t.Fatal(err)
				}
			}
			done := make(chan error, 1)
			go func() { done <- writeFrame(cw.conn, body) }()
			_, _, err := sw.receive()
			await(t, done)
			if mode == "repeat" {
				if err != nil {
					t.Fatal(err)
				}
				go func() { done <- writeFrame(cw.conn, body) }()
				_, _, err = sw.receive()
				await(t, done)
			}
			if err == nil {
				t.Fatal("无效密文被接受")
			}
		})
	}
}
