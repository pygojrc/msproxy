package mspx

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

func testPolicy() policy.Session {
	p := policy.SessionDefault()
	p.Timeouts.ConnectionIdle = 10 * time.Second
	p.Timeouts.UplinkOnly = 10 * time.Second
	p.Timeouts.DownlinkOnly = 10 * time.Second
	return p
}

func testWires(t *testing.T) (*wire, *wire) {
	t.Helper()
	a, b := net.Pipe()
	t.Cleanup(func() { a.Close(); b.Close() })
	key, cn, sn := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32), bytes.Repeat([]byte{3}, 32)
	client, err := newWire(a, key, cn, sn, true)
	if err != nil {
		t.Fatal(err)
	}
	server, err := newWire(b, key, cn, sn, false)
	if err != nil {
		t.Fatal(err)
	}
	return client, server
}

func testLink() (*transport.Link, *pipe.Writer, *pipe.Reader) {
	in, appWriter := pipe.New(pipe.WithSizeLimit(0))
	appReader, out := pipe.New(pipe.WithSizeLimit(0))
	return &transport.Link{Reader: in, Writer: out}, appWriter, appReader
}

func writeApplication(w *pipe.Writer, data []byte) error {
	writer := buf.NewBufferedWriter(w)
	if err := writer.SetBuffered(false); err != nil {
		return err
	}
	for len(data) > 0 {
		n := min(len(data), 8192)
		if _, err := writer.Write(data[:n]); err != nil {
			return err
		}
		data = data[n:]
	}
	return w.Close()
}

func drain(r *pipe.Reader, slow bool) ([]byte, error) {
	var data []byte
	for {
		mb, err := r.ReadMultiBuffer()
		for _, b := range mb {
			data = append(data, b.Bytes()...)
		}
		buf.ReleaseMulti(mb)
		if err == io.EOF {
			return data, nil
		}
		if err != nil {
			return data, err
		}
		if slow {
			time.Sleep(time.Millisecond)
		}
	}
}

func await(t *testing.T, ch <-chan error) {
	t.Helper()
	select {
	case err := <-ch:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("MSPX 流控/EOF 超时")
	}
}

// 从 Link 两端验证大传输、背压和半关闭，不断言内部状态字段。
func TestRelayDuplexAndTail(t *testing.T) {
	cw, sw := testWires(t)
	cl, upload, downloads := testLink()
	sl, download, uploads := testLink()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	done := make(chan error, 6)
	u := bytes.Repeat([]byte("upload"), 200001)
	d := append(bytes.Repeat([]byte("download"), 1024*1024), bytes.Repeat([]byte{7}, 777)...)
	go func() { done <- relay(ctx, cl, cw, testPolicy()) }()
	go func() { done <- relay(ctx, sl, sw, testPolicy()) }()
	go func() { done <- writeApplication(upload, u) }()
	go func() { done <- writeApplication(download, d) }()
	go func() {
		got, err := drain(uploads, true)
		if err == nil && !bytes.Equal(got, u) {
			err = errProtocol
		}
		done <- err
	}()
	go func() {
		got, err := drain(downloads, true)
		if err == nil && !bytes.Equal(got, d) {
			err = errProtocol
		}
		done <- err
	}()
	for range 6 {
		await(t, done)
	}
}

func TestBlockedDeliveryAllowsOppositeDirection(t *testing.T) {
	cw, sw := testWires(t)
	cl, upload, downloads := testLink()
	sl, download, uploads := testLink()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	done := make(chan error, 5)
	downDone := make(chan error, 1)
	down := bytes.Repeat([]byte{9}, 2*window)
	up := bytes.Repeat([]byte{8}, 65536)
	go func() { done <- relay(ctx, cl, cw, testPolicy()) }()
	go func() { done <- relay(ctx, sl, sw, testPolicy()) }()
	go func() { downDone <- writeApplication(download, down) }()
	go func() { done <- writeApplication(upload, up) }()
	uploadProgress := make(chan error, 1)
	go func() {
		got, err := drain(uploads, false)
		if err == nil && !bytes.Equal(got, up) {
			err = errProtocol
		}
		uploadProgress <- err
	}()
	await(t, uploadProgress)
	select {
	case err := <-downDone:
		t.Fatalf("慢读未产生背压: %v", err)
	default:
	}
	go func() {
		got, err := drain(downloads, false)
		if err == nil && !bytes.Equal(got, down) {
			err = errProtocol
		}
		done <- err
	}()
	await(t, downDone)
	for range 4 {
		await(t, done)
	}
}

type gatedWriter struct {
	gate   chan struct{}
	mu     sync.Mutex
	data   []byte
	closed bool
}

func (w *gatedWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	defer buf.ReleaseMulti(mb)
	<-w.gate
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, b := range mb {
		w.data = append(w.data, b.Bytes()...)
	}
	return nil
}
func (w *gatedWriter) Close() error { w.mu.Lock(); w.closed = true; w.mu.Unlock(); return nil }
func (w *gatedWriter) Interrupt() {
	select {
	case <-w.gate:
	default:
		close(w.gate)
	}
}

func TestFullDataQueueHasEOFSpace(t *testing.T) {
	cw, sw := testWires(t)
	input, inputWriter := pipe.New()
	inputWriter.Close()
	output := &gatedWriter{gate: make(chan struct{})}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- relay(ctx, &transport.Link{Reader: input, Writer: output}, cw, testPolicy()) }()
	peerDone := make(chan error, 1)
	go func() {
		count := 0
		for count < 256 {
			op, p, err := sw.receive()
			if err != nil {
				peerDone <- err
				return
			}
			if op == opWindow {
				count += int(binary.BigEndian.Uint32(p))
			}
		}
		peerDone <- nil
	}()
	for range 256 {
		if err := sw.send(opData, []byte{5}); err != nil {
			t.Fatal(err)
		}
	}
	if err := sw.send(opEOF, nil); err != nil {
		t.Fatal(err)
	}
	close(output.gate)
	await(t, done)
	await(t, peerDone)
	output.mu.Lock()
	defer output.mu.Unlock()
	if len(output.data) != 256 || !output.closed {
		t.Fatalf("EOF 截断: data=%d closed=%v", len(output.data), output.closed)
	}
}

func TestFinalWindowMustArriveBeforeNormalClose(t *testing.T) {
	cw, sw := testWires(t)
	link, source, destination := testLink()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- relay(ctx, link, cw, testPolicy()) }()
	go func() { _ = writeApplication(source, []byte("last upload")) }()
	if err := sw.send(opEOF, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := drain(destination, false); err != nil {
		t.Fatal(err)
	}
	credit := 0
	for {
		op, p, err := sw.receive()
		if err != nil {
			t.Fatal(err)
		}
		if op == opData {
			credit += len(p)
		}
		if op == opEOF {
			break
		}
	}
	select {
	case err := <-done:
		t.Fatalf("最后 WINDOW 前提前退出: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	var amount [4]byte
	binary.BigEndian.PutUint32(amount[:], uint32(credit))
	if err := sw.send(opWindow, amount[:]); err != nil {
		t.Fatal(err)
	}
	sw.conn.Close()
	await(t, done)
}

func TestWindowOverflowAndCancellation(t *testing.T) {
	cw, sw := testWires(t)
	link, _, _ := testLink()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- relay(ctx, link, cw, testPolicy()) }()
	var amount [4]byte
	binary.BigEndian.PutUint32(amount[:], window)
	if err := sw.send(opWindow, amount[:]); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("透支窗口被接受")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("取消没有唤醒阻塞读写")
	}
}

func TestReaderEOFWithNilBuffers(t *testing.T) {
	cw, sw := testWires(t)
	cl, _, downloads := testLink()
	sl, download, uploads := testLink()
	// Xray 的 SingleReader 在 EOF 时可以返回包含 nil 的 MultiBuffer。
	cl.Reader = &buf.SingleReader{Reader: bytes.NewReader([]byte("EOF payload"))}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan error, 2)
	go func() { done <- relay(ctx, cl, cw, testPolicy()) }()
	go func() { done <- relay(ctx, sl, sw, testPolicy()) }()
	download.Close()
	if got, err := drain(uploads, false); err != nil || string(got) != "EOF payload" {
		t.Fatalf("EOF 数据丢失: %q %v", got, err)
	}
	if got, err := drain(downloads, false); err != nil || len(got) != 0 {
		t.Fatalf("空 EOF: %q %v", got, err)
	}
	await(t, done)
	await(t, done)
}
