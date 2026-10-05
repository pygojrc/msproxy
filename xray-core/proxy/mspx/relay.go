package mspx

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"sync"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/transport"
)

var errComplete = errors.New("MSPX 正常收尾")

// relay 的交付对象是 Xray Link；正常完成只关闭协议连接，不打断已关闭但仍待排空的管道。
func relay(parent context.Context, link *transport.Link, w *wire, sessionPolicy policy.Session) error {
	ctx, stop := context.WithCancelCause(parent)
	defer stop(context.Canceled)
	var mu sync.Mutex
	cond := sync.NewCond(&mu)
	credit, recvCredit, pending := window, window, 0
	sentEOF, receivedEOF, closedWrite := false, false, false
	sendingEOF := false
	complete := func() bool { return sentEOF && closedWrite && credit == window }
	draining := func() bool { return receivedEOF && (sentEOF || sendingEOF) && credit == window }
	type delivery struct {
		op byte
		p  []byte
	}
	queue := make(chan delivery, 257) // DATA 最多256条，EOF有独立控制槽。
	timer := signal.CancelAfterInactivity(ctx, func() { stop(errors.New("MSPX 连接空闲超时")) }, sessionPolicy.Timeouts.ConnectionIdle)
	defer timer.SetTimeout(0)
	w.touch = timer.Update
	cleanupDone := make(chan struct{})
	cleanup := context.AfterFunc(ctx, func() {
		defer close(cleanupDone)
		w.conn.Close()
		if context.Cause(ctx) != errComplete {
			common.Interrupt(link.Reader)
			common.Interrupt(link.Writer)
		}
		mu.Lock()
		cond.Broadcast()
		mu.Unlock()
	})
	defer func() {
		if !cleanup() {
			<-cleanupDone
		}
	}()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for ctx.Err() == nil {
			mb, readErr := link.Reader.ReadMultiBuffer()
			failed := false
			for _, b := range mb {
				if b == nil {
					continue
				}
				data := b.Bytes()
				for len(data) > 0 {
					mu.Lock()
					for credit == 0 && ctx.Err() == nil {
						cond.Wait()
					}
					if ctx.Err() != nil {
						mu.Unlock()
						failed = true
						break
					}
					n := min(len(data), dataMax, credit)
					credit -= n
					mu.Unlock()
					if err := w.send(opData, data[:n]); err != nil {
						stop(err)
						failed = true
						break
					}
					data = data[n:]
				}
				if failed {
					break
				}
			}
			buf.ReleaseMulti(mb)
			if failed {
				return
			}
			if readErr == io.EOF {
				mu.Lock()
				sendingEOF = true
				mu.Unlock()
				if err := w.send(opEOF, nil); err != nil {
					stop(err)
					return
				}
				timer.SetTimeout(sessionPolicy.Timeouts.DownlinkOnly)
				mu.Lock()
				sentEOF = true
				sendingEOF = false
				finished := complete()
				mu.Unlock()
				if finished {
					stop(errComplete)
				}
				return
			}
			if readErr != nil {
				stop(readErr)
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		writer := buf.NewBufferedWriter(link.Writer)
		if err := writer.SetBuffered(false); err != nil {
			stop(err)
			return
		}
		for {
			select {
			case <-ctx.Done():
				return
			case item := <-queue:
				if item.op == opEOF {
					if err := common.Close(link.Writer); err != nil {
						stop(err)
						return
					}
					timer.SetTimeout(sessionPolicy.Timeouts.UplinkOnly)
					mu.Lock()
					closedWrite = true
					finished := complete()
					mu.Unlock()
					if finished {
						stop(errComplete)
					}
					return
				}
				if _, err := writer.Write(item.p); err != nil {
					stop(err)
					return
				}
				var amount [4]byte
				binary.BigEndian.PutUint32(amount[:], uint32(len(item.p)))
				// 已交付字节先恢复本地信用；网络写不能持流控锁，否则双向背压会死锁。
				mu.Lock()
				recvCredit += len(item.p)
				pending--
				mu.Unlock()
				err := w.send(opWindow, amount[:])
				if err != nil {
					stop(err)
					return
				}
			}
		}
	}()
	for ctx.Err() == nil {
		op, p, err := w.receive()
		if err != nil {
			mu.Lock()
			finished := complete()
			waiting := draining()
			mu.Unlock()
			if finished {
				stop(errComplete)
			} else if waiting && err != errProtocol {
				// 对端可在读到 EOF/最终 WINDOW 后立即关闭；等待本地发送和交付状态提交。
				<-ctx.Done()
			} else {
				stop(err)
			}
			break
		}
		switch op {
		case opData:
			mu.Lock()
			bad := receivedEOF || len(p) > recvCredit || pending >= 256
			if !bad {
				recvCredit -= len(p)
				pending++
			}
			mu.Unlock()
			if bad {
				stop(errProtocol)
				break
			}
			select {
			case queue <- delivery{op, p}:
			default:
				stop(errProtocol)
			}
		case opWindow:
			amount := int(binary.BigEndian.Uint32(p))
			mu.Lock()
			bad := amount < 1 || amount > window || credit > window-amount
			if !bad {
				credit += amount
				cond.Broadcast()
			}
			finished := complete()
			mu.Unlock()
			if bad {
				stop(errProtocol)
			} else if finished {
				stop(errComplete)
			}
		case opEOF:
			mu.Lock()
			bad := receivedEOF
			receivedEOF = true
			mu.Unlock()
			if bad {
				stop(errProtocol)
				break
			}
			select {
			case queue <- delivery{op, nil}:
			default:
				stop(errProtocol)
			}
		case opClose:
			mu.Lock()
			finished := complete()
			waiting := draining()
			mu.Unlock()
			if finished {
				stop(errComplete)
			} else if waiting {
				<-ctx.Done()
			} else {
				stop(errProtocol)
			}
		default:
			stop(errProtocol)
		}
	}
	wg.Wait()
	if context.Cause(ctx) == errComplete {
		return nil
	}
	return context.Cause(ctx)
}
