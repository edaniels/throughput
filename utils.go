package throughput

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/sctp"
)

type Stats struct {
	bytesReadPerSecond float64
	reads              uint64
	writes             uint64
	writesPerSecond    float64
	percentageComplete float64
}

func (s Stats) String() string {
	return fmt.Sprintf("stats: MiB/s=%f reads=%d writes=%d missing=%d writes/s=%f pct_done=%f%%",
		s.bytesReadPerSecond/1024.0/1024.0,
		s.reads,
		s.writes,
		s.writes-s.reads,
		s.writesPerSecond,
		s.percentageComplete,
	)
}

func TestPacketThroughput(t *testing.T, makeReaderWriterPair func(t *testing.T) (io.ReadCloser, io.WriteCloser, error)) {
	sizes := []int64{
		4,
		16,
		128,
		256,
		1024,
		// 4096,
		// 16384,
		// 32768,
	}

	numWrites := int64(1_000_000)

	for _, size := range sizes {
		t.Run(fmt.Sprintf("%d", size), func(t *testing.T) {
			waitForBytes := size * numWrites
			t.Log("Will send a total of", float64(waitForBytes)/1024/1024, "MiB", "or", waitForBytes, "bytes")

			reader, writer, err := makeReaderWriterPair(t)
			if err != nil {
				t.Fatal(err)
				return
			}
			defer reader.Close()
			defer writer.Close()
			// spew.Dump(reader)
			// spew.Dump(writer)

			done := make(chan struct{})
			var copied, totalReads, totalWrites int64
			ticker := time.NewTicker(time.Second * 1)
			started := time.Now()
			var writesDone bool
			var writesFinishedAt time.Time

			calcStats := func() Stats {
				s := Stats{
					bytesReadPerSecond: float64(atomic.LoadInt64(&copied)) / time.Since(started).Seconds(),
					percentageComplete: float64(atomic.LoadInt64(&copied)) / float64(waitForBytes) * 100.0,
					reads:              uint64(atomic.LoadInt64(&totalReads)),
					writes:             uint64(atomic.LoadInt64(&totalWrites)),
				}
				if writesDone {
					s.writesPerSecond = float64(atomic.LoadInt64(&totalWrites)) / writesFinishedAt.Sub(started).Seconds()
				} else {
					s.writesPerSecond = float64(atomic.LoadInt64(&totalWrites)) / time.Since(started).Seconds()
				}
				return s
			}

			// var waitWriteMu sync.Mutex
			// waitWrite := sync.NewCond(&waitWriteMu)

			go func() {
				for {
					select {
					case <-ticker.C:
						t.Log(calcStats())
					case <-done:
						return
					}
				}
			}()
			go func() {
				var buf [8192]byte
				for {
					n, err := reader.Read(buf[:])
					if err != nil {
						if errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) {
							println("EOF")
							return
						}
						panic(err)
					}
					nowCopied := atomic.AddInt64(&copied, int64(n))
					atomic.StoreInt64(&totalReads, copied/size)
					if nowCopied == waitForBytes {
						close(done)
						return
					}
				}
			}()

			bytes := make([]byte, size)
			_, err = rand.Read(bytes)
			if err != nil {
				t.Fatal(err)
			}

			for i := 0; i < int(numWrites); i++ {
				_, err := writer.Write(bytes)
				if err != nil {
					t.Fatal(err)
					break
				}
				atomic.AddInt64(&totalWrites, 1)
			}
			t.Log("all writes buffered")
			writesDone = true
			writesFinishedAt = time.Now()
			<-done
			t.Log("done!")
			t.Log(calcStats())
		})
	}
}

type PairedUDPWriter struct {
	Conn   *net.UDPConn
	ToAddr net.Addr
}

func (w PairedUDPWriter) Write(p []byte) (n int, err error) {
	return w.Conn.WriteTo(p, w.ToAddr)
}

func (w PairedUDPWriter) Close() error {
	return w.Conn.Close()
}

type SCTPStreamConnWrapper struct {
	*sctp.Stream
}

func (s SCTPStreamConnWrapper) LocalAddr() net.Addr {
	return nil
}

func (s SCTPStreamConnWrapper) RemoteAddr() net.Addr {
	return nil
}

func (s SCTPStreamConnWrapper) SetDeadline(time.Time) error {
	return nil
}

func (s SCTPStreamConnWrapper) SetReadDeadline(time.Time) error {
	return nil
}

func (s SCTPStreamConnWrapper) SetWriteDeadline(time.Time) error {
	return nil
}

type ConnCloserWrapper struct {
	net.Conn
	CloseFunc func() error
}

func (c ConnCloserWrapper) Close() error {
	return errors.Join(c.Conn.Close(), c.CloseFunc())
}
