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
	"github.com/pion/transport/v2"
)

type Stats struct {
	bytesReadPerSecond float64
	bytesRead          uint64
	reads              uint64
	readsRaw           uint64
	writes             uint64
	writesPerSecond    float64
	percentageComplete float64
	totalTime          time.Duration
}

func (s Stats) String() string {
	return fmt.Sprintf("stats: %fMb/s (%d Mb) reads=%d (%d) writes=%d missing=%d writes/s=%f pct_done=%f%% total_time=%s",
		s.bytesReadPerSecond*8/1000/1000,
		s.bytesRead*8/1000/1000,
		s.reads,
		s.readsRaw,
		s.writes,
		s.writes-s.reads,
		s.writesPerSecond,
		s.percentageComplete,
		s.totalTime,
	)
}

func TestPacketThroughput(t *testing.T, makeReaderWriterPair func(t *testing.T) (io.ReadCloser, io.WriteCloser, error)) {
	sizes := []int64{
		1,
		10,
		100,
		1000,
	}

	const maxThroughputBitsPerSecond = 10 * 1000 * 1000 // 10Mibs

	totalBitsToSend := int64(600 * 1000 * 1000) // 600Mib for a 10Mib/s BW over 60 seconds

	for _, size := range sizes {
		t.Run(fmt.Sprintf("%d", size), func(t *testing.T) {
			if (totalBitsToSend/8)%size != 0 {
				t.Fatalf("totalBitsToSend in bytes %d must be evenly divisible by size %d", totalBitsToSend/8, size)
			}

			numWrites := totalBitsToSend / 8 / size
			t.Log("Will send a total of", float64(totalBitsToSend)/1000/1000, "Mb")
			waitForBytes := totalBitsToSend / 8

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
			var copied, bytesRead, totalReads, totalReadsRaw, totalWrites int64
			ticker := time.NewTicker(time.Second * 1)
			started := time.Now()
			var writesDone bool
			var writesFinishedAt time.Time

			calcStats := func() Stats {
				s := Stats{
					bytesReadPerSecond: float64(atomic.LoadInt64(&copied)) / time.Since(started).Seconds(),
					percentageComplete: float64(atomic.LoadInt64(&copied)) / float64(waitForBytes) * 100.0,
					bytesRead:          uint64(bytesRead),
					reads:              uint64(atomic.LoadInt64(&totalReads)),
					readsRaw:           uint64(atomic.LoadInt64(&totalReadsRaw)),
					writes:             uint64(atomic.LoadInt64(&totalWrites)),
					totalTime:          time.Since(started),
				}
				if writesDone {
					s.writesPerSecond = float64(atomic.LoadInt64(&totalWrites)) / writesFinishedAt.Sub(started).Seconds()
				} else {
					s.writesPerSecond = float64(atomic.LoadInt64(&totalWrites)) / time.Since(started).Seconds()
				}
				return s
			}

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

			data := make([]byte, size)
			_, err = rand.Read(data)
			if err != nil {
				t.Fatal(err)
			}

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
					atomic.AddInt64(&bytesRead, int64(n))
					atomic.AddInt64(&totalReadsRaw, 1)
					atomic.StoreInt64(&totalReads, copied/size)
					if nowCopied == waitForBytes {
						close(done)
						return
					}
				}
			}()

			// pacer so we don't overflow buffers
			maxWritesPerSecond := maxThroughputBitsPerSecond / (len(data) * 8)
			writeDur := time.Second / time.Duration(maxWritesPerSecond)
			t.Log("max writes per second", maxWritesPerSecond, "wait", writeDur, "per sec", len(data)*maxWritesPerSecond)
			writeTicker := time.NewTicker(writeDur)
			defer writeTicker.Stop()
			for i := 0; i < int(numWrites); i++ {
				<-writeTicker.C
				_, err := writer.Write(data)
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
	Conn   transport.UDPConn
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
