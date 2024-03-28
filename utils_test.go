package throughput

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/pion/datachannel"
	"github.com/pion/dtls/v2"
	"github.com/pion/dtls/v2/pkg/crypto/selfsign"
	"github.com/pion/ice/v2"
	"github.com/pion/logging"
	"github.com/pion/sctp"
	"github.com/pion/stun"
	"github.com/pion/webrtc/v3"
)

const (
	serverPort = 1234
	clientPort = 1235

	serverAddr = "127.0.0.1:1234"
	clientAddr = "127.0.0.1:1235"
)

var (
	serverUDPAddr = &net.UDPAddr{Port: 1234}
	clientUDPAddr = &net.UDPAddr{Port: 1235}
)

// // all 250k w/s
//
//	sizes := []int64{
//		// 4, // 1 MiB/s
//		// 16, // 4 MiB/s
//		// 128, // 32 MiB/s
//		// 256, // 64 MiB/s
//		// 1024, // 256 MiB/s
//	}
//
// This is all OS net stack impl dependent
func TestThroughputUDP(t *testing.T) {
	TestPacketThroughput(t, func(t *testing.T) (io.ReadCloser, io.WriteCloser, error) {
		server, err := net.ListenUDP("udp4", serverUDPAddr)
		if err != nil {
			return nil, nil, err
		}

		client, err := net.ListenUDP("udp4", clientUDPAddr)
		if err != nil {
			return nil, nil, err
		}

		return server, PairedUDPWriter{client, server.LocalAddr()}, nil
	})
}

// all 241k w/s
// all data rates slightly lower than UDP
// This is all OS net stack impl dependent
func TestThroughputTCP(t *testing.T) {
	TestPacketThroughput(t, func(t *testing.T) (io.ReadCloser, io.WriteCloser, error) {
		server, err := net.Listen("tcp", serverAddr)
		if err != nil {
			return nil, nil, err
		}

		serverConn := make(chan net.Conn)
		go func() {
			conn, err := server.Accept()
			if err != nil {
				panic(err)
			}
			serverConn <- conn
		}()

		fmt.Println(server.Addr().(*net.TCPAddr))

		client, err := net.Dial(server.Addr().Network(), server.Addr().String())
		if err != nil {
			return nil, nil, err
		}

		return <-serverConn, client, nil
	})
}

// This is UDP over DTLS
//   - UDP is managed by the OS
//   - DTLS is managed by Pion
//   - Read Path
//   - dtls.Conn.Read: <-c.decrypted:
//     c.decrypted <- content.Data:
//     dtls.Conn:handleIncomingPacket: dtls.Conn:readAndBuffer: // doesn't really buffer
//     c.nextConn.ReadContext (*connctx.connCtx):
//     transport/v2/udp.Conn.Read: c.buffer.Read(p) (*packetio.Buffer):
//     listener.read -> l.dispatchMsg(raddr, buf[:n]): // buffering happens here
//     net.PacketConn.ReadFrom (go native)
//     listener.readLoop
//   - Write Path
//   - dtls.Conn.Write: c.writePackets:
//     c.nextConn.WriteContext (*connctx.connCtx):
//     udp.Conn.Write (go native)
func TestThroughputDTLS(t *testing.T) {
	TestPacketThroughput(t, func(t *testing.T) (io.ReadCloser, io.WriteCloser, error) {
		return pipeDTLS(t)
	})
}

//	sizes := []int64{
//		// 4, // 1.1 MiB/s
//		// 16, // 4.6 MiB/s
//		// 128, // 36 MiB/s
//		// 256, // 60 MiB/s
//		// 1024, // 239 MiB/s
//	}
func TestThroughputICE(t *testing.T) {
	TestPacketThroughput(t, func(t *testing.T) (io.ReadCloser, io.WriteCloser, error) {
		return pipeICE(t)
	})
}

// Note: no DTLS/ICE here.
//
//	sizes := []int64{
//		// 4, // .8 MiB/s
//		// 16, // 5.5 MiB/s
//		// 128, // 53 MiB/s
//		// 256, // 73 MiB/s
//		// 1024, // 148 MiB/s
//	}
func TestThroughputSCTPUnordered(t *testing.T) {
	TestPacketThroughput(t, func(t *testing.T) (io.ReadCloser, io.WriteCloser, error) {
		return pipeSCTPWithOpts(t, pipeUDP, func(writer *sctp.Stream) {
			writer.SetReliabilityParams(true, sctp.ReliabilityTypeReliable, 0)
		})
	})
}

// Note: no DTLS/ICE here.
//
//	sizes := []int64{
//		// 4, // .8 MiB/s
//		// 16, // 5.5 MiB/s
//		// 128, // 54 MiB/s
//		// 256, // 116 MiB/s
//		// 1024, // 156 MiB/s
//	}
func TestThroughputSCTPOrdered(t *testing.T) {
	TestPacketThroughput(t, func(t *testing.T) (io.ReadCloser, io.WriteCloser, error) {
		return pipeSCTPWithOpts(t, pipeUDP, func(writer *sctp.Stream) {
			writer.SetReliabilityParams(false, sctp.ReliabilityTypeReliable, 0)
		})
	})
}

//	sizes := []int64{
//		// 4, // .59 MiB/s
//		// 16, // 3.4 MiB/s
//		// 128, // 22 MiB/s
//		// 256, // 96 MiB/s
//		// 1024, // 107 MiB/s
//	}
func TestThroughputSCTPUnorderedOnDTLS(t *testing.T) {
	TestPacketThroughput(t, func(t *testing.T) (io.ReadCloser, io.WriteCloser, error) {
		return pipeSCTPWithOpts(t, pipeDTLS, func(writer *sctp.Stream) {
			writer.SetReliabilityParams(true, sctp.ReliabilityTypeReliable, 0)
		})
	})
}

//	sizes := []int64{
//		// 4, // .9 MiB/s
//		// 16, // 6.6 MiB/s
//		// 128, // 81 MiB/s
//		// 256, // 134 MiB/s
//		// 1024, // 130 MiB/s
//	}
func TestThroughputSCTPUnorderedOnICE(t *testing.T) {
	TestPacketThroughput(t, func(t *testing.T) (io.ReadCloser, io.WriteCloser, error) {
		return pipeSCTPWithOpts(t, pipeICE, func(writer *sctp.Stream) {
			writer.SetReliabilityParams(true, sctp.ReliabilityTypeReliable, 0)
		})
	})
}

//	sizes := []int64{
//		// 4, // .59 MiB/s
//		// 16, // 3.5 MiB/s
//		// 128, // 23 MiB/s
//		// 256, // 79 MiB/s
//		// 1024, // 100 MiB/s
//	}
//
// maybe a little bit slower because ICE has its own layer of buffering?
func TestThroughputSCTPUnorderedOnDTLSOnICE(t *testing.T) {
	TestPacketThroughput(t, func(t *testing.T) (io.ReadCloser, io.WriteCloser, error) {
		return pipeSCTPWithOpts(t, func(t *testing.T) (net.Conn, net.Conn, error) {
			reader, writer, err := pipeICE(t)
			if err != nil {
				return nil, nil, err
			}
			return pipeDTLSConn(t, func(t *testing.T) (net.Conn, net.Conn, error) {
				return reader, writer, nil
			})
		}, func(writer *sctp.Stream) {
			writer.SetReliabilityParams(true, sctp.ReliabilityTypeReliable, 0)
		})
	})
}

func TestThroughputDataChannelUnordered(t *testing.T) {
	TestPacketThroughput(t, func(t *testing.T) (io.ReadCloser, io.WriteCloser, error) {
		return pipeDataChannel(t, func(t *testing.T) (net.Conn, net.Conn, error) {
			reader, writer, err := pipeICE(t)
			if err != nil {
				return nil, nil, err
			}
			return pipeDTLSConn(t, func(t *testing.T) (net.Conn, net.Conn, error) {
				return reader, writer, nil
			})
		})
	})
}

func TestThroughputDataChannelNoDTLSUnordered(t *testing.T) {
	TestPacketThroughput(t, func(t *testing.T) (io.ReadCloser, io.WriteCloser, error) {
		return pipeDataChannel(t, func(t *testing.T) (net.Conn, net.Conn, error) {
			return pipeICE(t)
		})
	})
}

// todo(erd): ordered/unordered + other params
func TestThroughputWebRTCDataChannel(t *testing.T) {
	TestPacketThroughput(t, func(t *testing.T) (io.ReadCloser, io.WriteCloser, error) {
		writerPC, readerPC, err := newPair()
		if err != nil {
			return nil, nil, err
		}

		name := "data"
		readerDC := make(chan *webrtc.DataChannel)
		readerPC.OnDataChannel(func(d *webrtc.DataChannel) {
			if d.Label() == name {
				t.Log("got data channel. now waiting for open")
				d.OnOpen(func() {
					readerDC <- d
				})
			}
		})

		writerDC, err := writerPC.CreateDataChannel("data", nil)
		if err != nil {
			return nil, nil, err
		}

		writerDCReady := make(chan struct{})
		writerDC.OnOpen(func() {
			close(writerDCReady)
		})

		if err := signalPair(writerPC, readerPC); err != nil {
			return nil, nil, err
		}
		<-writerDCReady
		return NewDataChannelIOWrapper(<-readerDC), NewDataChannelIOWrapper(writerDC), nil
	})
}

type DataChannelIOWrapper struct {
	mu      sync.RWMutex
	dc      *webrtc.DataChannel
	readBuf bytes.Buffer
	closed  bool
}

func NewDataChannelIOWrapper(dc *webrtc.DataChannel) *DataChannelIOWrapper {
	wrapper := DataChannelIOWrapper{dc: dc}
	reads := 0
	go func() {
		for {
			time.Sleep(5 * time.Second)
			println("dc reads", reads)
		}
	}()
	dc.OnMessage(func(msg webrtc.DataChannelMessage) {
		wrapper.mu.Lock()
		defer wrapper.mu.Unlock()
		reads++
		if _, err := wrapper.readBuf.Write(msg.Data); err != nil {
			panic(err)
		}
	})
	return &wrapper
}

func (dc *DataChannelIOWrapper) Read(p []byte) (int, error) {
	dc.mu.RLock()
	defer dc.mu.RUnlock()
	if dc.closed {
		return 0, io.EOF
	}
	n, err := dc.readBuf.Read(p)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return 0, nil
		}
		return 0, err
	}
	return n, nil
}

func (dc *DataChannelIOWrapper) Write(p []byte) (n int, err error) {
	if err := dc.dc.Send(p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (dc *DataChannelIOWrapper) Close() error {
	dc.mu.Lock()
	dc.closed = true
	dc.mu.Unlock()
	return nil
}

func signalPairWithModification(pcOffer *webrtc.PeerConnection, pcAnswer *webrtc.PeerConnection, modificationFunc func(string) string) error {
	// Note(albrow): We need to create a data channel in order to trigger ICE
	// candidate gathering in the background for the JavaScript/Wasm bindings. If
	// we don't do this, the complete offer including ICE candidates will never be
	// generated.
	if _, err := pcOffer.CreateDataChannel("initial_data_channel", nil); err != nil {
		return err
	}

	offer, err := pcOffer.CreateOffer(nil)
	if err != nil {
		return err
	}
	offerGatheringComplete := webrtc.GatheringCompletePromise(pcOffer)
	if err = pcOffer.SetLocalDescription(offer); err != nil {
		return err
	}
	<-offerGatheringComplete

	offer.SDP = modificationFunc(pcOffer.LocalDescription().SDP)
	if err = pcAnswer.SetRemoteDescription(offer); err != nil {
		return err
	}

	answer, err := pcAnswer.CreateAnswer(nil)
	if err != nil {
		return err
	}
	answerGatheringComplete := webrtc.GatheringCompletePromise(pcAnswer)
	if err = pcAnswer.SetLocalDescription(answer); err != nil {
		return err
	}
	<-answerGatheringComplete
	return pcOffer.SetRemoteDescription(*pcAnswer.LocalDescription())
}

func signalPair(pcOffer *webrtc.PeerConnection, pcAnswer *webrtc.PeerConnection) error {
	return signalPairWithModification(pcOffer, pcAnswer, func(sessionDescription string) string { return sessionDescription })
}

// newPair creates two new peer connections (an offerer and an answerer)
// *without* using an api (i.e. using the default settings).
func newPair() (pcOffer *webrtc.PeerConnection, pcAnswer *webrtc.PeerConnection, err error) {
	pca, err := webrtc.NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		return nil, nil, err
	}

	pcb, err := webrtc.NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		return nil, nil, err
	}

	return pca, pcb, nil
}

func randomPort(t testing.TB) int {
	t.Helper()
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to pickPort: %v", err)
	}
	defer func() {
		_ = conn.Close()
	}()
	switch addr := conn.LocalAddr().(type) {
	case *net.UDPAddr:
		return addr.Port
	default:
		t.Fatalf("unknown addr type %T", addr)
		return 0
	}
}

func dtlsConfig() (*dtls.Config, error) {
	cert, err := selfsign.GenerateSelfSignedWithDNS("localhost")
	if err != nil {
		return nil, err
	}

	// choices
	// dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 // fastest
	// dtls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
	// dtls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA // slowest
	return &dtls.Config{
		Certificates:       []tls.Certificate{cert},
		CipherSuites:       []dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		InsecureSkipVerify: true,
	}, nil
}

func pipeDTLSConn(t *testing.T, piper piperFunc) (net.Conn, net.Conn, error) {
	cfg, err := dtlsConfig()
	if err != nil {
		return nil, nil, err
	}

	ca, cb, err := piper(t)
	if err != nil {
		return nil, nil, err
	}

	serverConn := make(chan net.Conn)
	go func() {
		server, err := dtls.Server(ca, cfg)
		if err != nil {
			panic(err)
		}
		serverConn <- server
	}()

	client, err := dtls.Client(cb, cfg)
	if err != nil {
		return nil, nil, err
	}

	return <-serverConn, client, err
}

func pipeDTLS(t *testing.T) (net.Conn, net.Conn, error) {
	cfg, err := dtlsConfig()
	if err != nil {
		return nil, nil, err
	}
	serverPort := randomPort(t)

	server, err := dtls.Listen("udp",
		&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: serverPort},
		cfg,
	)
	if err != nil {
		return nil, nil, err
	}

	serverConn := make(chan net.Conn)
	go func() {
		conn, err := server.Accept()
		if err != nil {
			panic(err)
		}
		serverConn <- conn
	}()

	client, err := dtls.Dial("udp",
		&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: serverPort},
		cfg,
	)
	if err != nil {
		return nil, nil, err
	}

	t.Logf("dtls on port %d", serverPort)
	return ConnCloserWrapper{Conn: <-serverConn, CloseFunc: server.Close}, client, err
}

func pipeICE(t *testing.T) (net.Conn, net.Conn, error) {
	var urls []*stun.URI

	onConnected := func() (func(ice.ConnectionState), chan struct{}) {
		done := make(chan struct{})
		return func(state ice.ConnectionState) {
			if state == ice.ConnectionStateConnected {
				close(done)
			}
		}, done
	}

	aNotifier, aConnected := onConnected()
	bNotifier, bConnected := onConnected()

	cfg := &ice.AgentConfig{}
	cfg.Urls = urls
	cfg.NetworkTypes = []ice.NetworkType{
		ice.NetworkTypeUDP4,
	}

	aAgent, err := ice.NewAgent(cfg)
	if err != nil {
		return nil, nil, err
	}
	if err := aAgent.OnConnectionStateChange(aNotifier); err != nil {
		return nil, nil, err
	}

	bAgent, err := ice.NewAgent(cfg)
	if err != nil {
		return nil, nil, err
	}

	if err := bAgent.OnConnectionStateChange(bNotifier); err != nil {
		return nil, nil, err
	}

	gatherAndExchangeCandidates := func(aAgent, bAgent *ice.Agent) error {
		var wg sync.WaitGroup
		wg.Add(2)

		if err := aAgent.OnCandidate(func(candidate ice.Candidate) {
			if candidate == nil {
				wg.Done()
			}
		}); err != nil {
			return err
		}
		if err := aAgent.GatherCandidates(); err != nil {
			return err
		}

		if err := bAgent.OnCandidate(func(candidate ice.Candidate) {
			if candidate == nil {
				wg.Done()
			}
		}); err != nil {
			return err
		}
		if err := bAgent.GatherCandidates(); err != nil {
			return err
		}

		wg.Wait()

		candidates, err := aAgent.GetLocalCandidates()
		if err != nil {
			return err
		}
		for _, c := range candidates {
			candidateCopy, copyErr := ice.UnmarshalCandidate(c.Marshal())
			if copyErr != nil {
				return copyErr
			}
			if err := bAgent.AddRemoteCandidate(candidateCopy); err != nil {
				return err
			}
		}

		candidates, err = bAgent.GetLocalCandidates()
		if err != nil {
			return err
		}
		for _, c := range candidates {
			candidateCopy, copyErr := ice.UnmarshalCandidate(c.Marshal())
			if copyErr != nil {
				return copyErr
			}
			if err := aAgent.AddRemoteCandidate(candidateCopy); err != nil {
				return err
			}
		}

		return nil
	}

	connect := func(aAgent, bAgent *ice.Agent) (*ice.Conn, *ice.Conn, error) {
		if err := gatherAndExchangeCandidates(aAgent, bAgent); err != nil {
			return nil, nil, err
		}

		accepted := make(chan struct{})
		var aConn *ice.Conn

		go func() {
			var acceptErr error
			bUfrag, bPwd, acceptErr := bAgent.GetLocalUserCredentials()
			if acceptErr != nil {
				panic(acceptErr)
			}
			aConn, acceptErr = aAgent.Accept(context.TODO(), bUfrag, bPwd)
			if acceptErr != nil {
				panic(acceptErr)
			}
			close(accepted)
		}()
		aUfrag, aPwd, err := aAgent.GetLocalUserCredentials()
		if err != nil {
			return nil, nil, err
		}
		bConn, err := bAgent.Dial(context.TODO(), aUfrag, aPwd)
		if err != nil {
			return nil, nil, err
		}

		// Ensure accepted
		<-accepted
		return aConn, bConn, nil
	}

	aConn, bConn, err := connect(aAgent, bAgent)
	if err != nil {
		return nil, nil, err
	}

	// Ensure pair selected
	// Note: this assumes ConnectionStateConnected is thrown after selecting the final pair
	<-aConnected
	<-bConnected

	return aConn, bConn, nil
}

func acceptDumbConn() (*dumbConn, error) {
	pConn, err := net.ListenUDP("udp4", serverUDPAddr)
	if err != nil {
		return nil, err
	}
	return &dumbConn{
		pConn: pConn,
	}, nil
}

func pipeUDP(t *testing.T) (net.Conn, net.Conn, error) {
	aConn, err := acceptDumbConn()
	if err != nil {
		return nil, nil, err
	}

	bConn, err := net.DialUDP("udp4", clientUDPAddr, aConn.LocalAddr().(*net.UDPAddr))
	if err != nil {
		return nil, nil, err
	}

	// Dumb handshake
	mgs := "Test"
	_, err = bConn.Write([]byte(mgs))
	if err != nil {
		return nil, nil, err
	}

	b := make([]byte, 4)
	_, err = aConn.Read(b)
	if err != nil {
		return nil, nil, err
	}

	if string(b) != mgs {
		panic("Dumb handshake failed")
	}

	return aConn, bConn, nil
}

func pipeSCTPWithOpts(t *testing.T, piper piperFunc, onWriteOpen func(s *sctp.Stream)) (io.ReadCloser, io.WriteCloser, error) {
	var err error

	var aa, ab *sctp.Association
	aa, ab, err = association(t, piper)
	if err != nil {
		return nil, nil, err
	}

	var sa, sb *sctp.Stream
	sa, err = aa.OpenStream(0, 0)
	if err != nil {
		return nil, nil, err
	}

	sb, err = ab.OpenStream(0, 0)
	if err != nil {
		return nil, nil, err
	}

	if onWriteOpen != nil {
		onWriteOpen(sb)
	}

	return ConnCloserWrapper{
			Conn: SCTPStreamConnWrapper{Stream: sa},
			CloseFunc: func() error {
				return aa.Close()
			},
		}, ConnCloserWrapper{
			Conn: SCTPStreamConnWrapper{Stream: sb},
			CloseFunc: func() error {
				return ab.Close()
			},
		}, nil
}

func pipeSCTP(t *testing.T, piper piperFunc) (io.ReadCloser, io.WriteCloser, error) {
	return pipeSCTPWithOpts(t, piper, nil)
}

func pipeDataChannel(t *testing.T, piper piperFunc) (io.ReadCloser, io.WriteCloser, error) {
	var aa, ab *sctp.Association
	aa, ab, err := association(t, piper)
	if err != nil {
		return nil, nil, err
	}

	loggerFactory := logging.NewDefaultLoggerFactory()
	cfg := &datachannel.Config{
		ChannelType:          datachannel.ChannelTypeReliableUnordered, // todo(erd): configure
		ReliabilityParameter: 0,                                        // todo(erd): configure
		Label:                "data",
		LoggerFactory:        loggerFactory,
	}

	dcWriter, err := datachannel.Dial(aa, 100, cfg)
	if err != nil {
		return nil, nil, err
	}

	dcReader, err := datachannel.Accept(ab, &datachannel.Config{
		LoggerFactory: loggerFactory,
	})
	if err != nil {
		return nil, nil, err
	}
	// dcReader.OnOpen()

	// go func() {
	// 	var buf [8192]byte
	// 	for {
	// 		_, err := dcWriter.Read(buf[:])
	// 		if err != nil {
	// 			return
	// 		}
	// 	}
	// }()

	return dcReader, dcWriter, nil
}

func association(t *testing.T, piper piperFunc) (*sctp.Association, *sctp.Association, error) {
	ca, cb, err := piper(t)
	if err != nil {
		return nil, nil, err
	}

	type result struct {
		a   *sctp.Association
		err error
	}

	c := make(chan result)
	// TODO(erd): make work for tests
	loggerFactory := logging.NewDefaultLoggerFactory()

	// Setup client
	go func() {
		client, err := sctp.Client(sctp.Config{
			NetConn:       ca,
			LoggerFactory: loggerFactory,
		})
		c <- result{client, err}
	}()

	// Setup server
	server, err := sctp.Server(sctp.Config{
		NetConn:       cb,
		LoggerFactory: loggerFactory,
	})
	if err != nil {
		return nil, nil, err
	}

	// Receive client
	res := <-c
	if res.err != nil {
		return nil, nil, res.err
	}

	return res.a, server, nil
}

type piperFunc func(t *testing.T) (net.Conn, net.Conn, error)

type dumbConn struct {
	mu    sync.RWMutex
	rAddr net.Addr
	pConn net.PacketConn
}

func (c *dumbConn) Read(p []byte) (int, error) {
	i, rAddr, err := c.pConn.ReadFrom(p)
	if err != nil {
		return 0, err
	}

	c.mu.Lock()
	c.rAddr = rAddr
	c.mu.Unlock()

	return i, err
}

func (c *dumbConn) Write(p []byte) (n int, err error) {
	return c.pConn.WriteTo(p, c.RemoteAddr())
}

func (c *dumbConn) Close() error {
	return c.pConn.Close()
}

func (c *dumbConn) LocalAddr() net.Addr {
	if c.pConn != nil {
		return c.pConn.LocalAddr()
	}
	return nil
}

func (c *dumbConn) RemoteAddr() net.Addr {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.rAddr
}

func (c *dumbConn) SetDeadline(time.Time) error {
	return nil
}

func (c *dumbConn) SetReadDeadline(time.Time) error {
	return nil
}

func (c *dumbConn) SetWriteDeadline(time.Time) error {
	return nil
}
