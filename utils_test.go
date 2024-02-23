package throughput

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"sync"
	"testing"

	"github.com/pion/dtls/v2"
	"github.com/pion/dtls/v2/pkg/crypto/selfsign"
	"github.com/pion/ice/v2"
	"github.com/pion/stun"
)

// // all 250k w/s
//
//	sizes := []int64{
//		// 4, // 1 MiB/s
//		// 16, // 4 MiB/s
//		// 128, // 32 MiB/s
//		// 256, // 64 MiB/s
//		// 1024, // 256 MiB/s
//		// 4096, // 1024 GiB/s
//		// 16384,
//		// 32768,
//	}
//
// This is all OS net stack impl dependent
func TestThroughputUDP(t *testing.T) {
	TestPacketThroughput(t, func(t *testing.T) (io.ReadCloser, io.WriteCloser, error) {
		server, err := net.ListenUDP("udp4", nil)
		if err != nil {
			return nil, nil, err
		}

		client, err := net.ListenUDP("udp4", nil)
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
		server, err := net.Listen("tcp", "0.0.0.0:0")
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

		client, err := net.Dial(server.Addr().Network(), server.Addr().String())
		if err != nil {
			return nil, nil, err
		}

		return <-serverConn, client, nil
	})
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
		cert, err := selfsign.GenerateSelfSignedWithDNS("localhost")
		if err != nil {
			return nil, nil, err
		}

		// choices
		// dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 // fastest
		// dtls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
		// dtls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA // slowest
		cfg := &dtls.Config{
			Certificates:       []tls.Certificate{cert},
			CipherSuites:       []dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
			InsecureSkipVerify: true,
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

		return ReadCloserWrapper{Conn: <-serverConn, CloseFunc: server.Close}, client, err
	})
}

func pipe(defaultConfig *ice.AgentConfig) (*ice.Conn, *ice.Conn, error) {
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
	if defaultConfig != nil {
		*cfg = *defaultConfig
	}

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

func TestThroughputICE(t *testing.T) {
	TestPacketThroughput(t, func(t *testing.T) (io.ReadCloser, io.WriteCloser, error) {
		return pipe(nil)
	})
}
