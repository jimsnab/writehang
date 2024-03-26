package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jimsnab/go-lane"
	"github.com/spf13/afero"
)

type (
	echoServer struct {
		genericTlsSockerServer
		clients map[int64]*echoServerCxn
		opened  atomic.Int64
	}

	echoServerCxn struct {
		mu          sync.Mutex
		l           lane.Lane
		id          int64
		conn        net.Conn
		cxnApi      tlsSockerServerCxnApi
		forcedClose bool
	}

	echoClient struct {
		t     *testing.T
		l     lane.Lane
		srv   *echoServer
		id    int64
		conn  net.Conn
		input []byte
	}
)

var AppFs afero.Fs

func startTestServer(t *testing.T) (l lane.TestingLane, srv genericTlsSockerServer) {
	l = lane.NewTestingLane(context.Background())
	l.AddTee(lane.NewLogLane(context.Background()))
	l.WantDescendantEvents(true)

	srv = newTestEchoServer(l.Derive())

	AppFs = afero.NewMemMapFs()
	err := AppFs.MkdirAll("/client-certs", 0755)
	if err != nil {
		t.Fatal(err)
	}

	afero.WriteFile(AppFs, "/client-certs/client.crt", testClientCertPem, 0644)
	afero.WriteFile(AppFs, "/client-certs/client.key", testClientKeyPem, 0644)

	sc := newServerConfig(l)

	if err = sc.loadClientCerts(l); err != nil {
		t.Fatal(err)
	}

	err = srv.StartServer("localhost", 29000, sc)
	if err != nil {
		t.Fatal(err)
	}

	l.Tracef("started server address: %s", srv.ServerAddr())
	return
}

func createTestClient(t *testing.T, l lane.Lane, srv *echoServer, crt, key []byte) *echoClient {
	roots := x509.NewCertPool()

	ok := roots.AppendCertsFromPEM(testRootCaPem)
	if !ok {
		t.Fatal("failed to parse root certificate")
	}

	cert, err := tls.X509KeyPair(crt, key)
	if err != nil {
		t.Fatal(err)
	}

	cfg := tls.Config{
		RootCAs:      roots,
		Certificates: []tls.Certificate{cert},
	}

	conn, err := tls.Dial("tcp", "localhost:29000", &cfg)
	if err != nil {
		t.Fatal(err)
	}

	// perform handshake immediately
	_, err = conn.Read(nil)
	if err != nil {
		t.Fatal(err)
	}

	logConnection(l, "client", conn)

	return &echoClient{
		t:    t,
		l:    l,
		srv:  srv,
		id:   srv.opened.Add(1),
		conn: conn,
	}
}

func newTestEchoServer(l lane.Lane) genericTlsSockerServer {
	es := echoServer{
		clients: map[int64]*echoServerCxn{},
	}
	es.genericTlsSockerServer = newTlsSockerServer(l, es.processConnection, nil)
	return &es
}

func (cli *echoClient) testClientSend(obj any) (err error) {
	msg, err := json.Marshal(obj)
	if err != nil {
		return
	}

	data := make([]byte, len(msg)+4)
	binary.BigEndian.PutUint32(data, uint32(len(msg)))

	copy(data[4:], msg)

	n, err := cli.conn.Write(data)
	if err != nil {
		return
	}

	if n != len(data) {
		cli.t.Fatal("did not write all data")
	}

	return
}

func (cli *echoClient) testClientReceive() (obj any, err error) {
	for {
		seg := make([]byte, 1024)

		var n int
		n, err = cli.conn.Read(seg)
		if err != nil {
			return
		}

		cli.input = append(cli.input, seg[:n]...)

		receivedLen := uint32(len(cli.input))
		if receivedLen < 4 {
			continue
		}

		msgLen := binary.BigEndian.Uint32(cli.input[0:4])
		packetSize := msgLen + 4

		if packetSize > 1024 {
			err = errors.New("too long")
			return
		}

		if packetSize < receivedLen {
			continue
		}

		err = json.Unmarshal(cli.input[4:packetSize], &obj)
		cli.input = cli.input[packetSize:]
		return
	}
}

func (srv *echoServer) processConnection(l lane.Lane, conn net.Conn, cxnApi tlsSockerServerCxnApi) (err error) {
	cxn := &echoServerCxn{
		l:      l,
		id:     cxnApi.GetClientId(),
		conn:   conn,
		cxnApi: cxnApi,
	}

	srv.clients[cxn.id] = cxn

	go cxn.doEcho()

	cxn.l.Infof("ECHO test: waiting for lane cancel for %s", cxn.cxnApi.GetClientInfo())
	<-l.Done()
	cxn.l.Infof("ECHO test: lane canceled for %s", cxn.cxnApi.GetClientInfo())
	return
}

func (cxn *echoServerCxn) doEcho() {
	ci := cxn.cxnApi.GetClientInfo()
	defer func() {
		cxn.l.Infof("ECHO test: terminating %s", ci)
		cxn.cxnApi.OnExit()
		cxn.l.Infof("ECHO test: terminated %s", ci)
	}()

	cxn.l.Infof("ECHO test: starting to echo to %s", ci)

	buffer := make([]byte, 1024*8)

	for {
		n, err := cxn.conn.Read(buffer)

		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				cxn.l.Debugf("ECHO test: read error from %s: %s", cxn.conn.RemoteAddr().String(), err)
			} else {
				cxn.mu.Lock()
				if cxn.forcedClose {
					cxn.l.Infof("ECHO test: client-forced disconnect on read: %s", cxn.conn.RemoteAddr().String())
				} else {
					cxn.l.Infof("ECHO test: server-forced disconnect on read: %s", cxn.conn.RemoteAddr().String())
				}
				cxn.mu.Unlock()
			}
			return
		}

		_, err = cxn.conn.Write(buffer[:n])

		if err != nil {
			cxn.l.Infof("ECHO test: server disconnect on write: %s", cxn.conn.RemoteAddr().String())
			return
		}
	}
}

func (srv *echoServer) injectExtraData(by []byte) (err error) {
	raw := make([]byte, len(by)+4)
	binary.BigEndian.PutUint32(raw, uint32(len(by)))
	copy(raw[4:], by)

	for _, cli := range srv.clients {
		_, err = cli.conn.Write(raw)
		if err != nil {
			return
		}
	}

	return
}

func TestSimpleConnectCloseServer(t *testing.T) {
	l, srv := startTestServer(t)
	if srv == nil {
		return
	}

	es := srv.(*echoServer)

	ec := createTestClient(t, l, es, testClientCertPem, testClientKeyPem)

	err := ec.testClientSend("testing")
	if err != nil {
		t.Fatal(err)
	}

	obj, err := ec.testClientReceive()
	if err != nil {
		t.Fatal(err)
	}

	s, _ := obj.(string)
	if s != "testing" {
		t.Fatal("did not echo")
	}

	srv.StopServer()
	srv.WaitForTermination()

	str := l.EventsToString()
	if !strings.Contains(str, "client connected") {
		t.Errorf("missing client connected: %s", str)
	}

	if !strings.Contains(str, "closing listener") {
		t.Errorf("missing closing: %s", str)
	}
	if !strings.Contains(str, "waiting for any open request connections to complete") {
		t.Errorf("missing waiting: %s", str)
	}
	if !strings.Contains(str, "blocking i/o to end by closing client connection") {
		t.Errorf("missing blocking i/o cancel: %s", str)
	}
	if !strings.Contains(str, "termination completed") {
		t.Errorf("missing closed: %s", str)
	}
	if !strings.Contains(str, "server-forced disconnect on read") && !strings.Contains(str, "use of closed network connection") {
		t.Errorf("missing server disconnect: %s", str)
	}
	if !strings.Contains(str, "finished serving requests") {
		t.Errorf("missing finished: %s", str)
	}
}

func TestBidirectionalStreamSlowClient(t *testing.T) {
	l, srv := startTestServer(t)
	if srv == nil {
		return
	}

	es := srv.(*echoServer)

	ec := createTestClient(t, l, es, testClientCertPem, testClientKeyPem)

	var wg sync.WaitGroup
	wg.Add(2)

	var failure error
	go func() {
		defer wg.Done()

		extra, _ := json.Marshal("extra data")
		for range 10000 {
			err := es.injectExtraData(extra)
			if err != nil {
				failure = err
				return
			}

			time.Sleep(time.Millisecond)
		}
		l.Tracef("server processing has finished")
		srv.StopServer()
	}()

	go func() {
		defer wg.Done()

		for range 10000 {
			err := ec.testClientSend("testing")
			if err != nil {
				failure = err
				return
			}

			obj, err := ec.testClientReceive()
			if err != nil {
				failure = err
				return
			}

			s, _ := obj.(string)
			if s != "testing" && s != "extra data" {
				failure = fmt.Errorf("received unexpected data %v", obj)
				return
			}

			time.Sleep(time.Millisecond)

			obj, err = ec.testClientReceive()
			if err != nil {
				failure = err
				return
			}

			s, _ = obj.(string)
			if s != "testing" && s != "extra data" {
				failure = fmt.Errorf("received unexpected data %v", obj)
				return
			}

			time.Sleep(time.Millisecond)
		}
		l.Tracef("client processing has finished")
	}()

	wg.Wait()
	if failure != nil {
		t.Fatal(failure)
	}

	l.Tracef("successful exchange of data")

	srv.WaitForTermination()
}
