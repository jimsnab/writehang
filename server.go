package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"

	"github.com/jimsnab/go-lane"
)

type (
	tlsSockerServer struct {
		mu          sync.Mutex
		l           lane.Lane
		listener    net.Listener
		wg          sync.WaitGroup
		starting    sync.WaitGroup
		terminating bool
		port        int
		iface       string
		cs          *clientSet
		cleanup     tlsSocketServerCleanup
	}

	clientSet struct {
		mu         sync.Mutex
		clients    []*clientCxn
		wg         sync.WaitGroup
		l          lane.Lane
		cxnCounter atomic.Int64
		handler    tlsSockerServerHandler
	}

	clientCxn struct {
		l        lane.Lane
		mu       sync.Mutex // synchronizes access to waiting, closing flags
		cs       *clientSet
		cancelFn context.CancelFunc
		id       int64
		cxn      net.Conn
		closing  bool
	}

	// Generic interface for a socket server with TLS and client side certs
	genericTlsSockerServer interface {
		StartServer(endpoint string, port int, config TlsSockerServerConfig) error

		// Initiates server termination, if it is running.
		StopServer() error

		// Waits for the server to stop
		WaitForTermination()

		// StopServer and WaitForTermination combo
		Close()

		// Returns the server address
		ServerAddr() string
	}

	TlsSockerServerConfig interface {
		GetTlsConfig() (*tls.Config, error)
	}

	tlsSockerServerCxnApi interface {
		OnExit()                      // called by processing handler just before final return
		GetClientInfo() (info string) // exposes client connection info to the processing handler
		GetClientId() (id int64)      // exposes client connection number for unit tests
	}

	// Implements service-specific connection handling and blocks until the connection
	// is terminated. It must stop when the conn or lane is closed.
	//
	// Just before the handler funcion returns, it must call cxnHandler.OnExit().
	//
	// The processing handler can call cxnApi.GetClientInfo() to obtain client
	// connection details.
	tlsSockerServerHandler func(l lane.Lane, conn net.Conn, cxnApi tlsSockerServerCxnApi) error

	// Optional server termination extension.
	tlsSocketServerCleanup func()
)

const kDefaultPort = 9096

func newTlsSockerServer(l lane.Lane, handler tlsSockerServerHandler, cleanup tlsSocketServerCleanup) genericTlsSockerServer {
	eng := tlsSockerServer{
		l:       l,
		cs:      newClientSet(l, handler),
		cleanup: cleanup,
	}
	return &eng
}

func (eng *tlsSockerServer) StartServer(endpoint string, port int, config TlsSockerServerConfig) error {
	eng.mu.Lock()
	defer eng.mu.Unlock()

	if eng.listener != nil {
		return fmt.Errorf("already started")
	}

	eng.starting.Add(1)

	if port != 0 {
		eng.port = port
	} else {
		eng.port = kDefaultPort
	}

	if endpoint != "" {
		eng.iface = endpoint
	}

	// kick off connection processing
	err := eng.startListening(config)
	if err != nil {
		eng.starting.Done()
		return err
	}

	return nil
}

func (eng *tlsSockerServer) StopServer() error {
	// ensure startup completed
	eng.starting.Wait()

	// ensure only one termination
	eng.mu.Lock()
	if eng.listener == nil {
		eng.mu.Unlock()
		return errors.New("not started")
	}

	wasTerminating := eng.terminating
	eng.terminating = true
	eng.mu.Unlock()

	if !wasTerminating {
		// shut down connection processing
		eng.wg.Add(1)
		go func() { eng.onTerminate() }()
	}

	return nil
}

func (eng *tlsSockerServer) WaitForTermination() {
	eng.wg.Wait()
	eng.l.Info("finished serving requests")
}

func (eng *tlsSockerServer) Close() {
	eng.StopServer()
	eng.WaitForTermination()
}

func (eng *tlsSockerServer) ServerAddr() string {
	eng.mu.Lock()
	defer eng.mu.Unlock()

	if eng.listener == nil {
		return ""
	}

	return eng.listener.Addr().String()
}

func (eng *tlsSockerServer) startListening(config TlsSockerServerConfig) (err error) {
	// establish socket service
	if eng.iface == "" {
		eng.iface = fmt.Sprintf(":%d", eng.port)
	} else {
		eng.iface = fmt.Sprintf("%s:%d", eng.iface, eng.port)
	}

	tlscfg, err := config.GetTlsConfig()
	if err != nil {
		eng.l.Errorf("server tls error: %v", err)
		return
	}

	// n.b., mu is locked by the caller
	eng.listener, err = tls.Listen("tcp", eng.iface, tlscfg)

	if err != nil {
		eng.l.Errorf("error listening: %s", err.Error())
		return err
	}

	addr := eng.listener.Addr()
	eng.l.Infof("listening on %s", addr.String())

	eng.wg.Add(1)
	go func() {
		eng.starting.Done()

		// accept connections and process commands
		for {
			eng.mu.Lock()
			listener := eng.listener
			eng.mu.Unlock()

			if listener == nil {
				break
			}

			connection, err := listener.Accept()
			if err != nil {
				if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
					eng.l.Errorf("accept error: %v", err)
				}
				break
			}

			eng.mu.Lock()
			eng.cs.newClientCxn(connection)
			eng.mu.Unlock()
			eng.l.Tracef("client connected: %s", connection.RemoteAddr().String())
		}

		eng.l.Infof("listening terminated")
		eng.wg.Done()
	}()

	return nil
}

func (eng *tlsSockerServer) onTerminate() {

	eng.mu.Lock()
	if eng.listener != nil {
		// close the listening socket and wait for all active connections to finish
		who := eng.listener.Addr().String()
		eng.l.Tracef("closing listener")
		eng.listener.Close()
		eng.listener = nil

		eng.l.Infof("waiting for any open request connections to complete")
		eng.cs.requestCloseAll()

		eng.mu.Unlock()

		eng.cs.waitForCloseAll()

		if eng.cleanup != nil {
			eng.cleanup()
		}

		eng.l.Infof("termination completed for %s", who)
	} else {
		eng.mu.Unlock()
	}

	eng.wg.Done()
}

func newClientSet(l lane.Lane, handler tlsSockerServerHandler) *clientSet {
	return &clientSet{
		l:       l,
		handler: handler,
		clients: []*clientCxn{},
	}
}

func (cs *clientSet) newClientCxn(cxn net.Conn) *clientCxn {
	l, cancelFn := cs.l.DeriveWithCancel()
	cc := &clientCxn{
		l:        l,
		cancelFn: cancelFn,
		cxn:      cxn,
		id:       cs.cxnCounter.Add(1),
		cs:       cs,
	}

	cs.wg.Add(1)
	cs.mu.Lock()
	cs.clients = append(cs.clients, cc)
	cs.mu.Unlock()

	l.Tracef("client %d socket opened", cc.id)

	go func() {
		// perform tls handshake immediately
		_, err := cxn.Read(nil)
		if err != nil {
			l.Debugf("invalid tls handshake: %v", err)
			cc.OnExit()
			return
		}

		logConnection(l, "server", cxn.(*tls.Conn))
		cs.handler(cc.l, cxn, cc)
	}()

	return cc
}

func (cs *clientSet) requestCloseAll() {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	for _, cc := range cs.clients {
		cc.requestClose()
	}
}

func (cs *clientSet) waitForCloseAll() {
	cs.wg.Wait()
}

// takes the client out of the client set
func (cs *clientSet) onClientTerminate(cc *clientCxn) {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	for index, client := range cs.clients {
		if cc == client {
			err := client.cxn.Close()
			if err != nil {
				if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
					client.l.Infof("error closing client %d: %v", client.id, err)
				} else {
					client.l.Tracef("client %d socket already closed", client.id)
				}
			} else {
				client.l.Tracef("client %d socket closed", client.id)
			}
			cs.clients = append(cs.clients[:index], cs.clients[index+1:]...)
			cs.wg.Done()
			return
		}
	}

	panic("terminated client not found in client set")
}

// Request connection close (don't wait for the close to complete)
func (cc *clientCxn) requestClose() {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	if !cc.closing {
		cc.closing = true
		cc.cancelFn() // signal close to the lane

		// abort socket i/o
		err := cc.cxn.Close()
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				cc.l.Infof("error closing blocked client %d: %v", cc.id, err)
			} else {
				cc.l.Tracef("already forced blocking i/o to end by closing client connection %d", cc.id)
			}
		} else {
			cc.l.Tracef("forcing blocking i/o to end by closing client connection %d", cc.id)
		}
	}
}

// Cleans up the client connection as it exits.
func (cc *clientCxn) OnExit() {
	cc.l.Tracef("cleaning up client connection %s", cc.GetClientInfo())
	cc.cs.onClientTerminate(cc)
}

// Provides client identification details for logging
func (cc *clientCxn) GetClientInfo() (info string) {
	cc.mu.Lock()
	info = fmt.Sprintf("client %d at %s", cc.id, cc.cxn.RemoteAddr().String())
	cc.mu.Unlock()

	return
}

// Provides client id for unit tests
func (cc *clientCxn) GetClientId() (id int64) {
	return cc.id
}

func logConnection(l lane.Lane, prefix string, cxn *tls.Conn) {
	state := cxn.ConnectionState()
	l.Infof("%s: tls Version: %x", prefix, state.Version)
	l.Infof("%s: tls HandshakeComplete: %t", prefix, state.HandshakeComplete)
	l.Infof("%s: tls DidResume: %t", prefix, state.DidResume)
	l.Infof("%s: tls CipherSuite: %x", prefix, state.CipherSuite)
	l.Infof("%s: tls NegotiatedProtocol: %s", prefix, state.NegotiatedProtocol)

	l.Infof("%s: tls certificate chain:", prefix)
	for i, cert := range state.PeerCertificates {
		subject := cert.Subject
		issuer := cert.Issuer
		l.Infof("%s: %d s:/C=%v/ST=%v/L=%v/O=%v/OU=%v/SAN=%s", prefix, i, subject.Country, subject.Province, subject.Locality, subject.Organization, subject.OrganizationalUnit, subject.ExtraNames)
		l.Infof("%s:    i:/C=%v/ST=%v/L=%v/O=%v/OU=%v/SAN=%s", prefix, issuer.Country, issuer.Province, issuer.Locality, issuer.Organization, issuer.OrganizationalUnit, issuer.ExtraNames)
	}
}
