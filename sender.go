package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/jimsnab/go-lane"
)

type (
	sender struct {
		genericTlsSockerServer
		l       lane.Lane
		cfg     *tls.Config
		clients map[int64]*senderCxn
		mu      sync.Mutex
	}

	senderCxn struct {
		l      lane.Lane
		id     int64
		conn   net.Conn
		cxnApi tlsSockerServerCxnApi
		wg     sync.WaitGroup
	}
)

var errNoCertificates = errors.New("tls: no certificates configured")
var errNoMatchingCertificates = errors.New("tls: no client certificates match handshake")

func newSender(l lane.Lane) *sender {
	srv := sender{
		l:       l,
		clients: map[int64]*senderCxn{},
	}
	srv.genericTlsSockerServer = newTlsSockerServer(l, srv.processConnection, nil)

	cert, err := tls.X509KeyPair(testServerCertPem, testServerKeyPem)
	if err != nil {
		l.Fatal("error parsing server cert and key")
	}

	roots := x509.NewCertPool()
	valid := roots.AppendCertsFromPEM(testRootCaPem)
	if !valid {
		l.Fatal("error appending root CA pem")
	}

	srv.cfg = &tls.Config{
		Certificates:     []tls.Certificate{cert},
		ClientAuth:       tls.RequireAndVerifyClientCert,
		ClientCAs:        roots,
		MinVersion:       tls.VersionTLS12,
		GetCertificate:   srv.onGetCertificate,
		VerifyConnection: srv.onVerifyConnection,
	}

	return &srv
}

func (srv *sender) onGetCertificate(clientHello *tls.ClientHelloInfo) (cert *tls.Certificate, err error) {
	c, err := tls.X509KeyPair(testClientCertPem, testClientKeyPem)
	if err != nil {
		panic(err)
	}

	terr := clientHello.SupportsCertificate(&c)
	if terr == nil {
		cert = &c
		return
	}

	srv.l.Tracef("no match with certificate: %v", terr)
	err = errNoMatchingCertificates
	return
}

func (srv *sender) onVerifyConnection(cs tls.ConnectionState) error {
	srv.mu.Lock()
	defer srv.mu.Unlock()

	srv.l.Tracef("connection state peer ceritificates: %d", len(cs.PeerCertificates))
	if len(cs.PeerCertificates) > 0 {
		peer := cs.PeerCertificates[0]
		c, err := tls.X509KeyPair(testClientCertPem, testClientKeyPem)
		if err != nil {
			panic(err)
		}

		if len(c.Certificate) > 0 {
			cert, err := x509.ParseCertificate(c.Certificate[0])
			if err == nil {
				if peer.Equal(cert) {
					return nil
				}
				srv.l.Tracef("peer cert not equal to authorized client cert")
			} else {
				srv.l.Debugf("client certificate parse error: %s", err)
			}
		} else {
			srv.l.Tracef("client certificate array is empty")
		}
	}

	return errNoMatchingCertificates
}

func (srv *sender) GetTlsConfig() (cfg *tls.Config, err error) {
	cfg = srv.cfg
	return
}

func (srv *sender) processConnection(l lane.Lane, conn net.Conn, cxnApi tlsSockerServerCxnApi) (err error) {
	cxn := &senderCxn{
		l:      l,
		id:     cxnApi.GetClientId(),
		conn:   conn,
		cxnApi: cxnApi,
	}

	srv.clients[cxn.id] = cxn

	cxn.wg.Add(2)
	go cxn.sendStuff()
	go cxn.recvStuff()

	<-l.Done()
	cxn.wg.Wait()
	return
}

func (cxn *senderCxn) sendStuff() {
	ci := cxn.cxnApi.GetClientInfo()
	cxn.l.Infof("sending to %s", ci)

	defer func() {
		cxn.l.Infof("terminating %s", ci)
		cxn.cxnApi.OnExit()
		cxn.l.Infof("terminated %s", ci)
		cxn.wg.Done()
	}()

	count := uint32(0)
	sent := uint64(0)
	for {
		select {
		case <-cxn.l.Done():
			return
		default:
			// continue
		}

		count++
		msg := fmt.Sprintf("message %d, previously sent %d bytes", count, sent)
		raw, err := json.Marshal(msg)
		if err != nil {
			panic(err)
		}
		msgLen := uint32(len(raw))
		packet := make([]byte, msgLen+4)
		binary.BigEndian.PutUint32(packet, msgLen)
		copy(packet[4:], raw)

		_, err = cxn.conn.Write(packet)
		if err != nil {
			panic(err)
		}
		sent += uint64(len(packet))

		fmt.Printf("sent %d, %d bytes\n", count, sent)
		time.Sleep(time.Millisecond) // slow things for easier observation
	}
}

func (cxn *senderCxn) recvStuff() {
	ci := cxn.cxnApi.GetClientInfo()
	cxn.l.Infof("receiving from %s", ci)

	defer cxn.wg.Done()

	var inbound []byte

	for {
		select {
		case <-cxn.l.Done():
			return
		default:
			// continue
		}

		buffer := make([]byte, 1024*8)
		n, err := cxn.conn.Read(buffer)

		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				cxn.l.Debugf("read error from %s: %s", cxn.conn.RemoteAddr().String(), err)
			}
			return
		}

		inbound = append(inbound, buffer[:n]...)
		if len(inbound) < 4 {
			continue
		}

		msgLen := binary.BigEndian.Uint32(inbound[0:4])
		packetSize := msgLen + 4

		if uint32(len(inbound)) < packetSize {
			continue
		}

		var obj any
		if err = json.Unmarshal(inbound[4:packetSize], &obj); err != nil {
			panic(err)
		}
		inbound = inbound[packetSize:]

		fmt.Printf("received: %v\n", obj)
	}
}
