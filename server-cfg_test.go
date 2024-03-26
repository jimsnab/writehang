package main

import (
	"crypto/tls"
	"crypto/x509"
	"path"
	"strings"
	"sync"

	"github.com/jimsnab/go-lane"
	"github.com/spf13/afero"
)

type (
	serverConfig struct {
		l                   lane.Lane
		mu                  sync.Mutex
		serverCert          tls.Certificate
		clientCertDirectory string
		clientCerts         []*tls.Certificate
		config              tls.Config
	}

	filePairs struct {
		base string
		cert []byte
		key  []byte
	}
)

func newServerConfig(l lane.Lane) (sc *serverConfig) {
	cert, err := tls.X509KeyPair(testServerCertPem, testServerKeyPem)
	if err != nil {
		l.Fatal("error parsing server cert and key")
	}

	roots := x509.NewCertPool()
	valid := roots.AppendCertsFromPEM(testRootCaPem)
	if !valid {
		l.Fatal("error appending root CA pem")
	}

	sc = &serverConfig{
		l:                   l,
		serverCert:          cert,
		clientCertDirectory: "/client-certs",
		config: tls.Config{
			Certificates: []tls.Certificate{cert},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    roots,
			MinVersion:   tls.VersionTLS12,
		},
	}

	sc.config.GetCertificate = sc.onGetCertificate
	sc.config.VerifyConnection = sc.onVerifyConnection

	return
}

func (sc *serverConfig) loadClientCerts(l lane.Lane) (err error) {
	l.Tracef("loading certificates from %s", sc.clientCertDirectory)
	dir, err := AppFs.Open(sc.clientCertDirectory)
	if err != nil {
		l.Errorf("failed to open client cert directory %s: %v", sc.clientCertDirectory, err)
		return
	}
	defer dir.Close()

	names, err := dir.Readdirnames(0)
	if err != nil {
		l.Errorf("error listing files of directory %s: %v", sc.clientCertDirectory, err)
		return
	}

	tuples := map[string]*filePairs{}

	for _, name := range names {
		cutPoint := strings.LastIndex(name, ".")
		if cutPoint < 0 {
			continue
		}
		base := name[:cutPoint]
		ext := name[cutPoint+1:]

		p := path.Join(sc.clientCertDirectory, name)

		if ext != "crt" && ext != "key" {
			l.Infof("file does not have crt or key extension, ignoring: %s", p)
			continue
		}

		data, ferr := afero.ReadFile(AppFs, p)
		if ferr != nil {
			l.Warnf("error reading client cert %s: %v", p, ferr)
			continue
		}

		var fp *filePairs
		fp = tuples[base]
		if fp == nil {
			fp = &filePairs{
				base: path.Join(sc.clientCertDirectory, base),
			}
			tuples[base] = fp
		}

		if ext == "crt" {
			fp.cert = data
		} else {
			fp.key = data
		}
	}

	removals := []string{}
	for k, fp := range tuples {
		if fp.cert == nil {
			l.Warnf("client key does not have corresponding crt file: %s.key", fp.base)
			removals = append(removals, k)
		} else if fp.key == nil {
			l.Warnf("client crt does not have corresponding key file: %s.crt", fp.base)
			removals = append(removals, k)
		}
	}

	for _, k := range removals {
		delete(tuples, k)
	}

	clientCerts := make([]*tls.Certificate, 0, len(tuples))

	for _, fp := range tuples {
		cert, cerr := tls.X509KeyPair(fp.cert, fp.key)
		if cerr != nil {
			l.Warnf("failed to load client cert %s: %v", fp.base, cerr)
			continue
		}

		clientCerts = append(clientCerts, &cert)
		l.Trace("loaded client cert:", path.Base(fp.base))
	}

	sc.mu.Lock()
	sc.clientCerts = clientCerts
	sc.mu.Unlock()
	l.Tracef("client certs loaded: %d", len(clientCerts))
	return
}

func (sc *serverConfig) onGetCertificate(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	// This is the logic of tls lib tlsConfig.getCertificate(). But - they
	// forgot to implement a mutex, so we implement ourselves to support
	// hot-loading client certs.

	sc.mu.Lock()
	defer sc.mu.Unlock()

	if len(sc.clientCerts) == 0 {
		return nil, errNoCertificates
	}

	for _, cert := range sc.clientCerts {
		var terr error
		if terr = clientHello.SupportsCertificate(cert); terr == nil {
			// At least one client cert known to the server is signed by a trusted ca;
			// but this is not yet preventing a client from using any signed cert
			// from that trusted ca.
			return cert, nil
		}

		sc.l.Tracef("no match with certificate: %v", terr)
	}

	// If nothing matches, return an error.
	return nil, errNoMatchingCertificates
}

func (sc *serverConfig) onVerifyConnection(cs tls.ConnectionState) error {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	// Ensure the cert sent by the client is an exact match of one in the
	// server's client cert directory.
	sc.l.Tracef("connection state peer ceritificates: %d", len(cs.PeerCertificates))
	if len(cs.PeerCertificates) > 0 {
		peer := cs.PeerCertificates[0]
		for _, tlsCert := range sc.clientCerts {
			if len(tlsCert.Certificate) > 0 {
				cert, err := x509.ParseCertificate(tlsCert.Certificate[0])
				if err == nil {
					if peer.Equal(cert) {
						return nil
					}
					sc.l.Tracef("peer cert not equal to authorized client cert")
				} else {
					sc.l.Debugf("client certificate parse error: %s", err)
				}
			} else {
				sc.l.Tracef("client certificate array is empty")
			}
		}
	}

	return errNoMatchingCertificates
}

func (sc *serverConfig) GetTlsConfig() (*tls.Config, error) {
	return &sc.config, nil
}
