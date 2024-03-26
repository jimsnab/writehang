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
	receiver struct {
		l     lane.Lane
		conn  net.Conn
		input []byte
		wg    sync.WaitGroup
	}
)

func newReceiver(l lane.Lane, hostAndPort string, crt, key []byte) *receiver {
	roots := x509.NewCertPool()

	ok := roots.AppendCertsFromPEM(testRootCaPem)
	if !ok {
		l.Fatal("failed to parse root certificate")
	}

	cert, err := tls.X509KeyPair(crt, key)
	if err != nil {
		l.Fatal(err)
	}

	cfg := tls.Config{
		RootCAs:      roots,
		Certificates: []tls.Certificate{cert},
	}

	conn, err := tls.Dial("tcp", hostAndPort, &cfg)
	if err != nil {
		l.Fatal(err)
	}

	// perform handshake immediately
	_, err = conn.Read(nil)
	if err != nil {
		l.Fatal(err)
	}

	logConnection(l, "client", conn)

	r := receiver{
		l:    l,
		conn: conn,
	}

	r.wg.Add(1)
	go r.react()

	return &r
}

func (cli *receiver) Close() {
	// caller cancels lane
	cli.wg.Wait()
}

func (cli *receiver) react() {
	defer cli.wg.Done()

	reply := uint32(0)
	for {
		obj, err := cli.receive()
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				fmt.Println("client connection lost")
				return
			}
			panic(err)
		}

		fmt.Printf("received: %v\n", obj)

		// simulate some processing delay
		time.Sleep(time.Millisecond * 5)

		reply++
		msg := fmt.Sprintf("processed %d", reply)
		if err = cli.send(msg); err != nil {
			panic(err)
		}
	}
}

func (cli *receiver) send(obj any) (err error) {
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
		cli.l.Fatal("did not write all data")
	}

	return
}

func (cli *receiver) receive() (obj any, err error) {
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

		if packetSize > 8192 {
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
