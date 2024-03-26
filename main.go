package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"

	"github.com/jimsnab/go-lane"
)

func main() {
	args := os.Args[1:]
	if len(args) < 1 || (args[0] != "client" && args[0] != "server") {
		fmt.Println("usage: writehang client [host]\n    or writehang server")
		return
	}

	l := lane.NewLogLane(context.Background())
	l2, cancelFn := l.DeriveWithCancel()

	sigs := make(chan os.Signal, 10)
	signal.Notify(sigs, os.Interrupt)

	if args[0] == "client" {
		host := "localhost"
		if len(args) > 1 {
			host = args[1]
		}
		receiver := newReceiver(l2, fmt.Sprintf("%s:29000", host), testClientCertPem, testClientKeyPem)
		<-sigs
		cancelFn()
		receiver.Close()
	} else {
		sender := newSender(l2)
		err := sender.StartServer("", 29000, sender)
		if err != nil {
			panic(err)
		}
		<-sigs
		cancelFn()
		sender.Close()
	}
}
