package main

import (
	"context"
	"flag"
	"io"
	"log"
	"net"
	"sync"
	sc "syscall"
)

var addr = flag.String("addr", ":9999", "address to listen on")
var listeners = flag.Int("listeners", 2, "number of simultaneous connections")

func reusePort(network, address string, conn sc.RawConn) error {
	return conn.Control(func(fd uintptr) {
		// "15" taken from asm-generic/socket.h
		sc.SetsockoptInt(int(fd), sc.SOL_SOCKET, 15, 1)
	})
}

func listen(id int, listener net.Listener, wg *sync.WaitGroup) {
	defer wg.Done()
	defer listener.Close()

	socket, err := listener.Accept()
	if err != nil {
		log.Fatalf("Listener %v: Error accepting: %v", id, err)
	}
	defer socket.Close()

	log.Println("Accepted socket from listener", id)
	buf := make([]byte, 2<<10)
	for {
		n, err := io.ReadAtLeast(socket, buf, 1)
		if err != nil {
			log.Printf("Listener %v: error: %v", id, err)
			break
		}
		log.Printf("Listener %v read %v bytes: %q", id, n, buf[:n])
	}
	log.Printf("Listener %v terminating", id)
}

func main() {
	flag.Parse()

	lc := &net.ListenConfig{Control: reusePort}

	var wg sync.WaitGroup

	for i := 0; i < *listeners; i++ {
		listener, err := lc.Listen(context.Background(), "tcp", *addr)
		if err != nil {
			log.Fatalf("Could create listener %v: %v", i, err)
		}
		wg.Add(1)
		go listen(i, listener, &wg)
	}

	wg.Wait()
}
