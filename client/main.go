package main

import (
	"flag"
	"fmt"
	"net"
	"sync"
	"time"
)

var addr = flag.String("addr", ":9999", "address to connect to")
var clients = flag.Int("clients", 3, "number of simultaneous connections")

func connect(id int, wg *sync.WaitGroup) {
	defer wg.Done()

	conn, err := net.DialTimeout("tcp", *addr, 5*time.Second)
	if err != nil {
		fmt.Printf("client %v could not connect to %q: %v\n", id, *addr, err)
		return
	}
	defer conn.Close()

	fmt.Printf("client %v connection %q->%q opened\n", id, conn.LocalAddr(), conn.RemoteAddr())

	b := make([]byte, 10)
	_, err = conn.Read(b)

	fmt.Printf("client %v connection %q->%q closed: %v\n", id, conn.LocalAddr(), conn.RemoteAddr(), err)
}

func main() {
	flag.Parse()

	var wg sync.WaitGroup
	for i := 0; i < *clients; i++ {
		wg.Add(1)
		go connect(i, &wg)
	}
	wg.Wait()
}
