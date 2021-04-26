package main

import (
	"flag"
	"fmt"
	"net"
	"sync"
)

var addr = flag.String("addr", ":9999", "address to connect to")
var clients = flag.Int("clients", 3, "number of simultaneous connections")

func connect(id int, wg *sync.WaitGroup) {
	defer wg.Done()

	conn, err := net.Dial("tcp", *addr)
	if err != nil {
		fmt.Printf("client %v could not connect to %q: %v\n", id, *addr, err)
		return
	}
	defer conn.Close()

	select {}
}

func main() {
	var wg sync.WaitGroup
	for i := 0; i < *clients; i++ {
		wg.Add(1)
		go connect(i, &wg)
	}
	wg.Wait()
}
