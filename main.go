package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"regexp"
)

var listenAddr = flag.String("listen", ":43443", "the address to listen on")
var certPath = flag.String("cert", "server.cer", "the server certificate")
var keyPath = flag.String("key", "server.key", "the server key")

func main() {
	flag.Parse()

	cert, err := tls.LoadX509KeyPair(*certPath, *keyPath)
	if err != nil {
		log.Fatal(err)
		return
	}

	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	ln, err := tls.Listen("tcp", *listenAddr, config)
	if err != nil {
		log.Fatal(err)
		return
	}

	defer ln.Close()

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Fatal(err)
			continue
		}
		go handleConn(conn)
	}
}

func handleConn(conn net.Conn) {
	defer conn.Close()

	r := bufio.NewReader(conn)

	q, err := r.ReadString('\n')
	if err != nil {
		log.Fatal(err)
		return
	}

	log.Printf("Received query for: %s", q)

	resp := whois(q)

	n, err := conn.Write([]byte(resp))
	if err != nil {
		log.Fatal(n, err)
	}
}

var regexExtractWhoisServer = regexp.MustCompile(`whois:\s+([a-z0-9\-\.]+)`)

func queryWhois(query string, addr string) string {
	conn, _ := net.Dial("tcp", addr)
	fmt.Fprintf(conn, query+"\r\n")
	data, _ := ioutil.ReadAll(conn)
	return string(data)
}

func whois(query string) string {
	data := queryWhois(query, "whois.iana.org:43")
	resp := data
	for {
		refSearch := regexExtractWhoisServer.FindStringSubmatch(data)
		if len(refSearch) < 2 {
			break
		}
		data = queryWhois(query, refSearch[1]+":43")
		resp += "\n\n" + data
	}
	return resp
}
