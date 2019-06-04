package server

import (
	"crypto/tls"
	"log"

	"github.com/vmihailenco/msgpack"
)

func Client(password, host, port string, request PrivateKeyExchange) *PrivateKeyExchange {
	cert, err := tls.LoadX509KeyPair("server/util/certs/client.pem", "server/util/certs/client.key")

	if err != nil {
		log.Fatalf("server: loadkeys: %s", err)
	}

	config := tls.Config{Certificates: []tls.Certificate{cert}, InsecureSkipVerify: true}

	conn, err := tls.Dial("tcp", host+":"+port, &config)
	if err != nil {
		log.Fatalf("client: dial: %s", err)
	}
	defer conn.Close()
	log.Println("client: connected to: ", conn.RemoteAddr())

	b, err := msgpack.Marshal(request)
	conn.Write(b)

	decoder := msgpack.NewDecoder(conn)
	tmpStruct := new(PrivateKeyExchange)

	decoder.Decode(tmpStruct)

	log.Print("client: exiting")

	return tmpStruct
}
