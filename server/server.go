package server

import (
	"bufio"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"log"
	"net"
	"os"
	"time"

	"github.com/blueskan/harpocrates/core"
	"github.com/blueskan/harpocrates/service"
	"github.com/vmihailenco/msgpack"
)

var masterPasswordHash string

// Errors
const MESSAGE_TYPE_WRONG_CREDENTIALS = "WRONG_CREDENTIALS"
const MESSAGE_TYPE_BANNED = "BANNED"
const MESSAGE_TYPE_PRIVATE_KEY_ALREADY_EXISTS = "PRIVATE_KEY_ALREADY_EXISTS"

// Successes
const MESSAGE_TYPE_PRIVATE_KEY_SAVED = "MESSAGE_TYPE_PRIVATE_KEY_SAVED"

// Common Messages
const MESSAGE_TYPE_GET_PRIVATE_KEY = "GET_PRIVATE_KEY"
const MESSAGE_TYPE_STORE_PRIVATE_KEY = "STORE_PRIVATE_KEY"

const DEFAULT_SERVER_DEADLINE = 15 * time.Second

type PrivateKeyExchange struct {
	PasswordHash string
	PrivateKey   string
	Type         string
}

type Fail2Ban struct {
	IPAddr      string
	FailCount   int
	BannedUntil time.Time
}

var blacklist map[string]Fail2Ban = make(map[string]Fail2Ban, 0)

func Server(storageService service.Storage) {
	settings := storageService.ReadSettings()

	masterPasswordHash, _ = core.HashPassword(settings["password"])

	cert, err := tls.LoadX509KeyPair("server/util/certs/server.pem", "server/util/certs/server.key")
	if err != nil {
		log.Fatalf("Harpocrates Server: loadkeys: %s", err)
	}

	config := tls.Config{Certificates: []tls.Certificate{cert}}
	config.Rand = rand.Reader
	service := "0.0.0.0:" + settings["port"]
	listener, err := tls.Listen("tcp", service, &config)

	if err != nil {
		log.Fatalf("Harpocrates Server: listen: %s", err)
	}

	log.Print("Harpocrates Server: listening")

	for {
		conn, err := listener.Accept()
		conn.SetDeadline(time.Now().Add(DEFAULT_SERVER_DEADLINE))
		if err != nil {
			log.Printf("Harpocrates Server accept connection: %s", err)
			break
		}

		defer conn.Close()
		tlscon, ok := conn.(*tls.Conn)
		if ok {
			state := tlscon.ConnectionState()
			for _, v := range state.PeerCertificates {
				log.Print(x509.MarshalPKIXPublicKey(v.PublicKey))
			}
		}

		go handleClient(conn, settings, storageService)
	}
}

func handleClient(conn net.Conn, settings map[string]string, storageService service.Storage) {
	defer conn.Close()

	decoder := msgpack.NewDecoder(conn)
	tmpstruct := new(PrivateKeyExchange)

	decoder.Decode(tmpstruct)

	var message PrivateKeyExchange

	if val, ok := blacklist[conn.RemoteAddr().String()]; ok {
		if val.BannedUntil.After(time.Now()) {
			message = PrivateKeyExchange{
				Type: MESSAGE_TYPE_BANNED,
			}

			b, _ := msgpack.Marshal(message)
			conn.Write(b)
			return
		}
	}

	authResult := core.CheckPasswordHash(tmpstruct.PasswordHash, masterPasswordHash)

	if authResult == false {
		if val, ok := blacklist[conn.RemoteAddr().String()]; !ok {
			blacklist[conn.RemoteAddr().String()] = Fail2Ban{
				IPAddr:      conn.RemoteAddr().String(),
				FailCount:   1,
				BannedUntil: time.Now(),
			}
		} else {
			bannedUntil := val.BannedUntil.Add(time.Duration(val.FailCount) * time.Minute)

			blacklist[conn.RemoteAddr().String()] = Fail2Ban{
				IPAddr:      val.IPAddr,
				FailCount:   val.FailCount + 1,
				BannedUntil: bannedUntil,
			}
		}

		log.Println("Wrong password attempt!")

		message = PrivateKeyExchange{
			Type: MESSAGE_TYPE_WRONG_CREDENTIALS,
		}
	} else {
		if _, ok := blacklist[conn.RemoteAddr().String()]; ok {
			delete(blacklist, conn.RemoteAddr().String())
		}

		switch tmpstruct.Type {
		case MESSAGE_TYPE_GET_PRIVATE_KEY:
			priKeyFile, _ := os.OpenFile(settings["private_key"], os.O_RDONLY|os.O_CREATE, 0666)
			bytes, _ := ioutil.ReadAll(priKeyFile)

			message = PrivateKeyExchange{
				PrivateKey: string(bytes),
				Type:       MESSAGE_TYPE_GET_PRIVATE_KEY,
			}

			priKeyFile.Close()
			break
		case MESSAGE_TYPE_STORE_PRIVATE_KEY:
			if _, ok := settings["private_key"]; ok {
				log.Println("Attempt to private key override!")

				message = PrivateKeyExchange{
					Type: MESSAGE_TYPE_PRIVATE_KEY_ALREADY_EXISTS,
				}
			} else {
				priKeyFile, _ := os.OpenFile(service.PRIVATE_KEY_LOCATION, os.O_WRONLY|os.O_CREATE, 0666)

				writer := bufio.NewWriter(priKeyFile)
				writer.Write([]byte(tmpstruct.PrivateKey))
				writer.Flush()

				settings["private_key"] = service.PRIVATE_KEY_LOCATION
				storageService.StoreSettings(settings)

				priKeyFile.Close()

				message = PrivateKeyExchange{
					Type: MESSAGE_TYPE_PRIVATE_KEY_SAVED,
				}
			}
		}
	}

	b, _ := msgpack.Marshal(message)
	conn.Write(b)

	log.Println("Harpocrates Server: Client connection closed")
}
