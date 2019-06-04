package main

import (
	"bufio"
	"crypto/rsa"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"

	"github.com/blueskan/harpocrates/server"

	"github.com/blueskan/harpocrates/cli"
	"github.com/blueskan/harpocrates/core"
	"github.com/blueskan/harpocrates/service"
)

func main() {
	mode := flag.String("mode", "client", "operational mode")
	settingsLocation := flag.String("settings", "", "location of settings")
	passwordsLocation := flag.String("passwords", "", "location of passwords")

	flag.Parse()

	storageService := service.NewStorage(*passwordsLocation, *settingsLocation, *mode)

	fmt.Printf("Selected mode: %s\n\n", *mode)

	areSettingsExists := storageService.AreSettingsExists()
	settings := make(map[string]string)

	// Server
	if *mode == "server" {
		harpocratesCli := cli.NewCli()
		harpocratesCli.Banner()

		if !areSettingsExists {
			harpocratesCli.WelcomeMessage()

			settings["password"] = harpocratesCli.AskMasterPassword()
			settings["port"] = harpocratesCli.AskServerPort()

			storageService.StoreSettings(settings)

			fmt.Println("\n")
		} else {
			settings = storageService.ReadSettings()
		}

		server.Server(storageService)
	}

	// Client
	harpocratesCli := cli.NewCli()
	harpocratesCli.Banner()

	var pri *rsa.PrivateKey
	var pub *rsa.PublicKey
	var cryptoManager core.CryptoManager

	if !areSettingsExists {
		harpocratesCli.WelcomeMessage()
		password := harpocratesCli.AskMasterPassword()

		settings["server_host"] = harpocratesCli.AskServerAddr()
		settings["server_port"] = harpocratesCli.AskServerPort()
		settings["bits"] = harpocratesCli.AskEncryptionBits()
		bits, _ := strconv.Atoi(settings["bits"])

		cryptoManager = core.NewCryptoManager(bits)
		pri, pub = cryptoManager.CreatePubPriKey()

		request := server.PrivateKeyExchange{
			PasswordHash: password,
			PrivateKey:   string(cryptoManager.PrivateKeyToBytes(pri)),
			Type:         server.MESSAGE_TYPE_STORE_PRIVATE_KEY,
		}

		resp := server.Client(password, settings["server_host"], settings["server_port"], request)

		if resp.Type == server.MESSAGE_TYPE_WRONG_CREDENTIALS {
			fmt.Println("Wrong credentials")
			os.Exit(0)
		}

		if resp.Type == server.MESSAGE_TYPE_BANNED {
			fmt.Println("You're banned please try after a while..")
			os.Exit(0)
		}

		if resp.Type == server.MESSAGE_TYPE_PRIVATE_KEY_ALREADY_EXISTS {
			fmt.Println("Private key already exists in server")
			os.Exit(0)
		}

		if resp.Type == server.MESSAGE_TYPE_PRIVATE_KEY_ALREADY_EXISTS {
			fmt.Println("Server successfully saved private key.")
		}

		pubKeyFile, _ := os.OpenFile(service.PUBLIC_KEY_LOCATION, os.O_WRONLY|os.O_CREATE, 0666)

		writer := bufio.NewWriter(pubKeyFile)

		writer.Write(cryptoManager.PublicKeyToBytes(pub))
		writer.Flush()

		pubKeyFile.Close()

		settings["public_key"] = service.PUBLIC_KEY_LOCATION

		storageService.StoreSettings(settings)
	} else {
		password := harpocratesCli.AskMasterPassword()

		settings = storageService.ReadSettings()
		encryptionBits := settings["bits"]
		publicKey := settings["public_key"]
		serverHost := settings["server_host"]
		serverPort := settings["server_port"]

		bits, _ := strconv.Atoi(encryptionBits)

		cryptoManager = core.NewCryptoManager(bits)

		pubKeyFile, _ := os.OpenFile(publicKey, os.O_RDONLY|os.O_CREATE, 0666)
		bytes, _ := ioutil.ReadAll(pubKeyFile)

		pub = cryptoManager.BytesToPublicKey(bytes)

		pubKeyFile.Close()

		request := server.PrivateKeyExchange{
			PasswordHash: password,
			Type:         server.MESSAGE_TYPE_GET_PRIVATE_KEY,
		}

		resp := server.Client(password, serverHost, serverPort, request)

		if resp.Type == server.MESSAGE_TYPE_WRONG_CREDENTIALS {
			fmt.Println("Wrong credentials")
			os.Exit(0)
		}

		if resp.Type == server.MESSAGE_TYPE_BANNED {
			fmt.Println("You're banned please try after a while")
			os.Exit(0)
		}

		pri = cryptoManager.BytesToPrivateKey([]byte(resp.PrivateKey))
	}

	passwordService := service.NewPasswordService(
		cryptoManager,
		pri,
		pub,
		storageService,
	)

	harpocratesCli.SetPasswordService(*passwordService)
	harpocratesCli.Repl()
}
