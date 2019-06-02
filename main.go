package main

import "fmt"
import "github.com/blueskan/harpocrates/core"

func main() {
	cryptoManager := core.NewCryptoManager(4096)

	pri, pub := cryptoManager.CreatePubPriKey()

	fmt.Println("PRIVATE KEY:")
	fmt.Println(string(cryptoManager.PrivateKeyToBytes(pri)))

	fmt.Println("PUBLIC KEY:")
	fmt.Println(string(cryptoManager.PublicKeyToBytes(pub)))

	fmt.Println("ENCRYPT WITH PUB KEY")

	encryptedString := cryptoManager.EncryptWithPublicKey([]byte("hello world!"), pub)

	fmt.Println(string(encryptedString))

	fmt.Println("DECRYPT WITH PRI KEY")
	fmt.Println(string(cryptoManager.DecryptWithPrivateKey(encryptedString, pri)))
}
