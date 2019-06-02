package core

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
)

type CryptoManager interface {
	GetBits() int

	CreatePubPriKey() (*rsa.PrivateKey, *rsa.PublicKey)
	PrivateKeyToBytes(pri *rsa.PrivateKey) []byte
	PublicKeyToBytes(pub *rsa.PublicKey) []byte
	BytesToPrivateKey(priv []byte) *rsa.PrivateKey
	BytesToPublicKey(pub []byte) *rsa.PublicKey
	EncryptWithPublicKey(msg []byte, pub *rsa.PublicKey) []byte
	DecryptWithPrivateKey(ciphertext []byte, priv *rsa.PrivateKey) []byte
}

type cryptoManager struct {
	bits int
}

func NewCryptoManager(bits int) CryptoManager {
	return &cryptoManager{
		bits: bits,
	}
}

func (cm *cryptoManager) GetBits() int {
	return cm.bits
}

func (cm *cryptoManager) CreatePubPriKey() (*rsa.PrivateKey, *rsa.PublicKey) {
	privkey, _ := rsa.GenerateKey(rand.Reader, cm.bits)

	return privkey, &privkey.PublicKey
}

func (cm *cryptoManager) PrivateKeyToBytes(pri *rsa.PrivateKey) []byte {
	privBytes := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(pri),
		},
	)

	return privBytes
}

func (cm *cryptoManager) PublicKeyToBytes(pub *rsa.PublicKey) []byte {
	pubASN1, _ := x509.MarshalPKIXPublicKey(pub)

	pubBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubASN1,
	})

	return pubBytes
}

func (cm *cryptoManager) BytesToPrivateKey(priv []byte) *rsa.PrivateKey {
	block, _ := pem.Decode(priv)
	enc := x509.IsEncryptedPEMBlock(block)
	b := block.Bytes
	var err error

	if enc {
		// log.Println("is encrypted pem block")
		b, err = x509.DecryptPEMBlock(block, nil)
		if err != nil {
			// log.Error(err)
		}
	}

	key, err := x509.ParsePKCS1PrivateKey(b)
	if err != nil {
		// log.Error(err)
	}

	return key
}

func (cm *cryptoManager) BytesToPublicKey(pub []byte) *rsa.PublicKey {
	block, _ := pem.Decode(pub)
	enc := x509.IsEncryptedPEMBlock(block)
	b := block.Bytes
	var err error

	if enc {
		// log.Println("is encrypted pem block")
		b, err = x509.DecryptPEMBlock(block, nil)
		if err != nil {
			// log.Error(err)
		}
	}

	ifc, err := x509.ParsePKIXPublicKey(b)
	if err != nil {
		// log.Error(err)
	}

	key, ok := ifc.(*rsa.PublicKey)
	if !ok {
		// log.Error("not ok")
	}

	return key
}

func (cm *cryptoManager) EncryptWithPublicKey(msg []byte, pub *rsa.PublicKey) []byte {
	hash := sha512.New()
	ciphertext, err := rsa.EncryptOAEP(hash, rand.Reader, pub, msg, nil)
	if err != nil {
		// log.Error(err)
	}

	return ciphertext
}

func (cm *cryptoManager) DecryptWithPrivateKey(ciphertext []byte, priv *rsa.PrivateKey) []byte {
	hash := sha512.New()
	plaintext, err := rsa.DecryptOAEP(hash, rand.Reader, priv, ciphertext, nil)

	if err != nil {
		// log.Error(err)
	}

	return plaintext
}
