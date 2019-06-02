package core

import (
	"crypto/rsa"
	"strings"
	"testing"
)

// TODO i think, this test is anemic, every case depends on before case itself..

var sut = NewCryptoManager(4096)
var pri *rsa.PrivateKey
var pub *rsa.PublicKey

func Test_it_should_create_new_crypto_manager_with_correct_bit_count(t *testing.T) {
	bits := sut.GetBits()

	if bits != 4096 {
		t.Errorf("Bits was incorrect, got: %d, want: %d", bits, 4096)
	}
}

func Test_it_should_create_pub_pri_key(t *testing.T) {
	pri, pub = sut.CreatePubPriKey()

	if pri == nil {
		t.Errorf("Crypto Manager was not create private key")
	}

	if pub == nil {
		t.Errorf("Crypto Manager was not create public key")
	}
}

func Test_it_should_convert_private_key_to_bytes(t *testing.T) {
	priKey := string(sut.PrivateKeyToBytes(pri))
	correctPriKeyFormat := strings.Contains(priKey, "BEGIN RSA PRIVATE KEY")

	if !correctPriKeyFormat {
		t.Errorf("Private key was incorrect, got %s", priKey)
	}
}

func Test_it_should_convert_public_key_to_bytes(t *testing.T) {
	pubKey := string(sut.PublicKeyToBytes(pub))
	correctPriKeyFormat := strings.Contains(pubKey, "PUBLIC KEY")

	if !correctPriKeyFormat {
		t.Errorf("Public key was incorrect, got %s", pubKey)
	}
}

func Test_it_should_encrypt_and_decrypt_any_text_with_pub_pri_key(t *testing.T) {
	enrcyptedText := sut.EncryptWithPublicKey([]byte("testing"), pub)

	if string(enrcyptedText) == "testing" {
		t.Errorf("Encrypted text was incorrect")
	}

	decryptedText := sut.DecryptWithPrivateKey(enrcyptedText, pri)

	if string(decryptedText) != "testing" {
		t.Errorf("Decrypted text was not same with before encryption text")
	}
}
