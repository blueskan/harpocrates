package service

import (
	"crypto/rsa"
	"fmt"

	"github.com/blueskan/harpocrates/core"
)

type Password struct {
	url               string
	encryptedPassword []byte
}

type PasswordRepresentation struct {
	Name     string
	Url      string
	Password string
}

type PasswordService struct {
	cryptoManager core.CryptoManager
	privateKey    *rsa.PrivateKey
	publicKey     *rsa.PublicKey
	passwords     map[string]Password
}

func (p *PasswordService) ListPasswords() []*PasswordRepresentation {
	passwords := make([]*PasswordRepresentation, 0)

	for key, val := range p.passwords {
		passwords = append(passwords, &PasswordRepresentation{
			Name: key,
			Url:  val.url,
		})
	}
}

func (p *PasswordService) GetPassword(name string) (*PasswordRepresentation, error) {
	if val, ok := p.passwords[name]; ok {
		password := p.cryptoManager.DecryptWithPrivateKey(val.encryptedPassword, p.privateKey)

		return &PasswordRepresentation{
			Name:     name,
			Url:      val.url,
			Password: string(password),
		}, nil
	}

	return nil, fmt.Errorf("Key `%s` not found", name)
}

func (p *PasswordService) StorePassword(representation PasswordRepresentation) (*PasswordRepresentation, error) {
	if _, ok := p.passwords[representation.Name]; ok {
		return nil, fmt.Errorf("Key `%s` already exists in your password database, please prefer other name or get password from this key.", representation.Name)
	}

	encryptedPassword := p.cryptoManager.EncryptWithPublicKey([]byte(representation.Password), p.publicKey)
	p.passwords[representation.Name] = Password{
		url:               representation.Url,
		encryptedPassword: encryptedPassword,
	}

	return &representation, nil
}
