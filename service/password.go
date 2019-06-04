package service

import (
	"crypto/rsa"
	"encoding/csv"
	"fmt"
	"os"

	"github.com/blueskan/harpocrates/core"
)

type Password struct {
	Url               string
	EncryptedPassword []byte
}

type PasswordRepresentation struct {
	Name     string
	Url      string
	Password string
}

type PasswordService struct {
	cryptoManager  core.CryptoManager
	privateKey     *rsa.PrivateKey
	publicKey      *rsa.PublicKey
	passwords      map[string]Password
	storageService Storage
}

func NewPasswordService(
	cryptoManager core.CryptoManager,
	privateKey *rsa.PrivateKey,
	publicKey *rsa.PublicKey,
	storageService Storage,
) *PasswordService {
	passwords := storageService.ReadPasswords()

	return &PasswordService{
		cryptoManager:  cryptoManager,
		privateKey:     privateKey,
		publicKey:      publicKey,
		passwords:      passwords,
		storageService: storageService,
	}
}

func (p *PasswordService) ListPasswords() []*PasswordRepresentation {
	passwords := make([]*PasswordRepresentation, 0)

	for key, val := range p.passwords {
		passwords = append(passwords, &PasswordRepresentation{
			Name: key,
			Url:  val.Url,
		})
	}

	return passwords
}

func (p *PasswordService) GetPassword(name string) (*PasswordRepresentation, error) {
	if val, ok := p.passwords[name]; ok {
		password := p.cryptoManager.DecryptWithPrivateKey(val.EncryptedPassword, p.privateKey)

		return &PasswordRepresentation{
			Name:     name,
			Url:      val.Url,
			Password: string(password),
		}, nil
	}

	return nil, fmt.Errorf("Key `%s` not found", name)
}

func (p *PasswordService) DeletePassword(name string) error {
	if _, ok := p.passwords[name]; !ok {
		return fmt.Errorf("Password named as `%s` not exists", name)
	}

	delete(p.passwords, name)

	p.storageService.StorePasswords(p.passwords)

	return nil
}

func (p *PasswordService) ExportToCsv(filename string) {
	file, _ := os.Create(filename)
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	var data = [][]string{{"Name", "URL", "Password"}}

	for key, _ := range p.passwords {
		password, _ := p.GetPassword(key)

		data = append(data, []string{key, password.Url, password.Password})
	}

	for _, value := range data {
		writer.Write(value)
	}
}

func (p *PasswordService) StorePassword(representation PasswordRepresentation) (*PasswordRepresentation, error) {
	if _, ok := p.passwords[representation.Name]; ok {
		return nil, fmt.Errorf("Key `%s` already exists in your password database, please prefer other name or get password from this key.", representation.Name)
	}

	encryptedPassword := p.cryptoManager.EncryptWithPublicKey([]byte(representation.Password), p.publicKey)
	p.passwords[representation.Name] = Password{
		Url:               representation.Url,
		EncryptedPassword: encryptedPassword,
	}

	p.storageService.StorePasswords(p.passwords)

	return &representation, nil
}
