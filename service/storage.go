package service

import (
	"bufio"
	"io/ioutil"
	"os"
	"os/user"

	"github.com/go-ini/ini"
	"github.com/vmihailenco/msgpack"
)

type Storage interface {
	StorePasswords(passwords map[string]Password)
	ReadPasswords() map[string]Password
	StoreSettings(settings map[string]string)
	ReadSettings() map[string]string
	AreSettingsExists() bool
}

type storage struct {
	passwordLocation string
	settingsLocation string
}

var PRIVATE_KEY_LOCATION string
var PUBLIC_KEY_LOCATION string

const DEFAULT_DATABASE_NAME = "harpocrates.db"
const DEFAULT_SETTINGS_NAME = "harpocrates.ini"

func NewStorage(passwordLocation, defaultSettingsLocation, mode string) Storage {
	user, _ := user.Current()
	homeDir := user.HomeDir

	PRIVATE_KEY_LOCATION = homeDir + string(os.PathSeparator) + "harpocrates"
	PUBLIC_KEY_LOCATION = homeDir + string(os.PathSeparator) + "harpocrates.pub"

	if len(passwordLocation) <= 0 {
		passwordLocation = homeDir + string(os.PathSeparator) + DEFAULT_DATABASE_NAME
	}

	if len(defaultSettingsLocation) <= 0 {
		defaultSettingsLocation = homeDir + string(os.PathSeparator) + mode + "_" + DEFAULT_SETTINGS_NAME
	}

	return &storage{
		passwordLocation: passwordLocation,
		settingsLocation: defaultSettingsLocation,
	}
}

func (s *storage) StorePasswords(passwords map[string]Password) {
	b, err := msgpack.Marshal(&passwords)

	if err != nil {
		panic(err)
	}

	ioutil.WriteFile(s.passwordLocation, b, 666)
}

func (s *storage) ReadPasswords() map[string]Password {
	database, err := os.OpenFile(s.passwordLocation, os.O_RDONLY|os.O_CREATE, 0666)
	defer database.Close()

	if err != nil {
		panic(err)
	}

	bytes, _ := ioutil.ReadAll(database)

	var passwords map[string]Password
	msgpack.Unmarshal(bytes, &passwords)

	if passwords == nil {
		passwords = make(map[string]Password, 0)
	}

	return passwords
}

func (s *storage) StoreSettings(settings map[string]string) {
	cfg := ini.Empty()

	section := cfg.Section("harpocrates")

	for key, value := range settings {
		section.NewKey(key, value)
	}

	serverConfigFile, err := os.OpenFile(s.settingsLocation, os.O_WRONLY|os.O_CREATE, 0666)
	defer serverConfigFile.Close()

	if err != nil {
		panic(err)
	}

	writer := bufio.NewWriter(serverConfigFile)
	cfg.WriteTo(writer)

	writer.Flush()
}

func (s *storage) ReadSettings() map[string]string {
	cfg, _ := ini.Load(s.settingsLocation)
	section := cfg.Section("harpocrates")

	settings := make(map[string]string)

	for _, value := range section.Keys() {
		settings[value.Name()] = value.String()
	}

	return settings
}

func (s *storage) AreSettingsExists() bool {
	if _, err := os.Stat(s.settingsLocation); err != nil {
		if os.IsNotExist(err) {
			return false
		}
	}

	return true
}
