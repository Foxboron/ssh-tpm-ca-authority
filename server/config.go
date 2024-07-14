package server

import (
	"os"
	"slices"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	yaml "github.com/goccy/go-yaml"
)

type UnmarshalTPMkey struct {
	*keyfile.TPMKey
}

func (v *UnmarshalTPMkey) UnmarshalYAML(b []byte) error {
	b, err := os.ReadFile(string(b))
	if err != nil {
		return err
	}
	k, err := keyfile.Decode(b)
	if err != nil {
		return err
	}

	*v = UnmarshalTPMkey{k}
	return nil
}

type UsersConf struct {
	User string `yaml:"user"`
	EK   string `yaml:"ek"`
}

type HostConf struct {
	Host   string           `yaml:"host"`
	CaFile *UnmarshalTPMkey `yaml:"ca_file"`
	Users  []*UsersConf     `yaml:"users"`
}

func (h *HostConf) IsValidUser(user string, ek string) bool {
	return slices.ContainsFunc(h.Users, func(u *UsersConf) bool {
		return u.User == user && u.EK == ek
	})
}

type Config struct {
	Hosts []*HostConf `yaml:"hosts"`
}

func (h *Config) HasHost(host string) (*HostConf, bool) {
	index := slices.IndexFunc(h.Hosts, func(h *HostConf) bool {
		return h.Host == host
	})
	if index == -1 {
		return nil, false
	}
	return h.Hosts[index], true
}

func NewConfig(b []byte) (*Config, error) {
	var v Config
	if err := yaml.Unmarshal(b, &v); err != nil {
		return nil, err
	}
	return &v, nil
}
