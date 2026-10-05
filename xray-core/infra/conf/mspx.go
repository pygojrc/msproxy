package conf

import (
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/proxy/mspx"
	"google.golang.org/protobuf/proto"
)

type MSPXUser struct {
	PSK   string `json:"psk"`
	Email string `json:"email"`
	Level uint32 `json:"level"`
}

func (u MSPXUser) build() (*protocol.User, error) {
	a := &mspx.Account{Psk: u.PSK}
	if _, err := a.AsAccount(); err != nil {
		return nil, err
	}
	return &protocol.User{Account: serial.ToTypedMessage(a), Email: u.Email, Level: u.Level}, nil
}

type MSPXInboundConfig struct {
	Clients []MSPXUser `json:"clients"`
}

func (c *MSPXInboundConfig) Build() (proto.Message, error) {
	if len(c.Clients) == 0 {
		return nil, errors.New("MSPX clients 不能为空")
	}
	config := &mspx.ServerConfig{}
	seen := make(map[string]bool)
	for _, raw := range c.Clients {
		user, err := raw.build()
		if err != nil {
			return nil, err
		}
		if seen[raw.PSK] {
			return nil, errors.New("MSPX psk 账户重复")
		}
		seen[raw.PSK] = true
		config.Users = append(config.Users, user)
	}
	return config, nil
}

type MSPXOutboundConfig struct {
	Address *Address `json:"address"`
	Port    uint16   `json:"port"`
	PSK     string   `json:"psk"`
	Email   string   `json:"email"`
	Level   uint32   `json:"level"`
}

func (c *MSPXOutboundConfig) Build() (proto.Message, error) {
	if c.Address == nil || c.Port == 0 {
		return nil, errors.New("MSPX address/port 无效")
	}
	user, err := (MSPXUser{PSK: c.PSK, Email: c.Email, Level: c.Level}).build()
	if err != nil {
		return nil, err
	}
	return &mspx.ClientConfig{Server: &protocol.ServerEndpoint{Address: c.Address.Build(), Port: uint32(c.Port), User: user}}, nil
}
