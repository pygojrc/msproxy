package mspx

import (
	"crypto/hmac"
	"encoding/base64"
	"errors"

	"github.com/xtls/xray-core/common/protocol"
	"google.golang.org/protobuf/proto"
)

type MemoryAccount struct {
	PSK string
	Key []byte
}

func (a *Account) AsAccount() (protocol.Account, error) {
	key, err := base64.StdEncoding.Strict().DecodeString(a.Psk)
	if err != nil || len(key) != 32 {
		return nil, errors.New("MSPX psk 必须是32字节随机密钥的标准 base64")
	}
	return &MemoryAccount{PSK: a.Psk, Key: key}, nil
}

func (a *MemoryAccount) Equals(other protocol.Account) bool {
	b, ok := other.(*MemoryAccount)
	return ok && hmac.Equal(a.Key, b.Key)
}

func (a *MemoryAccount) ToProto() proto.Message {
	return &Account{Psk: a.PSK}
}
