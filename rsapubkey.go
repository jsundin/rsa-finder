package main

import (
	"encoding/binary"
	"io"
)

const (
	RSAPUBKEY_MAGIC_PUBKEY      = 0x31415352 // "RSA1"
	RSAPUBKEY_MAGIC_PRIVKEY     = 0x32415352 // "RSA2"
	RSAPUBKEY_MAGIC_PUBKEY_STR  = "RSA1"
	RSAPUBKEY_MAGIC_PRIVKEY_STR = "RSA2"
)

type RSAPUBKEY struct {
	Magic  uint32 `json:"magic"`
	Bitlen uint32 `json:"bitlen"`
	Pubexp uint32 `json:"pubexp"`
}

type RSAPUBKEY_EX struct {
	RSAPUBKEY
	MagicName string `json:"magic_name"`
}

func ReadRSAPUBKEY(r io.Reader) (*RSAPUBKEY, error) {
	rpk := &RSAPUBKEY{}
	err := binary.Read(r, binary.LittleEndian, rpk)
	return rpk, err
}

func (rpk *RSAPUBKEY) GetExtended() *RSAPUBKEY_EX {
	rpke := &RSAPUBKEY_EX{
		RSAPUBKEY: *rpk,
		MagicName: rpk.GetMagicName(),
	}
	return rpke
}

func (rpk *RSAPUBKEY) GetMagicName() string {
	switch rpk.Magic {
	case RSAPUBKEY_MAGIC_PUBKEY:
		return RSAPUBKEY_MAGIC_PUBKEY_STR
	case RSAPUBKEY_MAGIC_PRIVKEY:
		return RSAPUBKEY_MAGIC_PRIVKEY_STR
	}
	return "UNKNOWN"
}
