package main

import (
	"encoding/binary"
	"fmt"
	"io"
)

// definition found in https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-publickeystruc

const ( // from https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-publickeystruc
	TYPE_KEYSTATEBLOB         = 0xC //The BLOB is a key state BLOB.
	TYPE_OPAQUEKEYBLOB        = 0x9 // The key is a session key.
	TYPE_PLAINTEXTKEYBLOB     = 0x8 // The key is a session key.
	TYPE_PRIVATEKEYBLOB       = 0x7 // The key is a public/private key pair.
	TYPE_PUBLICKEYBLOB        = 0x6 // The key is a public key.
	TYPE_PUBLICKEYBLOBEX      = 0xA // The key is a public key.
	TYPE_SIMPLEBLOB           = 0x1 // The key is a session key.
	TYPE_SYMMETRICWRAPKEYBLOB = 0xB // The key is a symmetric key.
)

const ( // from https://learn.microsoft.com/en-us/windows/win32/seccrypto/alg-id
	CALG_3DES                 = 0x00006603 // Triple DES encryption algorithm.
	CALG_3DES_112             = 0x00006609 // Two-key triple DES encryption with effective key length equal to 112 bits.
	CALG_AES                  = 0x00006611 // Advanced Encryption Standard (AES). This algorithm is supported by the Microsoft AES Cryptographic Provider.
	CALG_AES_128              = 0x0000660e // 128 bit AES. This algorithm is supported by the Microsoft AES Cryptographic Provider.
	CALG_AES_192              = 0x0000660f // 192 bit AES. This algorithm is supported by the Microsoft AES Cryptographic Provider.
	CALG_AES_256              = 0x00006610 // 256 bit AES. This algorithm is supported by the Microsoft AES Cryptographic Provider.
	CALG_AGREEDKEY_ANY        = 0x0000aa03 // Temporary algorithm identifier for handles of Diffie-Hellman–agreed keys.
	CALG_CYLINK_MEK           = 0x0000660c // An algorithm to create a 40-bit DES key that has parity bits and zeroed key bits to make its key length 64 bits. This algorithm is supported by the Microsoft Base Cryptographic Provider.
	CALG_DES                  = 0x00006601 // DES encryption algorithm.
	CALG_DESX                 = 0x00006604 // DESX encryption algorithm.
	CALG_DH_EPHEM             = 0x0000aa02 // Diffie-Hellman ephemeral key exchange algorithm.
	CALG_DH_SF                = 0x0000aa01 // Diffie-Hellman store and forward key exchange algorithm.
	CALG_DSS_SIGN             = 0x00002200 // DSA public key signature algorithm.
	CALG_ECDH                 = 0x0000aa05 // Elliptic curve Diffie-Hellman key exchange algorithm.
	CALG_ECDH_EPHEM           = 0x0000ae06 // Ephemeral elliptic curve Diffie-Hellman key exchange algorithm.
	CALG_ECDSA                = 0x00002203 // Elliptic curve digital signature algorithm.
	CALG_ECMQV                = 0x0000a001 // Elliptic curve Menezes, Qu, and Vanstone (MQV) key exchange algorithm. This algorithm is not supported.
	CALG_HASH_REPLACE_OWF     = 0x0000800b // One way function hashing algorithm.
	CALG_HUGHES_MD5           = 0x0000a003 // Hughes MD5 hashing algorithm.
	CALG_HMAC                 = 0x00008009 // HMAC keyed hash algorithm. This algorithm is supported by the Microsoft Base Cryptographic Provider.
	CALG_KEA_KEYX             = 0x0000aa04 // KEA key exchange algorithm (FORTEZZA). This algorithm is not supported.
	CALG_MAC                  = 0x00008005 // MAC keyed hash algorithm. This algorithm is supported by the Microsoft Base Cryptographic Provider.
	CALG_MD2                  = 0x00008001 // MD2 hashing algorithm. This algorithm is supported by the Microsoft Base Cryptographic Provider.
	CALG_MD4                  = 0x00008002 // MD4 hashing algorithm.
	CALG_MD5                  = 0x00008003 // MD5 hashing algorithm. This algorithm is supported by the Microsoft Base Cryptographic Provider.
	CALG_NO_SIGN              = 0x00002000 // No signature algorithm.
	CALG_OID_INFO_CNG_ONLY    = 0xffffffff // The algorithm is only implemented in CNG. The macro, IS_SPECIAL_OID_INFO_ALGID, can be used to determine whether a cryptography algorithm is only supported by using the CNG functions.
	CALG_OID_INFO_PARAMETERS  = 0xfffffffe // The algorithm is defined in the encoded parameters. The algorithm is only supported by using CNG. The macro, IS_SPECIAL_OID_INFO_ALGID, can be used to determine whether a cryptography algorithm is only supported by using the CNG functions.
	CALG_PCT1_MASTER          = 0x00004c04 // Used by the Schannel.dll operations system. This ALG_ID should not be used by applications.
	CALG_RC2                  = 0x00006602 // RC2 block encryption algorithm. This algorithm is supported by the Microsoft Base Cryptographic Provider.
	CALG_RC4                  = 0x00006801 // RC4 stream encryption algorithm. This algorithm is supported by the Microsoft Base Cryptographic Provider.
	CALG_RC5                  = 0x0000660d // RC5 block encryption algorithm.
	CALG_RSA_KEYX             = 0x0000a400 // RSA public key exchange algorithm. This algorithm is supported by the Microsoft Base Cryptographic Provider.
	CALG_RSA_SIGN             = 0x00002400 // RSA public key signature algorithm. This algorithm is supported by the Microsoft Base Cryptographic Provider.
	CALG_SCHANNEL_ENC_KEY     = 0x00004c07 // Used by the Schannel.dll operations system. This ALG_ID should not be used by applications.
	CALG_SCHANNEL_MAC_KEY     = 0x00004c03 // Used by the Schannel.dll operations system. This ALG_ID should not be used by applications.
	CALG_SCHANNEL_MASTER_HASH = 0x00004c02 // Used by the Schannel.dll operations system. This ALG_ID should not be used by applications.
	CALG_SEAL                 = 0x00006802 // SEAL encryption algorithm. This algorithm is not supported.
	CALG_SHA                  = 0x00008004 // SHA hashing algorithm. This algorithm is supported by the Microsoft Base Cryptographic Provider.
	CALG_SHA1                 = 0x00008004 // Same as CALG_SHA. This algorithm is supported by the Microsoft Base Cryptographic Provider.
	CALG_SHA_256              = 0x0000800c // 256 bit SHA hashing algorithm. This algorithm is supported by Microsoft Enhanced RSA and AES Cryptographic Provider..Windows XP with SP3: This algorithm is supported by the Microsoft Enhanced RSA and AES Cryptographic Provider (Prototype).
	CALG_SHA_384              = 0x0000800d // 384 bit SHA hashing algorithm. This algorithm is supported by Microsoft Enhanced RSA and AES Cryptographic Provider.Windows XP with SP3: This algorithm is supported by the Microsoft Enhanced RSA and AES Cryptographic Provider (Prototype).
	CALG_SHA_512              = 0x0000800e // 512 bit SHA hashing algorithm. This algorithm is supported by Microsoft Enhanced RSA and AES Cryptographic Provider.Windows XP with SP3: This algorithm is supported by the Microsoft Enhanced RSA and AES Cryptographic Provider (Prototype).
	CALG_SKIPJACK             = 0x0000660a // Skipjack block encryption algorithm (FORTEZZA). This algorithm is not supported.
	CALG_SSL2_MASTER          = 0x00004c05 // Used by the Schannel.dll operations system. This ALG_ID should not be used by applications.
	CALG_SSL3_MASTER          = 0x00004c01 // Used by the Schannel.dll operations system. This ALG_ID should not be used by applications.
	CALG_SSL3_SHAMD5          = 0x00008008 // Used by the Schannel.dll operations system. This ALG_ID should not be used by applications.
	CALG_TEK                  = 0x0000660b // TEK (FORTEZZA). This algorithm is not supported.
	CALG_TLS1_MASTER          = 0x00004c06 // Used by the Schannel.dll operations system. This ALG_ID should not be used by applications.
	CALG_TLS1PRF              = 0x0000800a // Used by the Schannel.dll operations system. This ALG_ID should not be used by applications.
)

type PUBLICKEYSTRUC struct {
	Type     uint8  `json:"type"`
	Version  uint8  `json:"version"`
	Reserved uint16 `json:"reserved"`
	KeyAlg   uint32 `json:"keyalg"`
}

type PUBLICKEYSTRUC_EX struct {
	PUBLICKEYSTRUC
	TypeName   string `json:"type_name"`
	KeyAlgName string `json:"keyalg_name"`
	KeyAlgHex  string `json:"keyalg_hex"`
}

func ReadPUBLICKEYSTRUC(r io.Reader) (*PUBLICKEYSTRUC, error) {
	pk := &PUBLICKEYSTRUC{}
	err := binary.Read(r, binary.LittleEndian, pk)
	return pk, err
}

func (pk *PUBLICKEYSTRUC) GetExtended() *PUBLICKEYSTRUC_EX {
	pke := &PUBLICKEYSTRUC_EX{
		PUBLICKEYSTRUC: *pk,
		TypeName:       pk.GetTypeName(),
		KeyAlgName:     pk.GetKeyAlgName(),
		KeyAlgHex:      fmt.Sprintf("0x%x", pk.KeyAlg),
	}
	return pke
}

func (pk *PUBLICKEYSTRUC) GetTypeName() string {
	switch pk.Type {
	case TYPE_KEYSTATEBLOB:
		return "KEYSTATEBLOB"
	case TYPE_OPAQUEKEYBLOB:
		return "OPAQUEKEYBLOB"
	case TYPE_PLAINTEXTKEYBLOB:
		return "PLAINTEXTKEYBLOB"
	case TYPE_PRIVATEKEYBLOB:
		return "PRIVATEKEYBLOB"
	case TYPE_PUBLICKEYBLOB:
		return "PUBLICKEYBLOB"
	case TYPE_PUBLICKEYBLOBEX:
		return "PUBLICKEYBLOBEX"
	case TYPE_SIMPLEBLOB:
		return "SIMPLEBLOB"
	case TYPE_SYMMETRICWRAPKEYBLOB:
		return "SYMMETRICWRAPKEYBLOB"
	}
	return "UNKNOWN"
}

func (pk *PUBLICKEYSTRUC) GetKeyAlgName() string {
	switch pk.KeyAlg {
	case CALG_3DES:
		return "3DES"
	case CALG_3DES_112:
		return "3DES_112"
	case CALG_AES:
		return "AES"
	case CALG_AES_128:
		return "AES_128"
	case CALG_AES_192:
		return "AES_192"
	case CALG_AES_256:
		return "AES_256"
	case CALG_AGREEDKEY_ANY:
		return "AGREEDKEY_ANY"
	case CALG_CYLINK_MEK:
		return "CYLINK_MEK"
	case CALG_DES:
		return "DES"
	case CALG_DESX:
		return "DESX"
	case CALG_DH_EPHEM:
		return "DH_EPHEM"
	case CALG_DH_SF:
		return "DH_SF"
	case CALG_DSS_SIGN:
		return "DSS_SIGN"
	case CALG_ECDH:
		return "ECDH"
	case CALG_ECDH_EPHEM:
		return "ECDH_EPHEM"
	case CALG_ECDSA:
		return "ECDSA"
	case CALG_ECMQV:
		return "ECMQV"
	case CALG_HASH_REPLACE_OWF:
		return "HASH_REPLACE_OWF"
	case CALG_HUGHES_MD5:
		return "HUGHES_MD5"
	case CALG_HMAC:
		return "HMAC"
	case CALG_KEA_KEYX:
		return "KEA_KEYX"
	case CALG_MAC:
		return "MAC"
	case CALG_MD2:
		return "MD2"
	case CALG_MD4:
		return "MD4"
	case CALG_MD5:
		return "MD5"
	case CALG_NO_SIGN:
		return "NO_SIGN"
	case CALG_OID_INFO_CNG_ONLY:
		return "OID_INFO_CNG_ONLY"
	case CALG_OID_INFO_PARAMETERS:
		return "OID_INFO_PARAMETERS"
	case CALG_PCT1_MASTER:
		return "PCT1_MASTER"
	case CALG_RC2:
		return "RC2"
	case CALG_RC4:
		return "RC4"
	case CALG_RC5:
		return "RC5"
	case CALG_RSA_KEYX:
		return "RSA_KEYX"
	case CALG_RSA_SIGN:
		return "RSA_SIGN"
	case CALG_SCHANNEL_ENC_KEY:
		return "SCHANNEL_ENC_KEY"
	case CALG_SCHANNEL_MAC_KEY:
		return "SCHANNEL_MAC_KEY"
	case CALG_SCHANNEL_MASTER_HASH:
		return "SCHANNEL_MASTER_HASH"
	case CALG_SEAL:
		return "SEAL"
	case CALG_SHA1: // CALG_SHA1 and CALG_SHA are the same
		return "SHA1"
	case CALG_SHA_256:
		return "SHA_256"
	case CALG_SHA_384:
		return "SHA_384"
	case CALG_SHA_512:
		return "SHA_512"
	case CALG_SKIPJACK:
		return "SKIPJACK"
	case CALG_SSL2_MASTER:
		return "SSL2_MASTER"
	case CALG_SSL3_MASTER:
		return "SSL3_MASTER"
	case CALG_SSL3_SHAMD5:
		return "SSL3_SHAMD5"
	case CALG_TEK:
		return "TEK"
	case CALG_TLS1_MASTER:
		return "TLS1_MASTER"
	case CALG_TLS1PRF:
		return "TLS1PRF"
	}
	return "UNKNOWN"
}
