package pkcs5

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"hash"

	"github.com/qazsvm/go-pkcs/errlist"
	"github.com/qazsvm/go-pkcs/oid"
)

func cipherFromOID(key []byte, id asn1.ObjectIdentifier) (cipher.Block, error) {
	switch {
	case id.Equal(oid.AES256CBC):
		ci, err := aes.NewCipher(key)
		return ci, err
	case id.Equal(oid.AES192CBC):
		ci, err := aes.NewCipher(key)
		return ci, err
	case id.Equal(oid.AES128CBC):
		ci, err := aes.NewCipher(key)
		return ci, err
	case id.Equal(oid.D3DESCBC):
		ci, err := des.NewTripleDESCipher(key)
		return ci, err
	case id.Equal(oid.DESCBC):
		ci, err := des.NewCipher(key)
		return ci, err
	}
	return nil, errlist.ErrUnknownOID
}
func keyLenFromOID(id asn1.ObjectIdentifier) (int, int) {

	switch {
	case id.Equal(oid.AES256CBC):
		return 32, aes.BlockSize
	case id.Equal(oid.AES192CBC):
		return 24, aes.BlockSize
	case id.Equal(oid.AES128CBC):
		return 16, aes.BlockSize
	case id.Equal(oid.D3DESCBC):
		return 24, des.BlockSize
	case id.Equal(oid.DESCBC):
		return 8, des.BlockSize
	}
	return 0, 0
}
func cipherFromCode(key []byte, code x509.PEMCipher) (cipher.Block, error) {
	switch code {
	case x509.PEMCipherAES256:
		ci, err := aes.NewCipher(key)
		return ci, err
	case x509.PEMCipherAES192:
		ci, err := aes.NewCipher(key)
		return ci, err
	case x509.PEMCipherAES128:
		ci, err := aes.NewCipher(key)
		return ci, err
	case x509.PEMCipher3DES:
		ci, err := des.NewTripleDESCipher(key)
		return ci, err
	case x509.PEMCipherDES:
		ci, err := des.NewCipher(key)
		return ci, err
	default:
		return nil, errlist.ErrUnknownCipher
	}
}
func keyLenFromCode(code x509.PEMCipher) (int, int) {

	switch code {
	case x509.PEMCipherAES256:
		return 32, aes.BlockSize
	case x509.PEMCipherAES192:
		return 24, aes.BlockSize
	case x509.PEMCipherAES128:
		return 16, aes.BlockSize
	case x509.PEMCipher3DES:
		return 24, des.BlockSize
	case x509.PEMCipherDES:
		return 8, des.BlockSize
	default:
		return 0, 0
	}
}
func HashFnFromOID(asnOID asn1.ObjectIdentifier) (func() hash.Hash, func([]byte) []byte, error) {

	switch {
	case asnOID.Equal(oid.SHA1):
		return sha1.New, sha1Sum, nil
	case asnOID.Equal(oid.SHA224):
		return sha256.New224, sha224Sum, nil
	case asnOID.Equal(oid.SHA256):
		return sha256.New, sha256Sum, nil
	case asnOID.Equal(oid.SHA384):
		return sha512.New384, sha384Sum, nil
	case asnOID.Equal(oid.SHA512):
		return sha512.New, sha512Sum, nil
	case asnOID.Equal(oid.HMACWithSHA256):
		return sha256.New, sha256Sum, nil
	}

	return nil, nil, errlist.ErrUnknownOID

}
func sha1Sum(input []byte) []byte {
	res := sha1.Sum(input)
	return res[:]
}
func sha224Sum(input []byte) []byte {
	res := sha256.Sum224(input)
	return res[:]
}
func sha256Sum(input []byte) []byte {
	res := sha256.Sum256(input)
	return res[:]
}
func sha384Sum(input []byte) []byte {
	res := sha512.Sum384(input)
	return res[:]
}
func sha512Sum(input []byte) []byte {
	res := sha512.Sum512(input)
	return res[:]
}
