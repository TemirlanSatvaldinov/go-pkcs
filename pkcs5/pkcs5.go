package pkcs5

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"hash"

	"github.com/qazsvm/go-pkcs/errlist"
	"golang.org/x/crypto/pbkdf2"
)

const DefaultPBKDF2Iterations = 2048 //10000
const DefaultPBKDF2SaltSize = 16

func DecryptCBC(encryptedData, password, iv, salt []byte, PBKDF2Iterations int, id asn1.ObjectIdentifier, h func() hash.Hash) ([]byte, error) {
	var keyLen int
	if keyLen, _ = keyLenFromOID(id); keyLen == 0 {
		return nil, errlist.ErrUnknownOID
	}
	dkey := pbkdf2.Key(password, salt, PBKDF2Iterations, keyLen, h)
	block, err := cipherFromOID(dkey, id)
	if err != nil {
		return nil, err
	}
	blockMode := cipher.NewCBCDecrypter(block, iv)
	blockMode.CryptBlocks(encryptedData, encryptedData)

	return encryptedData, nil
}
func EncryptCBC(data, password []byte, PBKDF2Iterations, PBKDF2SaltSize int, cipherCode x509.PEMCipher, h func() hash.Hash) ([]byte, []byte, []byte, error) {
	if len(password) < 6 {
		return nil, nil, nil, errlist.ErrPasswordLen
	}
	var keyLen, blockSize int

	if keyLen, blockSize = keyLenFromCode(cipherCode); keyLen == 0 {
		return nil, nil, nil, errlist.ErrUnknownCipher
	}
	salt, iv := make([]byte, PBKDF2SaltSize), make([]byte, blockSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, nil, nil, errors.New("failed to generate salt")
	}
	if _, err := rand.Read(iv); err != nil {
		return nil, nil, nil, errors.New("failed to generate iv")
	}
	dkey := pbkdf2.Key(password, salt, PBKDF2Iterations, keyLen, h)
	block, err := cipherFromCode(dkey, cipherCode)
	if err != nil {
		return nil, nil, nil, err
	}
	blockMode := cipher.NewCBCEncrypter(block, iv)
	paddingLen := block.BlockSize() - (len(data) % block.BlockSize())
	encryptedData := make([]byte, len(data)+paddingLen)
	copy(encryptedData, data)
	copy(encryptedData[len(data):], bytes.Repeat([]byte{byte(paddingLen)}, paddingLen))
	blockMode.CryptBlocks(encryptedData, encryptedData)

	return salt, iv, encryptedData, nil
}
