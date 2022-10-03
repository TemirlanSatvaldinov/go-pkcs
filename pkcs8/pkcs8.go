package pkcs8

import (
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"

	"github.com/encode/go-pkcs/oid"
	"github.com/encode/go-pkcs/pkcs5"
	"github.com/encode/go-pkcs/pkcs7"
)

// pkcs8
type EncryptedPKCS8Key struct {
	Algorithm  pkix.AlgorithmIdentifier
	PrivateKey []byte
}

func New(key interface{}, password []byte, PBKDF2Iterations, PBKDF2SaltSize int, cipherCode x509.PEMCipher) ([]byte, error) {
	if len(password) == 0 {
		return x509.MarshalPKCS8PrivateKey(key)
	}
	hashFn := sha256.New

	oidEncryptionScheme, errCipher := oid.OIDFromCipher(cipherCode)
	if errCipher != nil {
		return nil, errCipher
	}
	//
	var pkey []byte
	var err error
	if pkey, err = x509.MarshalPKCS8PrivateKey(key); err != nil {
		return nil, err
	}

	salt, iv, encryptedKey, err := pkcs5.EncryptCBC(pkey, password, PBKDF2Iterations, PBKDF2SaltSize, cipherCode, hashFn)
	if err != nil {
		return nil, err
	}
	asnIV, err := asn1.Marshal(iv)
	if err != nil {
		return nil, err
	}
	encryptionScheme := pkix.AlgorithmIdentifier{
		Algorithm:  oidEncryptionScheme,
		Parameters: asn1.RawValue{FullBytes: asnIV},
	}
	pbkdf2Params := pkcs7.PBKDF2Params{
		Salt:           salt,
		IterationCount: PBKDF2Iterations,
		PrfParam: pkix.AlgorithmIdentifier{
			Algorithm:  oid.HMACWithSHA256,
			Parameters: asn1.RawValue{Tag: asn1.TagNull}},
	}
	asnPBKDF2Params, err := asn1.Marshal(pbkdf2Params)
	if err != nil {
		return nil, err
	}
	pbkdf2 := pkix.AlgorithmIdentifier{
		Algorithm:  oid.PKCS5PBKDF2,
		Parameters: asn1.RawValue{FullBytes: asnPBKDF2Params},
	}
	pbesParams := pkcs7.PBES2Params{
		EncryptionScheme:  encryptionScheme,
		KeyDerivationFunc: pbkdf2,
	}

	asnPBEParams, err := asn1.Marshal(pbesParams)
	if err != nil {
		return nil, err
	}
	encryptionAlgorithm := pkix.AlgorithmIdentifier{
		Algorithm:  oid.PBES2,
		Parameters: asn1.RawValue{FullBytes: asnPBEParams},
	}

	pkcs8 := EncryptedPKCS8Key{
		Algorithm:  encryptionAlgorithm,
		PrivateKey: encryptedKey,
	}
	return asn1.Marshal(pkcs8)
}

func Decode(data, password []byte) (interface{}, error) {
	if password == nil {
		return x509.ParsePKCS8PrivateKey(data)
	}
	var p8 EncryptedPKCS8Key
	if _, err := asn1.Unmarshal(data, &p8); err != nil {
		return nil, err
	}

	if !p8.Algorithm.Algorithm.Equal(oid.PBES2) {
		return nil, errors.New("unsupported algorithm: only PBES2 is supported")
	}

	var params pkcs7.PBES2Params
	if _, err := asn1.Unmarshal(p8.Algorithm.Parameters.FullBytes, &params); err != nil {
		return nil, errors.New("pkcs8: invalid PBES2 parameters")
	}
	iv := make([]byte, 0)
	if _, err := asn1.Unmarshal(params.EncryptionScheme.Parameters.FullBytes, &iv); err != nil {
		return nil, err
	}

	if !params.KeyDerivationFunc.Algorithm.Equal(oid.PKCS5PBKDF2) {
		return nil, errors.New("pkcs8: support only PKCS5 PBKDF2")
	}
	pbkdf2Params := new(pkcs7.PBKDF2Params)
	if _, err := asn1.Unmarshal(params.KeyDerivationFunc.Parameters.FullBytes, pbkdf2Params); err != nil {
		return nil, err
	}
	oidkey := params.EncryptionScheme.Algorithm
	hash, _, err := pkcs5.HashFnFromOID(pbkdf2Params.PrfParam.Algorithm)
	if err != nil {
		return nil, err
	}
	decryptedKey, err := pkcs5.DecryptCBC(p8.PrivateKey, password, iv, pbkdf2Params.Salt, pbkdf2Params.IterationCount, oidkey, hash)
	if err != nil {
		return nil, err
	}

	return x509.ParsePKCS8PrivateKey(decryptedKey)
}
