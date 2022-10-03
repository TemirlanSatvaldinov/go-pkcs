package pkcs7

import (
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"

	"github.com/qazsvm/go-pkcs/errlist"
	"github.com/qazsvm/go-pkcs/oid"
	"github.com/qazsvm/go-pkcs/pkcs5"
)

// pkcs5 struct
type PBES2Params struct {
	KeyDerivationFunc pkix.AlgorithmIdentifier
	EncryptionScheme  pkix.AlgorithmIdentifier
}
type PBKDF2Params struct {
	Salt           []byte
	IterationCount int
	PrfParam       pkix.AlgorithmIdentifier `asn1:"optional"`
}
type Attribute struct {
	AttrId     asn1.ObjectIdentifier
	AttrValues asn1.RawValue `asn1:"set"`
}
type X509Data struct {
	Id   asn1.ObjectIdentifier
	Data []byte `asn1:"tag:0,explicit"`
}
type DigestData struct {
	Id     pkix.AlgorithmIdentifier
	Digest []byte
}
type ContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"tag:0,explicit,optional"`
}

// 1
type EncryptedData struct {
	Version               int
	EncryptedContentInfo  EncryptedContentInfo
	UnprotectedAttributes pkix.AlgorithmIdentifier `asn1:"optional"`
}
type EncryptedContentInfo struct {
	ContentType                asn1.ObjectIdentifier
	ContentEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedContent           []byte `asn1:"tag:0,optional"`
}

func EncryptData(data, password []byte, PBKDF2Iterations, PBKDF2SaltSize int, cipherCode x509.PEMCipher) ([]byte, error) {
	// oidCertEncryption, err := oid.OIDFromCipher(certpbe)
	// if err != nil {
	// 	return nil, err
	// }
	if len(password) < 6 {
		return nil, errlist.ErrPasswordLen
	}
	hashFunc := sha256.New
	//
	oidCipher, err := oid.OIDFromCipher(cipherCode)
	if err != nil {
		return nil, err
	}
	salt, iv, encryptedContent, err := pkcs5.EncryptCBC(data, password, PBKDF2Iterations, PBKDF2SaltSize, cipherCode, hashFunc)
	if err != nil {
		return nil, err
	}

	//
	asnIV, err := asn1.Marshal(iv)
	if err != nil {
		return nil, err
	}
	encryptionScheme := pkix.AlgorithmIdentifier{
		Algorithm:  oidCipher,
		Parameters: asn1.RawValue{FullBytes: asnIV},
	}
	pbkdf2Params := PBKDF2Params{
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
	pbesParams := PBES2Params{
		EncryptionScheme:  encryptionScheme,
		KeyDerivationFunc: pbkdf2,
	}
	asnPBEParams, err := asn1.Marshal(pbesParams)
	if err != nil {
		return nil, err
	}

	encryptionAlgorithm := pkix.AlgorithmIdentifier{
		Algorithm: oid.PBES2,
		Parameters: asn1.RawValue{
			FullBytes: asnPBEParams,
		},
	}

	encryptedContentInfo := EncryptedContentInfo{
		ContentType:                oid.PKCS7Data,
		ContentEncryptionAlgorithm: encryptionAlgorithm,
		EncryptedContent:           encryptedContent,
	}
	encryptedData := EncryptedData{
		Version:              0,
		EncryptedContentInfo: encryptedContentInfo,
	}
	asnEncryptedData, err := asn1.Marshal(encryptedData)
	if err != nil {
		return nil, err
	}

	result := ContentInfo{
		ContentType: oid.PKCS7EncryptedData,
		Content: asn1.RawValue{
			Class:      2,
			Tag:        0,
			IsCompound: true,
			Bytes:      asnEncryptedData,
		},
	}
	return asn1.Marshal(result)

}

func Decode(data, password []byte) ([]byte, error) {

	p7 := new(ContentInfo)
	var result []byte
	if _, err := asn1.Unmarshal(data, p7); err != nil {
		return nil, err
	}
	// TODO: add signed Data
	switch {
	case p7.ContentType.Equal(oid.PKCS7EncryptedData):
		DecodeEncryptedData(p7.Content.Bytes, result)
	default:
		return nil, errors.New("pkcs7: unsupported OID")
	}
	return result, nil
}
func DecodeEncryptedData(data, password []byte) ([]byte, error) {

	encryptedData := new(EncryptedData)
	if _, err := asn1.Unmarshal(data, encryptedData); err != nil {
		return nil, err
	}
	if encryptedData.Version != 0 {
		return nil, errors.New("PKCS7 Encrypted Data: unsupported version")
	}

	var params PBES2Params
	if _, err := asn1.Unmarshal(encryptedData.EncryptedContentInfo.ContentEncryptionAlgorithm.Parameters.FullBytes, &params); err != nil {
		return nil, errors.New("PKCS7: invalid PBES2 parameters")
	}
	iv := make([]byte, 0)
	if _, err := asn1.Unmarshal(params.EncryptionScheme.Parameters.FullBytes, &iv); err != nil {
		return nil, err
	}

	if !params.KeyDerivationFunc.Algorithm.Equal(oid.PKCS5PBKDF2) {
		return nil, errors.New("PKCS7: support only PKCS5 PBKDF2")
	}
	pbkdf2Params := new(PBKDF2Params)
	if _, err := asn1.Unmarshal(params.KeyDerivationFunc.Parameters.FullBytes, pbkdf2Params); err != nil {
		return nil, err
	}
	oidkey := params.EncryptionScheme.Algorithm
	hash, _, err := pkcs5.HashFnFromOID(pbkdf2Params.PrfParam.Algorithm)
	if err != nil {
		return nil, err
	}
	decryptedData, err := pkcs5.DecryptCBC(encryptedData.EncryptedContentInfo.EncryptedContent, password, iv, pbkdf2Params.Salt, pbkdf2Params.IterationCount, oidkey, hash)
	if err != nil {
		return nil, err
	}

	return decryptedData, nil
}
