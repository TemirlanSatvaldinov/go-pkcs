package oid

import (
	"crypto/x509"
	"encoding/asn1"

	"github.com/qazsvm/go-pkcs/errlist"
)

var (
	PKCS7Data            = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	PKCS7EncryptedData   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 6}
	PKCS7SignedData      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	PKCS8ShroundedKeyBag = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 2}
	CertBag              = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 3}
	X509Certificate      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 22, 1}
	LocalKeyID           = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 21}
	FriendlyName         = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 20}
	CounterSignature     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 6}
	SigningTime          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
	ContentType          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	MessageDigest        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	SubjectKeyIdentifier = asn1.ObjectIdentifier{2, 5, 29, 14}

	SHA256WithRSA = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	PKCS5PBKDF2   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}
	PBES2         = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}

	HMACWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}
	SHA1           = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	SHA256         = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	SHA384         = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	SHA512         = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
	SHA224         = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 4}

	AES256CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
	AES128CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 2}
	AES192CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 22}
	DESCBC    = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 7}
	D3DESCBC  = asn1.ObjectIdentifier{1, 2, 840, 113549, 3, 7}
)

func OIDFromCipher(code x509.PEMCipher) (asn1.ObjectIdentifier, error) {
	switch code {
	case x509.PEMCipherAES256:
		return AES256CBC, nil
	case x509.PEMCipherAES192:
		return AES192CBC, nil
	case x509.PEMCipherAES128:
		return AES128CBC, nil
	case x509.PEMCipher3DES:
		return D3DESCBC, nil
	case x509.PEMCipherDES:
		return DESCBC, nil
	default:
		return nil, errlist.ErrUnknownCipher
	}
}
