package pkcs7

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"

	"github.com/qazsvm/go-pkcs/errlist"
	"github.com/qazsvm/go-pkcs/oid"
)

// 4
type signedData struct {
	Version          int                        `asn1:"default:1"`
	DigestAlgorithms []pkix.AlgorithmIdentifier `asn1:"set"`
	EncapContentInfo ContentInfo
	Certificates     RawContent             `asn1:"optional,tag:0"`
	CRLS             []pkix.CertificateList `asn1:"optional,tag:1"`
	SignerInfos      []signerInfos          `asn1:"set"`
}
type RawContent struct {
	Raw asn1.RawContent
}
type signerInfos struct {
	Version            int
	SID                asn1.RawValue
	DigestAlgorithms   pkix.AlgorithmIdentifier
	SignedAttrs        []Attribute `asn1:"optional,tag:0"`
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          []byte
	UnsignedAttrs      []Attribute `asn1:"optional,tag:0"`
}

type issuerAndSerialNumber struct {
	Issuer       asn1.RawValue
	SerialNumber *big.Int
}

// use sha256
func SignData(data []byte, signer *rsa.PrivateKey, cert *x509.Certificate, caChain []*x509.Certificate, crls []pkix.CertificateList) ([]byte, error) {

	var (
		err                 error
		certsRaw            []byte
		sid                 issuerAndSerialNumber
		signedAttributes    []Attribute
		asnMarshalBuf       []byte
		signature           []byte
		asnData             []byte
		asnSignedAttributes []byte
		asnCerts            []byte
	)
	var (
		asnSignedData []byte
	)

	certsRaw = append(certsRaw, cert.Raw...)
	for _, v := range caChain {
		certsRaw = append(certsRaw, v.Raw...)
	}
	if asnCerts, err = asn1.Marshal(asn1.RawValue{Bytes: certsRaw, Class: 2, Tag: 0, IsCompound: true}); err != nil {
		return nil, err
	}

	sid = issuerAndSerialNumber{
		SerialNumber: new(big.Int).Set(cert.SerialNumber),
	}

	if _, err := asn1.Unmarshal(cert.RawIssuer, &sid.Issuer); err != nil {
		return nil, err
	}
	//sign attrs
	{
		/*
			SignedAttributes require at least two required attributes - type (Content Type) and data hash (Message Digest).
		*/
		// Content Type

		if asnMarshalBuf, err = asn1.Marshal(oid.PKCS7Data); err != nil {
			return nil, err
		}

		contentType := Attribute{
			AttrId: oid.ContentType,
			AttrValues: asn1.RawValue{
				Class:      0,
				Tag:        17,
				IsCompound: true,
				Bytes:      asnMarshalBuf,
			},
		}

		if asnMarshalBuf, err = asn1.Marshal(sha256.New().Sum(data)); err != nil {
			return nil, err
		}
		messageDigest := Attribute{
			AttrId: oid.MessageDigest,
			AttrValues: asn1.RawValue{
				Class:      0,
				Tag:        17,
				IsCompound: true,
				Bytes:      asnMarshalBuf,
			},
		}
		//SignedAttributes ::= SET SIZE (1..MAX) OF Attribute
		signedAttributes = append(signedAttributes, contentType)
		signedAttributes = append(signedAttributes, messageDigest)
		if len(contentType.AttrValues.Bytes) > len(messageDigest.AttrValues.Bytes) {
			signedAttributes[0], signedAttributes[1] = signedAttributes[1], signedAttributes[0]

		}
		// 1 Marshal
		if asnSignedAttributes, err = asn1.Marshal(signedAttributes[:]); err != nil {
			return nil, err
		}

		h := sha256.New()
		h.Write(asnSignedAttributes)
		sumSignedAttributes := h.Sum(nil)
		if signature, err = rsa.SignPKCS1v15(rand.Reader, signer, crypto.SHA256, sumSignedAttributes); err != nil {
			return nil, err
		}
	}
	sidAsn, err := asn1.Marshal(sid)
	if err != nil {
		return nil, err
	}
	//  signerInfos SignerInfos
	signerInfo := signerInfos{
		Version: 1,
		SID:     asn1.RawValue{FullBytes: sidAsn},
		DigestAlgorithms: pkix.AlgorithmIdentifier{
			Algorithm: oid.SHA256,
		},
		SignatureAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: oid.SHA256WithRSA,
		},
		Signature:   signature,
		SignedAttrs: signedAttributes,
	}

	// signedData . 2 Marshal
	if asnData, err = asn1.Marshal(asn1.RawValue{Class: 0, Tag: 4, IsCompound: false, Bytes: data}); err != nil {
		return nil, err
	}
	signedData := signedData{
		Version:          1,
		DigestAlgorithms: []pkix.AlgorithmIdentifier{signerInfo.DigestAlgorithms},
		EncapContentInfo: ContentInfo{
			ContentType: oid.PKCS7Data,
			Content: asn1.RawValue{
				Class:      2,
				Tag:        0,
				IsCompound: true,
				Bytes:      asnData,
			},
		},
		Certificates: RawContent{Raw: asnCerts},
		CRLS:         crls,
		SignerInfos:  []signerInfos{signerInfo},
	}
	// 3 . Marshal
	if asnSignedData, err = asn1.Marshal(signedData); err != nil {
		return nil, err
	}
	// content info
	result := ContentInfo{
		ContentType: oid.PKCS7SignedData,
		Content: asn1.RawValue{
			Class:      2,
			Tag:        0,
			IsCompound: true,
			Bytes:      asnSignedData,
		},
	}
	return asn1.Marshal(result)
}
func DecodeSignedData(p7der []byte) ([]*x509.Certificate, []*x509.Certificate, []pkix.CertificateList, error) {
	var (
		err          error
		signedData   signedData
		signers      []*x509.Certificate
		certificates []*x509.Certificate
		certsBuf     asn1.RawValue
	)
	if _, err = asn1.Unmarshal(p7der, &signedData); err != nil {
		return nil, nil, nil, err
	}
	if len(signedData.Certificates.Raw) > 0 {
		if _, err = asn1.Unmarshal(signedData.Certificates.Raw, &certsBuf); err != nil {
			return nil, nil, nil, err
		}
		if certificates, err = x509.ParseCertificates(certsBuf.Bytes); err != nil {
			return nil, nil, nil, err
		}
	}

	for _, signer := range signedData.SignerInfos {

		for _, cert := range certificates {
			if ok, err := isSigner(&signer, cert); err == nil {
				if ok {
					signers = append(signers, cert)
				}
			} else {
				return nil, nil, nil, err
			}
		}
	}

	return signers, certificates, signedData.CRLS, nil
}

// func VerifyCMS(data, p7DER []byte) error {
// 	var (
// 		err        error
// 		signedData signedData
// 	)
// 	if _, err = asn1.Unmarshal(data, &signedData); err != nil {
// 		log.Fatal("signed data: " + err.Error())
// 	}
// 	for _, v := range signedData.SignerInfos {

// 	}

// 	return nil
// }

func isSigner(signer *signerInfos, cert *x509.Certificate) (bool, error) {

	switch signer.Version {
	case 1:
		issuer := &issuerAndSerialNumber{}
		if _, err := asn1.Unmarshal(signer.SID.FullBytes, issuer); err != nil {
			return false, err
		}
		if cert.SerialNumber.Cmp(issuer.SerialNumber) == 0 {
			if bytes.Equal(cert.RawIssuer, issuer.Issuer.FullBytes) {
				return true, nil
			}
		}
	case 3:
		dataRaw := signer.SID.Bytes
		for _, v := range cert.Extensions {
			if oid.SubjectKeyIdentifier.Equal(v.Id) {
				if bytes.Equal(v.Value, dataRaw) {
					return true, nil
				}
			}
		}
	default:
		return false, errlist.ErrUnsupportedSid
	}
	return false, nil
}
