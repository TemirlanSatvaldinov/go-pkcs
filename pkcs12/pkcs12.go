package pkcs12

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"encoding/asn1"
	"errors"

	"github.com/qazsvm/go-pkcs/errlist"
	"github.com/qazsvm/go-pkcs/oid"
	"github.com/qazsvm/go-pkcs/pkcs5"
	"github.com/qazsvm/go-pkcs/pkcs7"
	"github.com/qazsvm/go-pkcs/pkcs8"
	"github.com/qazsvm/go-pkcs/util"
)

// pkcs12
type macData struct {
	Mac        pkcs7.DigestData
	MacSalt    []byte
	Iterations int `asn1:"optional,default:1"`
}

type safeBag struct {
	BagId         asn1.ObjectIdentifier
	BagValue      asn1.RawValue     `asn1:"tag:0,explicit"`
	BagAttributes []pkcs7.Attribute `asn1:"set,optional"`
}

type p12 struct {
	Version           int
	AuthenticatedSafe pkcs7.ContentInfo
	MacData           macData `asn1:"optional"`
}

func New(password []byte, pemKey interface{}, cert *x509.Certificate, caChain []*x509.Certificate, friendlyNameSTR string, PBKDF2Iterations, PBKDF2SaltSize int, keypbe x509.PEMCipher, certpbe x509.PEMCipher) ([]byte, error) {
	if len(password) < 6 {
		return nil, errlist.ErrPasswordLen
	}
	if pemKey == nil && cert == nil {
		return nil, errlist.ErrEmptyKeyAndCert
	}
	macPassword := util.BMPStringNULLTerminator((string(password)))
	var (
		localKeyID, friendlyName pkcs7.Attribute
		contentInfoArray         []byte
	)

	if cert != nil {
		/*
		 The same identifier (alias) would be assigned to the corresponding certificates
		*/
		identifier := sha1.Sum(cert.Raw)
		if identifierOctet, err := asn1.Marshal(identifier[:]); err == nil {
			localKeyID = pkcs7.Attribute{
				AttrId: oid.LocalKeyID,
				AttrValues: asn1.RawValue{
					Class:      0,
					Tag:        17,
					IsCompound: true,
					Bytes:      identifierOctet,
				},
			}
		} else {
			return nil, err
		}

		if bmpAsn, err := asn1.Marshal(asn1.RawValue{Class: 0, Tag: 30, Bytes: util.BMPString(friendlyNameSTR)}); err == nil {
			friendlyName = pkcs7.Attribute{
				AttrId: oid.FriendlyName,
				AttrValues: asn1.RawValue{
					Class:      0,
					Tag:        17,
					IsCompound: true,
					Bytes:      bmpAsn,
				},
			}
		} else {
			return nil, err
		}

		var certs []safeBag
		certStruct := pkcs7.X509Certificate{
			Id:   oid.X509Certificate,
			Data: cert.Raw,
		}
		certMarshalled, err := asn1.Marshal(certStruct)
		if err != nil {
			return nil, err
		}
		certBag := safeBag{
			BagId: oid.CertBag,
			BagValue: asn1.RawValue{
				Class:      2,
				Tag:        0,
				IsCompound: true,
				Bytes:      certMarshalled,
			},
			BagAttributes: []pkcs7.Attribute{localKeyID, friendlyName},
		}

		certs = append(certs, certBag)
		for _, ca := range caChain {
			caStruct := pkcs7.X509Certificate{
				Id:   oid.X509Certificate,
				Data: ca.Raw,
			}
			caMarshalled, err := asn1.Marshal(caStruct)
			if err != nil {
				return nil, err
			}
			certBag := safeBag{
				BagId: oid.CertBag,
				BagValue: asn1.RawValue{
					Class:      2,
					Tag:        0,
					IsCompound: true,
					Bytes:      caMarshalled,
				},
			}

			certs = append(certs, certBag)
		}
		certBagMarshalled, err := asn1.Marshal(certs[:])
		if err != nil {
			return nil, err
		}
		p7, err := pkcs7.EncryptData(certBagMarshalled, password, PBKDF2Iterations, PBKDF2SaltSize, certpbe)
		if err != nil {
			return nil, err
		}
		contentInfoArray = append(contentInfoArray, p7...)

	}
	if pemKey != nil {
		p8key, err := pkcs8.New(pemKey, password, PBKDF2Iterations, PBKDF2SaltSize, keypbe)
		if err != nil {
			return nil, err
		}
		ShroudedKeyBag := safeBag{
			BagId: oid.PKCS8ShroundedKeyBag,
			BagValue: asn1.RawValue{
				Class:      2,
				Tag:        0,
				IsCompound: true,
				Bytes:      p8key,
			},
		}
		if cert != nil {
			ShroudedKeyBag.BagAttributes = []pkcs7.Attribute{localKeyID, friendlyName}
		}
		var ShroudedKeyBagArray [1]safeBag
		ShroudedKeyBagArray[0] = ShroudedKeyBag

		ShroudedKeyBagSequence, err := asn1.Marshal(ShroudedKeyBagArray[:])
		if err != nil {
			return nil, err
		}
		ShroudedKeyBagOctet, err := asn1.Marshal(ShroudedKeyBagSequence)
		if err != nil {
			return nil, err
		}

		pkcs8ContentInfo := pkcs7.ContentInfo{
			ContentType: oid.PKCS7Data,
			Content: asn1.RawValue{
				Class:      2,
				Tag:        0,
				IsCompound: true,
				Bytes:      ShroudedKeyBagOctet,
			},
		}
		p8, err := asn1.Marshal(pkcs8ContentInfo)
		if err != nil {
			return nil, err
		}
		contentInfoArray = append(contentInfoArray, p8...)
	}

	authenticatedSafeArray := asn1.RawValue{
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      contentInfoArray,
	}

	authenticatedSafeSequence, err := asn1.Marshal(authenticatedSafeArray)
	if err != nil {
		return nil, err
	}
	authenticatedSafeArrOctet, err := asn1.Marshal(authenticatedSafeSequence)
	if err != nil {
		return nil, err
	}
	// mac
	mac, err := genMac(macPassword, authenticatedSafeSequence)
	if err != nil {
		return nil, err
	}
	// pcks12
	pkcs12 := p12{
		Version: 3,
		AuthenticatedSafe: pkcs7.ContentInfo{
			ContentType: oid.PKCS7Data,
			Content: asn1.RawValue{
				Class:      2,
				Tag:        0,
				IsCompound: true,
				Bytes:      authenticatedSafeArrOctet,
			},
		},
		MacData: *mac,
	}

	return asn1.Marshal(pkcs12)
}

func genMac(password, data []byte) (*macData, error) {
	var macID byte = 3
	hasFunc, hashSum, err := pkcs5.HashFnFromOID(oid.SHA256)
	if err != nil {
		return nil, err
	}
	mac := new(macData)
	mac.Iterations = 1000
	mac.Mac.Id.Algorithm = oid.SHA256
	mac.MacSalt = make([]byte, hasFunc().Size())
	if _, err := rand.Read(mac.MacSalt); err != nil {
		return nil, err
	}

	dkey := pkcs12kdf(password, mac.MacSalt, macID, mac.Iterations, hasFunc().Size(), hasFunc().Size(), hasFunc().BlockSize(), hashSum)
	hmac := hmac.New(hasFunc, dkey)
	hmac.Write(data)
	mac.Mac.Digest = hmac.Sum(nil)
	return mac, nil
}
func Decode(data, password []byte) (interface{}, *x509.Certificate, []*x509.Certificate, error) {

	var (
		keysBag  []safeBag
		certsBag []safeBag
		err      error
		buf      []byte
		key      interface{}
		cert     *x509.Certificate
		chain    []*x509.Certificate
	)
	macPassword := util.BMPStringNULLTerminator((string(password)))

	pkcs12 := new(p12)
	if _, err := asn1.Unmarshal(data, pkcs12); err != nil {
		return nil, nil, nil, errors.New("error: canot unmarshal pkcs12 data : " + err.Error())
	}
	if pkcs12.Version != 3 {
		return nil, nil, nil, errlist.ErrPKCS12Version
	}
	if _, err := asn1.Unmarshal(pkcs12.AuthenticatedSafe.Content.Bytes, &pkcs12.AuthenticatedSafe.Content); err != nil {
		return nil, nil, nil, err
	}
	if pkcs12.MacData.Mac.Id.Algorithm == nil {
		return nil, nil, nil, errors.New("error: cannot verify mac ")
	}
	mac := pkcs12.MacData
	if err := verifyMac(macPassword, pkcs12.AuthenticatedSafe.Content.Bytes, mac.MacSalt, mac.Mac.Digest, mac.Mac.Id.Algorithm, mac.Iterations); err != nil {
		return nil, nil, nil, errors.New("verify mac : " + err.Error())
	}
	var authenticatedSafe []pkcs7.ContentInfo
	if _, err := asn1.Unmarshal(pkcs12.AuthenticatedSafe.Content.Bytes, &authenticatedSafe); err != nil {
		return nil, nil, nil, err
	}

	for _, v := range authenticatedSafe {

		switch {
		case v.ContentType.Equal(oid.PKCS7EncryptedData):
			if buf, err = pkcs7.DecodeEncryptedData(v.Content.Bytes, password); err != nil {
				return nil, nil, nil, err
			}
			if _, err := asn1.Unmarshal(buf, &certsBag); err != nil {
				return nil, nil, nil, err
			}
		case v.ContentType.Equal(oid.PKCS7Data):
			var data []byte
			if _, err := asn1.Unmarshal(v.Content.Bytes, &data); err != nil {
				return nil, nil, nil, err
			}
			if _, err := asn1.Unmarshal(data, &keysBag); err != nil {
				return nil, nil, nil, err
			}
		}

		// TODO: add signed Data
	}

	bags := append(certsBag, keysBag...)
	for _, bag := range bags {
		switch {
		case bag.BagId.Equal(oid.CertBag):
			certRaw := &pkcs7.X509Certificate{}
			_, err := asn1.Unmarshal(bag.BagValue.Bytes, certRaw)
			if err != nil {
				return nil, nil, nil, err
			}
			certs, err := x509.ParseCertificates(certRaw.Data)
			if err != nil {
				return nil, nil, nil, err
			}
			// cert or chain
			if bag.BagAttributes != nil {
				cert = certs[0]
			} else {
				chain = append(chain, certs[0])
			}
		case bag.BagId.Equal(oid.PKCS8ShroundedKeyBag):
			if key, err = pkcs8.Decode(bag.BagValue.Bytes, password); err != nil {
				return nil, nil, nil, err
			}
		}

	}
	return key, cert, chain, nil
}

func verifyMac(password, message, salt, digest []byte, asnOID asn1.ObjectIdentifier, iter int) error {
	hasFunc, hashSum, err := pkcs5.HashFnFromOID(asnOID)
	if err != nil {
		return err
	}
	dkey := pkcs12kdf(password, salt, 3, iter, hasFunc().Size(), hasFunc().Size(), hasFunc().BlockSize(), hashSum)
	mac := hmac.New(hasFunc, dkey)
	mac.Write(message)
	messageMAC := mac.Sum(nil)

	if !hmac.Equal(digest, messageMAC) {
		return errlist.ErrIncorrectPassword
	}
	return nil
}
