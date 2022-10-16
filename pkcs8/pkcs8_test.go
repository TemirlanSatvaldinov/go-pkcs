package pkcs8

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"testing"

	"github.com/qazsvm/go-pkcs/pkcs5"
)

func TestNew(t *testing.T) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	data, psw := []byte("test pkcs8 fn"), []byte("123456")
	hData := sha1.Sum(data)
	signed, _ := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA1, hData[:])

	//
	encryptedKey, _ := New(privateKey, psw, pkcs5.DefaultPBKDF2Iterations, pkcs5.DefaultPBKDF2SaltSize, x509.PEMCipherAES128)
	decryptedKey, _ := Decode(encryptedKey, psw)

	pKey := decryptedKey.(*rsa.PrivateKey)

	if err := rsa.VerifyPKCS1v15(&pKey.PublicKey, crypto.SHA1, hData[:], signed); err != nil {
		t.Fatalf("verification failed: %s", err.Error())
	}
}
