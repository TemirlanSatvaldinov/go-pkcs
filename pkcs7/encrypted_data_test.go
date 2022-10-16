package pkcs7

import (
	"crypto/x509"
	"testing"

	"github.com/qazsvm/go-pkcs/pkcs5"
)

func TestEncryptData(t *testing.T) {
	data, psw := []byte("hello kitty!"), []byte("123456")
	p7der, err := EncryptData(data, psw, pkcs5.DefaultPBKDF2Iterations, pkcs5.DefaultPBKDF2SaltSize, x509.PEMCipherAES128)
	if err != nil {
		t.Fatal(err)
	}
	p7, err := Decode(p7der, psw)
	if err != nil {
		t.Fatal(err)
	}
	if len(p7.DecryptedData) != len(data) {
		t.Fatalf("expected len = %v, got = %v", len(data), len(p7.DecryptedData))
	}
}
