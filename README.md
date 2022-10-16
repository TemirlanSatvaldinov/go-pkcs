# go-pkcs
Package go-pkcs implements some of PKCS#12, PKCS#8, PKCS#7(Encrypted Data) .
### installation
    go get "github.com/qazsvm/go-pkcs"

### example 
    p12der, err := pkcs12.New(password, key, cert, chain, pkcs5.DefaultPBKDF2Iterations, pkcs5.DefaultPBKDF2SaltSize, x509.PEMCipherAES192, x509.PEMCipherAES192)
	key, cert, chain, err := pkcs12.Decode(p12der, password)
	
	p8der, err := pkcs8.New(key, password, pkcs5.DefaultPBKDF2Iterations, pkcs5.DefaultPBKDF2SaltSize, x509.PEMCipherAES192)
	key, err := pkcs8.Decode(p8der, password)

	p7der, err := pkcs7.EncryptData([]byte("HEllo, kitty"), password, 1000, 8, x509.PEMCipherAES256)
	p7, err := pkcs7.Decode(p7der, password)

	p7der, err := pkcs7.SignData(data, key, cert, []*x509.Certificate{issue}, []pkix.CertificateList{*crl})
	p7, err := pkcs7.Decode(p7der, nil)