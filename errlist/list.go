package errlist

import "errors"

var (
	ErrUnknownCipher     = errors.New("error: unknown cipher")
	ErrUnknownOID        = errors.New("error: unknown OID")
	ErrPasswordLen       = errors.New("password must be at least 6 characters")
	ErrIncorrectPassword = errors.New("invalid password ?")
	ErrEmptyKeyAndCert   = errors.New("pkcs12 must contain keys or certificate")
	ErrPKCS12Version     = errors.New("error: support only pkcs12 version 3 ")
)
