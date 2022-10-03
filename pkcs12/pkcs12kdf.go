package pkcs12

import (
	"bytes"
	"math/big"
)

/*
https://cs.opensource.google/go/x/crypto/+/eccd6366:pkcs12/pbkdf.go
*/
func pkcs12kdf(password, salt []byte, macID byte, iter, keySize, sumSize, blockSize int, hashFunc func([]byte) []byte) []byte {

	one := big.NewInt(1)
	var (
		S []byte
		D []byte
		P []byte
	)
	for i := 0; i < blockSize; i++ {
		D = append(D, macID)
	}
	if salt != nil {
		length := blockSize * ((len(salt) + blockSize - 1) / blockSize)
		S = bytes.Repeat(salt, (length+len(salt)-1)/len(salt))[:length]
	}

	if password != nil {
		length := blockSize * ((len(password) + blockSize - 1) / blockSize)
		P = bytes.Repeat(password, (length+len(password)-1)/len(password))[:length]
	}
	I := append(S, P...)
	c := (keySize + sumSize - 1) / sumSize
	A := make([]byte, c*sumSize)
	var IjBuf []byte
	for i := 0; i < c; i++ {

		Ai := hashFunc(append(D, I...))
		for j := 1; j < iter; j++ {
			Ai = hashFunc(Ai)
		}
		copy(A[i*sumSize:], Ai)
		if i < c-1 {
			var B []byte
			for len(B) < blockSize {
				B = append(B, Ai...)
			}
			B = B[:blockSize]
			{
				Bbi := new(big.Int).SetBytes(B)
				Ij := new(big.Int)

				for j := 0; j < len(I)/blockSize; j++ {
					Ij.SetBytes(I[j*blockSize : (j+1)*blockSize])
					Ij.Add(Ij, Bbi)
					Ij.Add(Ij, one)
					Ijb := Ij.Bytes()
					if len(Ijb) > blockSize {
						Ijb = Ijb[len(Ijb)-blockSize:]
					}
					if len(Ijb) < blockSize {
						if IjBuf == nil {
							IjBuf = make([]byte, blockSize)
						}
						bytesShort := blockSize - len(Ijb)
						for i := 0; i < bytesShort; i++ {
							IjBuf[i] = 0
						}
						copy(IjBuf[bytesShort:], Ijb)
						Ijb = IjBuf
					}
					copy(I[j*blockSize:(j+1)*blockSize], Ijb)
				}
			}
		}
	}

	return A[:keySize]

}
