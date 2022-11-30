package util

import (
	"encoding/binary"
	"unicode/utf16"
)

func BMPStringNULLTerminator(src string) []byte {
	step := 0
	u16 := utf16.Encode([]rune(src))
	dst := make([]byte, len(src)*2)
	for i := 0; i < len(u16); i++ {
		binary.BigEndian.PutUint16(dst[step:], uint16(u16[i]))
		step += 2
	}

	return append(dst, 0x00, 0x00)
}
func BMPString(src string) []byte {
	step := 0
	u16 := utf16.Encode([]rune(src))
	dst := make([]byte, len(src)*2)
	for i := 0; i < len(u16); i++ {
		binary.BigEndian.PutUint16(dst[step:], uint16(u16[i]))
		step += 2
	}

	return dst
}
