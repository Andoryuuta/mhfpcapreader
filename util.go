package main

import (
	"bytes"
	"encoding/hex"
	"errors"

	"github.com/Andoryuuta/Erupe/network"
	"github.com/Andoryuuta/Erupe/network/crypto"
)

func bruteforceDecrypt(cph *network.CryptPacketHeader, data []byte) ([]byte, error) {
	for i := 0; i < 256; i++ {
		overrideKey := byte(i)
		outputData, _, check0, check1, check2 := crypto.Decrypt(data, 0, &overrideKey)
		if cph.Check0 == check0 && cph.Check1 == check1 && cph.Check2 == check2 {
			return outputData, nil
		}
	}

	return nil, errors.New("Couldn't decrypt packet")
}

// Helper function to make a spaced hex string.
func makeSpacedHex(data []byte) string {
	s := hex.EncodeToString(data)

	var buffer bytes.Buffer
	var strEnd = len(s) - 1
	for i, rune := range s {
		buffer.WriteRune(rune)
		if i%2 == 1 && i != strEnd {
			buffer.WriteRune(' ')
		}
	}
	return buffer.String()
}
