package main

import (
	"crypto/cipher"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"golang.org/x/crypto/blowfish"
	"log"
	"os"
)

func main() {
	// TimeStamp b64-encoded
	ts := ""
	// MachineId b64-encoded
	iv := ""

	tsb, _ := base64.StdEncoding.DecodeString(ts)
	ivb, _ := base64.StdEncoding.DecodeString(iv)

	raw, _ := os.ReadFile("keys/orig/Unity.Licensing.EntitlementResolver.Unity.cer")

	block, _ := pem.Decode(raw)
	originalCert, _ := x509.ParseCertificate(block.Bytes)

	var b64cert = make([]byte, base64.StdEncoding.EncodedLen(len(originalCert.Raw)))
	base64.StdEncoding.Encode(b64cert, originalCert.Raw)

	bfc, err := blowfish.NewCipher(b64cert[:16])
	if err != nil {
		log.Fatal(err)
	}

	decrypter := cipher.NewCFBDecrypter(bfc, ivb[:bfc.BlockSize()])
	decrypter.XORKeyStream(tsb, tsb)

	fmt.Println("raw ts: ", string(tsb))

	encrypter := cipher.NewCFBEncrypter(bfc, ivb[:bfc.BlockSize()])
	encrypter.XORKeyStream(tsb, tsb)

	fmt.Println("encoded ts: ", base64.StdEncoding.EncodeToString(tsb))
}
