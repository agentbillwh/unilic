package main

import (
	"crypto/x509"
	"encoding/pem"
	"github.com/moov-io/signedxml"
	"log"
	"os"
)

func main() {
	log.Println("USigner 1.0.0")
	log.Println("Reading private key...")

	rawKey, err := os.ReadFile("keys/mod/priv.key")
	if err != nil {
		log.Fatal(err)
	}

	blockKey, _ := pem.Decode(rawKey)
	key, err := x509.ParsePKCS1PrivateKey(blockKey.Bytes)
	if err != nil {
		panic(err)
	}

	log.Println("Reading license.xml...")
	lic, err := os.ReadFile("license.xml")
	if err != nil {
		panic(err)
	}

	log.Println("Creating XML signer instance...")
	signer, err := signedxml.NewSigner(string(lic))
	if err != nil {
		panic(err)
	}

	log.Println("Signing...")
	signer.SetReferenceIDAttribute("id")
	signedXML, err := signer.Sign(key)
	if err != nil {
		panic(err)
	}

	log.Println("Writing Unity_lic.ulf...")
	err = os.WriteFile("Unity_lic.ulf", []byte(signedXML), 0644)
	if err != nil {
		panic(err)
	}

	log.Println("Success, enjoy!")
}
