package main

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"io"
	"log"
	"os"
)

const pemLineLength = 76

var nl = []byte{'\n'}

func main() {
	log.Println("USigner 1.0.0")

	if len(os.Args) < 2 {
		log.Fatal("Usage: patch /path/to/Unity.Licensing.EntitlementResolver.dll")
	}
	fname := os.Args[1]

	log.Printf("Reading binary: %s\n", fname)
	resolver, err := os.ReadFile(fname)
	if err != nil {
		panic(err)
	}

	log.Println("Checking if previous backup exists")
	if _, err := os.Stat(fname + ".bak"); err == nil {
		panic("Backup already exists. Remove to proceed with patching")
	}

	log.Printf("Creating backup at: %s\n", fname+".bak")
	err = os.WriteFile(fname+".bak", resolver, 0644)
	if err != nil {
		panic(err)
	}

	log.Printf("Reading original cert")
	rawOriginal, err := os.ReadFile("keys/orig/Unity.Licensing.EntitlementResolver.Unity.cer")
	if err != nil {
		panic(err)
	}

	blockOriginal, _ := pem.Decode(rawOriginal)
	certOrig, _ := x509.ParseCertificate(blockOriginal.Bytes)

	log.Println("Reading patched cert")
	rawPatched, err := os.ReadFile("keys/mod/Unity.Licensing.EntitlementResolver.Unity.cer")
	if err != nil {
		panic(err)
	}

	blockPatched, _ := pem.Decode(rawPatched)
	certMod, _ := x509.ParseCertificate(blockPatched.Bytes)

	origLen := len(certOrig.Raw)
	patchedLen := len(certMod.Raw)

	if origLen != patchedLen {
		log.Fatalf("Certificate size mismatch! Original: %d, patched: %d\n", origLen, patchedLen)
	}

	var buf bytes.Buffer
	var bufMod bytes.Buffer

	var breaker lineBreaker
	breaker.out = &buf

	var breakerMod lineBreaker
	breakerMod.out = &bufMod

	b64 := base64.NewEncoder(base64.StdEncoding, &breaker)
	if _, err := b64.Write(certOrig.Raw); err != nil {
		panic(err)
	}
	_ = b64.Close()
	_ = breaker.Close()

	b64Mod := base64.NewEncoder(base64.StdEncoding, &breakerMod)
	if _, err := b64Mod.Write(certMod.Raw); err != nil {
		panic(err)
	}
	_ = b64Mod.Close()
	_ = breakerMod.Close()

	log.Println("Replacing original certificate with patched one")
	for {
		lineOrig, err := buf.ReadBytes('\n')
		lineMod, errMod := bufMod.ReadBytes('\n')

		if err != errMod {
			panic("Unexpected error condition")
		}

		if err == io.EOF || errMod == io.EOF {
			break
		}

		lineOrig = bytes.TrimSpace(lineOrig)
		lineMod = bytes.TrimSpace(lineMod)

		if bytes.Contains(resolver, lineMod) {
			log.Fatalf("Already patched, enjoy! Line found: %s\n", lineMod)
		}

		if !bytes.Contains(resolver, lineOrig) {
			log.Fatalf("Patch failed, certificate line not found: %s\n", lineOrig)
		}

		resolver = bytes.ReplaceAll(resolver, lineOrig, lineMod)
	}

	log.Println("Writing patched dll...")
	err = os.WriteFile(fname, resolver, 0644)
	if err != nil {
		panic(err)
	}

	log.Println("Success, enjoy!")
}

type lineBreaker struct {
	line [pemLineLength]byte
	used int
	out  io.Writer
}

func (l *lineBreaker) Write(b []byte) (n int, err error) {
	if l.used+len(b) < pemLineLength {
		copy(l.line[l.used:], b)
		l.used += len(b)
		return len(b), nil
	}

	n, err = l.out.Write(l.line[0:l.used])
	if err != nil {
		return
	}
	excess := pemLineLength - l.used
	l.used = 0

	n, err = l.out.Write(b[0:excess])
	if err != nil {
		return
	}

	n, err = l.out.Write(nl)
	if err != nil {
		return
	}

	return l.Write(b[excess:])
}

func (l *lineBreaker) Close() (err error) {
	if l.used > 0 {
		_, err = l.out.Write(l.line[0:l.used])
		if err != nil {
			return
		}
		_, err = l.out.Write(nl)
	}

	return
}
