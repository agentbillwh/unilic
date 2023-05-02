[![Moov Banner Logo](https://user-images.githubusercontent.com/20115216/104214617-885b3c80-53ec-11eb-8ce0-9fc745fb5bfc.png)](https://github.com/moov-io)

## moov-io/signedxml

[![GoDoc](https://godoc.org/github.com/moov-io/signedxml?status.svg)](https://godoc.org/github.com/moov-io/signedxml)
[![Build Status](https://github.com/moov-io/signedxml/workflows/Go/badge.svg)](https://github.com/moov-io/signedxml/actions)
[![Coverage Status](https://codecov.io/gh/moov-io/signedxml/branch/master/graph/badge.svg)](https://codecov.io/gh/moov-io/signedxml)
[![Go Report Card](https://goreportcard.com/badge/github.com/moov-io/signedxml)](https://goreportcard.com/report/github.com/moov-io/signedxml)
[![Repo Size](https://img.shields.io/github/languages/code-size/moov-io/signedxml?label=project%20size)](https://github.com/moov-io/signedxml)
[![MIT  License](https://img.shields.io/badge/license-MIT-blue.svg)](https://raw.githubusercontent.com/moov-io/signedxml/master/LICENSE.md)
[![Slack Channel](https://slack.moov.io/badge.svg?bg=e01563&fgColor=fffff)](https://slack.moov.io/)
[![Twitter](https://img.shields.io/twitter/follow/moov?style=social)](https://twitter.com/moov?lang=en)

The signedxml package transforms and validates signed xml documents. The main use case is to support Single Sign On protocols like SAML and WS-Federation.

Other packages that provide similar functionality rely on C libraries, which makes them difficult to run across platforms without significant configuration.  `signedxml` is written in pure go, and can be easily used on any platform. This package was originally created by [Matt Smith](https://github.com/ma314smith) and is in use at Moov Financial.

### Install

`go get github.com/moov-io/signedxml`

### Included Algorithms

- Hashes
  - http://www.w3.org/2001/04/xmldsig-more#md5
  - http://www.w3.org/2000/09/xmldsig#sha1
  - http://www.w3.org/2001/04/xmldsig-more#sha224
  - http://www.w3.org/2001/04/xmlenc#sha256
  - http://www.w3.org/2001/04/xmldsig-more#sha384
  - http://www.w3.org/2001/04/xmlenc#sha512
  - http://www.w3.org/2001/04/xmlenc#ripemd160


- Signatures
  - http://www.w3.org/2001/04/xmldsig-more#rsa-md2
  - http://www.w3.org/2001/04/xmldsig-more#rsa-md5
  - http://www.w3.org/2000/09/xmldsig#rsa-sha1
  - http://www.w3.org/2001/04/xmldsig-more#rsa-sha256
  - http://www.w3.org/2001/04/xmldsig-more#rsa-sha384
  - http://www.w3.org/2001/04/xmldsig-more#rsa-sha512
  - http://www.w3.org/2000/09/xmldsig#dsa-sha1
  - http://www.w3.org/2000/09/xmldsig#dsa-sha256
  - http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1
  - http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256
  - http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384
  - http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512


- Canonicalization Methods/Transforms
  - http://www.w3.org/2000/09/xmldsig#enveloped-signature
  - http://www.w3.org/2001/10/xml-exc-c14n#
  - http://www.w3.org/2001/10/xml-exc-c14n#WithComments

### Examples

#### Validating signed XML
If your signed xml contains the signature and certificate, then you can just pass in the xml and call `ValidateReferences()`.
```go
validator, err := signedxml.NewValidator(`<YourXMLString></YourXMLString>`)
xml, err = validator.ValidateReferences()
```
`ValidateReferences()` verifies the DigestValue and SignatureValue in the xml document, and returns the signed payload(s). If the error value is `nil`, then the signed xml is valid.

The x509.Certificate that was successfully used to validate the xml will be available by calling:
```go
validator.SigningCert()
```
You can then verify that you trust the certificate. You can optionally supply your trusted certificates ahead of time by assigning them to the `Certificates` property of the `Validator` object, which is an x509.Certificate array.

#### Using an external Signature
If you need to specify an external Signature, you can use the `SetSignature()` function to assign it:
```go
validator.SetSignature(<`Signature></Signature>`)
```

#### Generating signed XML
It is expected that your XML contains the Signature element with all the parameters set (except DigestValue and SignatureValue).
```go
signer, err := signedxml.NewSigner(`<YourXMLString></YourXMLString`)
signedXML, err := signer.Sign(`*rsa.PrivateKey object`)
```
`Sign()` will generate the DigestValue and SignatureValue, populate it in the XML, and return the signed XML string.

#### Implementing custom transforms
Additional Transform algorithms can be included by adding to the CanonicalizationAlgorithms map.  This interface will need to be implemented:
```go
type CanonicalizationAlgorithm interface {
	Process(inputXML string, transformXML string) (outputXML string, err error)
}
```
Simple Example:
```go
type NoChangeCanonicalization struct{}

func (n NoChangeCanonicalization) Process(inputXML string,
	transformXML string) (outputXML string, err error) {
	return inputXML, nil
}

signedxml.CanonicalizationAlgorithms["http://myTranform"] = NoChangeCanonicalization{}
```

See `envelopedsignature.go` and `exclusivecanonicalization.go` for examples of actual implementations.

### Using a custom reference ID attribute
It is possible to set a custom reference ID attribute for both the signer and the validator. The default value is `"ID"`

Signer example:
```go
signer.SetReferenceIDAttribute("customId")
```

Validator example:
```go
validator.SetReferenceIDAttribute("customId")
```

## Getting help

 channel | info
 ------- | -------
Twitter [@moov](https://twitter.com/moov)	| You can follow Moov.io's Twitter feed to get updates on our project(s). You can also tweet us questions or just share blogs or stories.
[GitHub Issue](https://github.com/moov-io/signedxml/issues/new) | If you are able to reproduce a problem please open a GitHub Issue under the specific project that caused the error.
[moov-io slack](https://slack.moov.io/) | Join our slack channel to have an interactive discussion about the development of the project.

## Contributions

Contributions are welcome. Just fork the repo and send a pull request.

## Releated Projects

- [Moov RTP20022](http://github.com/moov-io/rtp20022) implements ISO20022 messages in Go for Real Time Payments (RTP)
