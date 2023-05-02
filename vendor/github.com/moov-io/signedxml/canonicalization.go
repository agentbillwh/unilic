package signedxml

import (
	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

type c14N10RecCanonicalizer struct {
	WithComments bool
}

func (c *c14N10RecCanonicalizer) ProcessElement(inputXML *etree.Element, transformXML string) (outputXML string, err error) {
	transformedXML, err := c.processElement(inputXML, transformXML)
	if err != nil {
		return "", err
	}
	return transformedXML, nil
}

func (c *c14N10RecCanonicalizer) ProcessDocument(doc *etree.Document, transformXML string) (outputXML string, err error) {

	transformedXML, err := c.processElement(doc.Root(), transformXML)
	if err != nil {
		return "", err
	}
	return transformedXML, nil
}

func (c c14N10RecCanonicalizer) Process(inputXML string, transformXML string) (outputXML string, err error) {
	doc := etree.NewDocument()
	err = doc.ReadFromString(inputXML)
	if err != nil {
		return "", err
	}
	return c.ProcessDocument(doc, transformXML)
}

func (c *c14N10RecCanonicalizer) processElement(inputXML *etree.Element, transformXML string) (outputXML string, err error) {
	var canon dsig.Canonicalizer
	if c.WithComments {
		canon = dsig.MakeC14N10WithCommentsCanonicalizer()
	} else {
		canon = dsig.MakeC14N10RecCanonicalizer()
	}

	out, err := canon.Canonicalize(inputXML)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

type c14N11Canonicalizer struct {
	WithComments bool
}

func (c *c14N11Canonicalizer) ProcessElement(inputXML *etree.Element, transformXML string) (outputXML string, err error) {
	transformedXML, err := c.processElement(inputXML, transformXML)
	if err != nil {
		return "", err
	}
	return transformedXML, nil
}

func (c *c14N11Canonicalizer) ProcessDocument(doc *etree.Document, transformXML string) (outputXML string, err error) {

	transformedXML, err := c.processElement(doc.Root(), transformXML)
	if err != nil {
		return "", err
	}
	return transformedXML, nil
}

func (c c14N11Canonicalizer) Process(inputXML string, transformXML string) (outputXML string, err error) {
	doc := etree.NewDocument()
	err = doc.ReadFromString(inputXML)
	if err != nil {
		return "", err
	}
	return c.ProcessDocument(doc, transformXML)
}

func (c *c14N11Canonicalizer) processElement(inputXML *etree.Element, transformXML string) (outputXML string, err error) {
	var canon dsig.Canonicalizer
	if c.WithComments {
		canon = dsig.MakeC14N11WithCommentsCanonicalizer()
	} else {
		canon = dsig.MakeC14N11Canonicalizer()
	}

	out, err := canon.Canonicalize(inputXML)
	if err != nil {
		return "", err
	}
	return string(out), nil
}
