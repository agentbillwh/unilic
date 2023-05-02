package signedxml

import (
	"errors"

	"github.com/beevik/etree"
)

// EnvelopedSignature implements the CanonicalizationAlgorithm
// interface and is used for processing the
// http://www.w3.org/2000/09/xmldsig#enveloped-signature transform
// algorithm
type EnvelopedSignature struct{}

// see CanonicalizationAlgorithm.ProcessElement
func (e EnvelopedSignature) ProcessElement(inputXML *etree.Element, transformXML string) (outputXML string, err error) {
	transformedXML, err := e.processElement(inputXML.Copy(), transformXML)
	if err != nil {
		return "", err
	}

	doc := etree.NewDocument()
	doc.SetRoot(transformedXML)
	docString, err := doc.WriteToString()
	if err != nil {
		return "", err
	}
	//logger.Println(docString)
	return docString, nil
}

// see CanonicalizationAlgorithm.ProcessDocument
func (e EnvelopedSignature) ProcessDocument(doc *etree.Document,
	transformXML string) (outputXML string, err error) {

	transformedRoot, err := e.processElement(doc.Root().Copy(), transformXML)
	if err != nil {
		return "", err
	}
	doc.SetRoot(transformedRoot)
	docString, err := doc.WriteToString()
	if err != nil {
		return "", err
	}
	//logger.Println(docString)
	return docString, nil
}

// see CanonicalizationAlgorithm.Process
func (e EnvelopedSignature) Process(inputXML string, transformXML string) (outputXML string, err error) {
	doc := etree.NewDocument()
	err = doc.ReadFromString(inputXML)
	if err != nil {
		return "", err
	}
	return e.ProcessDocument(doc, transformXML)
}

func (e EnvelopedSignature) processElement(inputXML *etree.Element, transformXML string) (outputXML *etree.Element, err error) {
	sig := inputXML.FindElement(".//Signature")
	if sig == nil {
		return nil, errors.New("signedxml: unable to find Signature node")
	}

	sigParent := sig.Parent()
	elem := sigParent.RemoveChild(sig)
	if elem == nil {
		return nil, errors.New("signedxml: unable to remove Signature element")
	}

	return inputXML, nil
}
