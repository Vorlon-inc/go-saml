package saml

import (
	"encoding/xml"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRequest(t *testing.T) {
	assert := assert.New(t)
	cert, err := loadCertificate("./default.crt")
	assert.NoError(err)

	// Construct an AuthnRequest
	authRequest := NewAuthnRequest()
	authRequest.Signature.KeyInfo.X509Data.X509Certificate.Cert = cert

	b, err := xml.MarshalIndent(authRequest, "", "    ")
	assert.NoError(err)
	xmlAuthnRequest := string(b)

	signedXml, err := SignRequest(xmlAuthnRequest, "./default.key")
	assert.NoError(err)
	assert.NotEmpty(signedXml)

	err = VerifyRequestSignature(signedXml, "./default.crt")
	assert.NoError(err)
}

func TestResponse(t *testing.T) {
	assert := assert.New(t)
	cert, err := loadCertificate("./default.crt")
	assert.NoError(err)

	// Construct an AuthnRequest
	response := NewSignedResponse()
	response.Signature.KeyInfo.X509Data.X509Certificate.Cert = cert

	b, err := xml.MarshalIndent(response, "", "    ")
	assert.NoError(err)
	xmlResponse := string(b)

	signedXml, err := SignResponse(xmlResponse, "./default.key")
	assert.NoError(err)
	assert.NotEmpty(signedXml)

	err = VerifyRequestSignature(signedXml, "./default.crt")
	assert.NoError(err)
}
