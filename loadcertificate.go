package saml

import (
	"os"
	"regexp"
	"strings"
)

// loadCertificate from file system
func loadCertificate(certPath string) (string, error) {
	b, err := os.ReadFile(certPath)
	if err != nil {
		return "", err
	}
	cert := string(b)

	return cleanCertificate(cert), nil
}

// cleanCertificate clean given certificate
func cleanCertificate(cert string) string {
	re := regexp.MustCompile("---(.*)CERTIFICATE(.*)---")
	cert = re.ReplaceAllString(cert, "")
	cert = strings.Trim(cert, " \n")
	cert = strings.Replace(cert, "\n", "", -1)

	return cert
}
