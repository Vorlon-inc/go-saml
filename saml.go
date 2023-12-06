package saml

import "errors"

// ServiceProviderSettings provides settings to configure server acting as a SAML Service Provider.
// Expect only one IDP per SP in this configuration. If you need to configure multiple IDPs for an SP
// then configure multiple instances of this module
type ServiceProviderSettings struct {
	PublicCertPath              string
	RawPublicCert               string
	PrivateKeyPath              string
	RawPrivateKey               string
	IDPSSOURL                   string
	IDPSSODescriptorURL         string
	IDPPublicCertPath           string
	RawIDPPublicCert            string
	AssertionConsumerServiceURL string
	SPSignRequest               bool

	hasInit       bool
	publicCert    string
	privateKey    string
	iDPPublicCert string
}

type IdentityProviderSettings struct {
}

func (s *ServiceProviderSettings) Init() error {
	if s.hasInit {
		return nil
	}
	s.hasInit = true

	var err error
	if s.SPSignRequest {
		if s.RawPublicCert != "" {
			s.publicCert = cleanCertificate(s.RawPublicCert)
		} else {
			s.publicCert, err = loadCertificate(s.PublicCertPath)
			if err != nil {
				return err
			}
		}

		if s.RawPrivateKey != "" {
			s.privateKey = cleanCertificate(s.RawPrivateKey)
		} else {
			s.privateKey, err = loadCertificate(s.PrivateKeyPath)
			if err != nil {
				return err
			}
		}
	}

	if s.RawIDPPublicCert != "" {
		s.iDPPublicCert = cleanCertificate(s.RawIDPPublicCert)
	} else {
		s.iDPPublicCert, err = loadCertificate(s.IDPPublicCertPath)
		if err != nil {
			return err
		}
	}

	return nil
}

func (s *ServiceProviderSettings) PublicCert() (string, error) {
	if !s.hasInit {
		return "", errors.New("must call ServiceProviderSettings.Init() first")
	}
	return s.publicCert, nil
}

func (s *ServiceProviderSettings) PrivateKey() (string, error) {
	if !s.hasInit {
		return "", errors.New("must call ServiceProviderSettings.Init() first")
	}
	return s.privateKey, nil
}

func (s *ServiceProviderSettings) IDPPublicCert() (string, error) {
	if !s.hasInit {
		return "", errors.New("must call ServiceProviderSettings.Init() first")
	}
	return s.iDPPublicCert, nil
}
