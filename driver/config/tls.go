package config

import (
	"crypto/tls"
	"strings"

	"github.com/hashicorp/go-secure-stdlib/tlsutil"
	"github.com/pkg/errors"

	"github.com/ory/x/tlsx"
)

const (
	KeySuffixTLSEnabled              = "tls.enabled"
	KeySuffixTLSAllowTerminationFrom = "tls.allow_termination_from"
	KeySuffixTLSCertString           = "tls.cert.base64"
	KeySuffixTLSKeyString            = "tls.key.base64"
	KeySuffixTLSCertPath             = "tls.cert.path"
	KeySuffixTLSKeyPath              = "tls.key.path"

	KeyTLSAllowTerminationFrom = "serve." + KeySuffixTLSAllowTerminationFrom
	KeyTLSCertString           = "serve." + KeySuffixTLSCertString
	KeyTLSKeyString            = "serve." + KeySuffixTLSKeyString
	KeyTLSCertPath             = "serve." + KeySuffixTLSCertPath
	KeyTLSKeyPath              = "serve." + KeySuffixTLSKeyPath

	KeyClientTLSInsecureSkipVerify = "client.tls.insecure_skip_verify"
	KeyClientTLSCipherSuites       = "client.tls.cipher_suites"
	KeyClientTLSMinVer             = "client.tls.min_version"
	KeyClientTLSMaxVer             = "client.tls.max_version"
)

type TLSConfig interface {
	Enabled() bool
	AllowTerminationFrom() []string
	Certificate() ([]tls.Certificate, error)
}

func (p *Provider) TLS(iface ServeInterface) TLSConfig {
	enabled := true
	if p.forcedHTTP() {
		enabled = false
	} else if iface == AdminInterface {
		// Support `tls.enabled` for admin interface only
		enabled = p.p.Bool(iface.Key(KeySuffixTLSEnabled))
	}

	return &tlsConfig{
		enabled:              enabled,
		allowTerminationFrom: p.p.StringsF(iface.Key(KeySuffixTLSAllowTerminationFrom), p.p.Strings(KeyTLSAllowTerminationFrom)),

		certString: p.p.StringF(iface.Key(KeySuffixTLSCertString), p.p.String(KeyTLSCertString)),
		keyString:  p.p.StringF(iface.Key(KeySuffixTLSKeyString), p.p.String(KeyTLSKeyString)),
		certPath:   p.p.StringF(iface.Key(KeySuffixTLSCertPath), p.p.String(KeyTLSCertPath)),
		keyPath:    p.p.StringF(iface.Key(KeySuffixTLSKeyPath), p.p.String(KeyTLSKeyPath)),
	}
}

func (p *Provider) TLSClientConfig() (*tls.Config, error) {
	tlsClientConfig := new(tls.Config)
	tlsClientConfig.InsecureSkipVerify = p.p.BoolF(KeyClientTLSInsecureSkipVerify, false)

	if p.p.Exists(KeyClientTLSCipherSuites) {
		keyCipherSuites := p.p.Strings(KeyClientTLSCipherSuites)
		cipherSuites, err := tlsutil.ParseCiphers(strings.Join(keyCipherSuites[:], ","))
		if err != nil {
			return nil, errors.WithMessage(err, "Unable to setup client TLS configuration")
		}
		tlsClientConfig.CipherSuites = cipherSuites
	}

	if p.p.Exists(KeyClientTLSMinVer) {
		keyMinVer := p.p.String(KeyClientTLSMinVer)
		if tlsMinVer, found := tlsutil.TLSLookup[keyMinVer]; !found {
			return nil, errors.Errorf("Unable to setup client TLS configuration. Invalid minimum TLS version: %s", keyMinVer)
		} else {
			tlsClientConfig.MinVersion = tlsMinVer
		}
	}

	if p.p.Exists(KeyClientTLSMaxVer) {
		keyMaxVer := p.p.String(KeyClientTLSMaxVer)
		if tlsMaxVer, found := tlsutil.TLSLookup[keyMaxVer]; !found {
			return nil, errors.Errorf("Unable to setup client TLS configuration. Invalid maximum TLS version: %s", keyMaxVer)
		} else {
			tlsClientConfig.MaxVersion = tlsMaxVer
		}
	}

	return tlsClientConfig, nil
}

type tlsConfig struct {
	enabled              bool
	allowTerminationFrom []string

	certString string
	keyString  string
	certPath   string
	keyPath    string
}

func (c *tlsConfig) Enabled() bool {
	return c.enabled
}

func (c *tlsConfig) AllowTerminationFrom() []string {
	return c.allowTerminationFrom
}

func (c *tlsConfig) Certificate() ([]tls.Certificate, error) {
	return tlsx.Certificate(c.certString, c.keyString, c.certPath, c.keyPath)
}

func (p *Provider) forcedHTTP() bool {
	return p.p.Bool("dangerous-force-http")
}
