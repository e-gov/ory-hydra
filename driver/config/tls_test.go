package config

import (
	"context"
	"crypto/tls"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/ory/x/configx"
	"github.com/ory/x/logrusx"
)

func TestTLSClientConfig_CipherSuite(t *testing.T) {
	l := logrusx.New("", "")
	c := MustNew(context.TODO(), l, configx.WithValue("client.tls.cipher_suites", []string{"TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"}))

	tlsClientConfig, err := c.TLSClientConfig()
	assert.NoError(t, err)
	cipherSuites := tlsClientConfig.CipherSuites

	assert.Len(t, cipherSuites, 2)
	assert.Equal(t, tls.TLS_AES_128_GCM_SHA256, cipherSuites[0])
	assert.Equal(t, tls.TLS_AES_256_GCM_SHA384, cipherSuites[1])
}

func TestTLSClientConfig_InvalidCipherSuite(t *testing.T) {
	l := logrusx.New("", "")
	c := MustNew(context.TODO(), l, configx.WithValue("client.tls.cipher_suites", []string{"TLS_AES_128_GCM_SHA256", "TLS_INVALID_CIPHER_SUITE"}))

	_, err := c.TLSClientConfig()

	assert.EqualError(t, err, "Unable to setup client TLS configuration: unsupported cipher \"TLS_INVALID_CIPHER_SUITE\"")
}

func TestTLSClientConfig_MinVersion(t *testing.T) {
	l := logrusx.New("", "")
	c := MustNew(context.TODO(), l, configx.WithValue("client.tls.min_version", "tls13"))

	tlsClientConfig, err := c.TLSClientConfig()

	assert.NoError(t, err)
	assert.Equal(t, uint16(tls.VersionTLS13), tlsClientConfig.MinVersion)
}

func TestTLSClientConfig_InvalidMinVersion(t *testing.T) {
	l := logrusx.New("", "")
	c := MustNew(context.TODO(), l, configx.WithValue("client.tls.min_version", "tlsx"))

	_, err := c.TLSClientConfig()

	assert.EqualError(t, err, "Unable to setup client TLS configuration. Invalid minimum TLS version: tlsx")
}

func TestTLSClientConfig_MaxVersion(t *testing.T) {
	l := logrusx.New("", "")
	c := MustNew(context.TODO(), l, configx.WithValue("client.tls.max_version", "tls10"))

	tlsClientConfig, err := c.TLSClientConfig()

	assert.NoError(t, err)
	assert.Equal(t, uint16(tls.VersionTLS10), tlsClientConfig.MaxVersion)
}

func TestTLSClientConfig_InvalidMaxTlsVersion(t *testing.T) {
	l := logrusx.New("", "")
	c := MustNew(context.TODO(), l, configx.WithValue("client.tls.max_version", "tlsx"))

	_, err := c.TLSClientConfig()

	assert.EqualError(t, err, "Unable to setup client TLS configuration. Invalid maximum TLS version: tlsx")
}
