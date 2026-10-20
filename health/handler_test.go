// Copyright © 2022 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package health

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofrs/uuid"
	"github.com/ory/graceful"
	"github.com/stretchr/testify/assert"

	"github.com/ory/x/contextx"

	"github.com/stretchr/testify/require"

	"github.com/ory/hydra/v2/driver/config"
	"github.com/ory/hydra/v2/internal"
	"github.com/ory/hydra/v2/x"
	"github.com/ory/x/healthx"
)

func TestPublicHealthHandler(t *testing.T) {
	ctx := context.Background()

	doCORSRequest := func(t *testing.T, endpoint string) *http.Response {
		req, err := http.NewRequest(http.MethodGet, endpoint, nil)
		require.NoError(t, err)
		req.Host = "example.com"
		req.Header.Add("Origin", "https://example.com")
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		return resp
	}

	expectCORSHeaders := func(t *testing.T, resp *http.Response) {
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "Origin", resp.Header.Get("Vary"))
		assert.Equal(t, "https://example.com", resp.Header.Get("Access-Control-Allow-Origin"))
		assert.Equal(t, "true", resp.Header.Get("Access-Control-Allow-Credentials"))
	}

	expectNoCORSHeaders := func(t *testing.T, resp *http.Response) {
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.NotEqual(t, "Origin", resp.Header.Get("Vary"))
		assert.Equal(t, "", resp.Header.Get("Access-Control-Allow-Origin"))
	}

	for _, tc := range []struct {
		name           string
		config         map[string]interface{}
		verifyResponse func(t *testing.T, resp *http.Response)
	}{
		{
			name: "with CORS enabled",
			config: map[string]interface{}{
				"cors.allowed_origins":   []string{"https://example.com"},
				"cors.enabled":           true,
				"cors.allowed_methods":   []string{"GET"},
				"cors.allow_credentials": true,
			},
			verifyResponse: expectCORSHeaders,
		},
		{
			name: "with CORS disabled",
			config: map[string]interface{}{
				"cors.enabled": false,
			},
			verifyResponse: expectNoCORSHeaders,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conf := internal.NewConfigurationWithDefaults()
			for k, v := range tc.config {
				conf.MustSet(ctx, config.PublicInterface.Key(k), v)
			}

			reg := internal.NewRegistryMemory(t, conf, &contextx.Default{})

			public := x.NewRouterPublic()
			reg.RegisterRoutes(ctx, x.NewRouterAdmin(conf.AdminURL), public)

			ts := httptest.NewServer(public)

			tc.verifyResponse(t, doCORSRequest(t, ts.URL+healthx.AliveCheckPath))
			tc.verifyResponse(t, doCORSRequest(t, ts.URL+healthx.ReadyCheckPath))
		})
	}
}

// TestReadyHandlerConnectionPoolExhausted asserts that the readiness endpoint reports
// the instance as not ready when no connection can be obtained from the database pool,
// instead of blocking until one is released.
func TestReadyHandlerConnectionPoolExhausted(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping test in short mode, waits for the database ping timeout to elapse.")
	}
	ctx := context.Background()

	dsn := fmt.Sprintf(
		"sqlite://file:%s?mode=memory&_fk=true&cache=shared&max_conns=1",
		uuid.Must(uuid.NewV4()),
	)
	reg := internal.NewRegistrySQLFromURL(t, dsn, true, &contextx.Default{})

	// The admin endpoint is registered with shareErrors=true, so the response carries
	// the underlying reason rather than an obfuscated placeholder.
	admin := x.NewRouterAdmin(reg.Config().AdminURL)
	reg.RegisterRoutes(ctx, admin, x.NewRouterPublic())
	ts := httptest.NewServer(admin)
	t.Cleanup(ts.Close)

	resp, err := http.Get(ts.URL + healthx.ReadyCheckPath)
	require.NoError(t, err)
	t.Cleanup(func() { _ = resp.Body.Close() })
	require.Equal(t, http.StatusOK, resp.StatusCode, "the instance must be ready while the pool has capacity")

	// Check out the only connection the pool may hand out and keep it checked out.
	tx, err := reg.Persister().Connection(ctx).Store.TransactionContext(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = tx.Rollback() })

	// The check must fail rather than block until the transaction above releases
	// the connection.
	start := time.Now()
	resp, err = http.Get(ts.URL + healthx.ReadyCheckPath)
	require.NoError(t, err)
	t.Cleanup(func() { _ = resp.Body.Close() })

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode, "body: %s", body)
	assert.Less(t, time.Since(start), 2*graceful.DefaultReadTimeout)
}
