// Copyright © 2022 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package consent_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/tidwall/gjson"

	"github.com/ory/hydra/v2/driver"

	"github.com/ory/x/pointerx"

	"github.com/ory/hydra/v2/x"
	"github.com/ory/x/contextx"
	"github.com/ory/x/sqlxx"

	"github.com/ory/hydra/v2/internal"

	"github.com/stretchr/testify/require"

	hydra "github.com/ory/hydra-client-go/v2"
	"github.com/ory/hydra/v2/client"
	. "github.com/ory/hydra/v2/consent"
)

func TestGetLogoutRequest(t *testing.T) {
	for k, tc := range []struct {
		exists  bool
		handled bool
		status  int
	}{
		{false, false, http.StatusNotFound},
		{true, false, http.StatusOK},
		{true, true, http.StatusGone},
	} {
		t.Run(fmt.Sprintf("case=%d", k), func(t *testing.T) {
			key := fmt.Sprint(k)
			challenge := "challenge" + key
			requestURL := "http://192.0.2.1"

			conf := internal.NewConfigurationWithDefaults()
			reg := internal.NewRegistryMemory(t, conf, &contextx.Default{})

			if tc.exists {
				cl := &client.Client{LegacyClientID: "client" + key}
				require.NoError(t, reg.ClientManager().CreateClient(context.Background(), cl))
				require.NoError(t, reg.ConsentManager().CreateLogoutRequest(context.TODO(), &LogoutRequest{
					Client:     cl,
					ID:         challenge,
					WasHandled: tc.handled,
					RequestURL: requestURL,
				}))
			}

			h := NewHandler(reg, conf)
			r := x.NewRouterAdmin(conf.AdminURL)
			h.SetRoutes(r)
			ts := httptest.NewServer(r)
			defer ts.Close()

			c := &http.Client{}
			resp, err := c.Get(ts.URL + "/admin" + LogoutPath + "?challenge=" + challenge)
			require.NoError(t, err)
			require.EqualValues(t, tc.status, resp.StatusCode)

			if tc.handled {
				var result OAuth2RedirectTo
				require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))
				require.Equal(t, requestURL, result.RedirectTo)
			} else if tc.exists {
				var result LogoutRequest
				require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))
				require.Equal(t, challenge, result.ID)
				require.Equal(t, requestURL, result.RequestURL)
			}
		})
	}
}

func TestGetLoginRequest(t *testing.T) {
	for k, tc := range []struct {
		exists  bool
		handled bool
		status  int
	}{
		{false, false, http.StatusNotFound},
		{true, false, http.StatusOK},
		{true, true, http.StatusGone},
	} {
		t.Run(fmt.Sprintf("case=%d", k), func(t *testing.T) {
			key := fmt.Sprint(k)
			challenge := "challenge" + key
			requestURL := "http://192.0.2.1"

			conf := internal.NewConfigurationWithDefaults()
			reg := internal.NewRegistryMemory(t, conf, &contextx.Default{})

			if tc.exists {
				cl := &client.Client{LegacyClientID: "client" + key}
				require.NoError(t, reg.ClientManager().CreateClient(context.Background(), cl))
				require.NoError(t, reg.ConsentManager().CreateLoginRequest(context.Background(), &LoginRequest{
					Client:     cl,
					ID:         challenge,
					RequestURL: requestURL,
				}))

				if tc.handled {
					_, err := reg.ConsentManager().HandleLoginRequest(context.Background(), challenge, &HandledLoginRequest{ID: challenge, WasHandled: true})
					require.NoError(t, err)
				}
			}

			h := NewHandler(reg, conf)
			r := x.NewRouterAdmin(conf.AdminURL)
			h.SetRoutes(r)
			ts := httptest.NewServer(r)
			defer ts.Close()

			c := &http.Client{}
			resp, err := c.Get(ts.URL + "/admin" + LoginPath + "?challenge=" + challenge)
			require.NoError(t, err)
			require.EqualValues(t, tc.status, resp.StatusCode)

			if tc.handled {
				var result OAuth2RedirectTo
				require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))
				require.Equal(t, requestURL, result.RedirectTo)
			} else if tc.exists {
				var result LoginRequest
				require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))
				require.Equal(t, challenge, result.ID)
				require.Equal(t, requestURL, result.RequestURL)
				require.NotNil(t, result.Client)
			}
		})
	}
}

func TestGetConsentRequest(t *testing.T) {
	for k, tc := range []struct {
		exists  bool
		handled bool
		status  int
	}{
		{false, false, http.StatusNotFound},
		{true, false, http.StatusOK},
		{true, true, http.StatusGone},
	} {
		t.Run(fmt.Sprintf("case=%d", k), func(t *testing.T) {
			key := fmt.Sprint(k)
			challenge := "challenge" + key
			requestURL := "http://192.0.2.1"

			conf := internal.NewConfigurationWithDefaults()
			reg := internal.NewRegistryMemory(t, conf, &contextx.Default{})

			if tc.exists {
				cl := &client.Client{LegacyClientID: "client" + key}
				require.NoError(t, reg.ClientManager().CreateClient(context.Background(), cl))
				lr := &LoginRequest{ID: "login-" + challenge, Client: cl, RequestURL: requestURL}
				require.NoError(t, reg.ConsentManager().CreateLoginRequest(context.Background(), lr))
				_, err := reg.ConsentManager().HandleLoginRequest(context.Background(), lr.ID, &HandledLoginRequest{
					ID: lr.ID,
				})
				require.NoError(t, err)
				require.NoError(t, reg.ConsentManager().CreateConsentRequest(context.Background(), &OAuth2ConsentRequest{
					Client:         cl,
					ID:             challenge,
					Verifier:       challenge,
					CSRF:           challenge,
					LoginChallenge: sqlxx.NullString(lr.ID),
				}))

				if tc.handled {
					_, err := reg.ConsentManager().HandleConsentRequest(context.Background(), &AcceptOAuth2ConsentRequest{
						ID:         challenge,
						WasHandled: true,
						HandledAt:  sqlxx.NullTime(time.Now()),
					})
					require.NoError(t, err)
				}
			}

			h := NewHandler(reg, conf)

			r := x.NewRouterAdmin(conf.AdminURL)
			h.SetRoutes(r)
			ts := httptest.NewServer(r)
			defer ts.Close()

			c := &http.Client{}
			resp, err := c.Get(ts.URL + "/admin" + ConsentPath + "?challenge=" + challenge)
			require.NoError(t, err)
			require.EqualValues(t, tc.status, resp.StatusCode)

			if tc.handled {
				var result OAuth2RedirectTo
				require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))
				require.Equal(t, requestURL, result.RedirectTo)
			} else if tc.exists {
				var result OAuth2ConsentRequest
				require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))
				require.Equal(t, challenge, result.ID)
				require.Equal(t, requestURL, result.RequestURL)
				require.NotNil(t, result.Client)
			}
		})
	}
}

func TestGetLoginRequestWithDuplicateAccept(t *testing.T) {
	t.Run("Test get login request with duplicate accept", func(t *testing.T) {
		challenge := "challenge"
		requestURL := "http://192.0.2.1"

		conf := internal.NewConfigurationWithDefaults()
		reg := internal.NewRegistryMemory(t, conf, &contextx.Default{})

		cl := &client.Client{LegacyClientID: "client"}
		require.NoError(t, reg.ClientManager().CreateClient(context.Background(), cl))
		require.NoError(t, reg.ConsentManager().CreateLoginRequest(context.Background(), &LoginRequest{
			Client:     cl,
			ID:         challenge,
			RequestURL: requestURL,
		}))

		h := NewHandler(reg, conf)
		r := x.NewRouterAdmin(conf.AdminURL)
		h.SetRoutes(r)
		ts := httptest.NewServer(r)
		defer ts.Close()

		c := &http.Client{}

		sub := "sub123"
		acceptLogin := &hydra.AcceptOAuth2LoginRequest{Remember: pointerx.Bool(true), Subject: sub}

		// marshal User to json
		acceptLoginJson, err := json.Marshal(acceptLogin)
		if err != nil {
			panic(err)
		}

		// set the HTTP method, url, and request body
		req, err := http.NewRequest(http.MethodPut, ts.URL+"/admin"+LoginPath+"/accept?challenge="+challenge, bytes.NewBuffer(acceptLoginJson))
		if err != nil {
			panic(err)
		}

		resp, err := c.Do(req)
		require.NoError(t, err)
		require.EqualValues(t, http.StatusOK, resp.StatusCode)

		var result OAuth2RedirectTo
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))
		require.NotNil(t, result.RedirectTo)
		require.Contains(t, result.RedirectTo, "login_verifier")

		req2, err := http.NewRequest(http.MethodPut, ts.URL+"/admin"+LoginPath+"/accept?challenge="+challenge, bytes.NewBuffer(acceptLoginJson))
		if err != nil {
			panic(err)
		}

		resp2, err := c.Do(req2)
		require.NoError(t, err)
		require.EqualValues(t, http.StatusOK, resp2.StatusCode)

		var result2 OAuth2RedirectTo
		require.NoError(t, json.NewDecoder(resp2.Body).Decode(&result2))
		require.NotNil(t, result2.RedirectTo)
		require.Contains(t, result2.RedirectTo, "login_verifier")
	})
}

func TestRevokeConsentSession(t *testing.T) {
	newWg := func(add int) *sync.WaitGroup {
		var wg sync.WaitGroup
		wg.Add(add)
		return &wg
	}

	t.Run("case=subject=subject-1,client=client-1,session=session-1,trigger_backchannel_logout=true", func(t *testing.T) {
		conf := internal.NewConfigurationWithDefaults()
		reg := internal.NewRegistryMemory(t, conf, &contextx.Default{})
		backChannelWG := newWg(1)
		cl := createClientWithBackChannelEndpoint(t, reg, "client-1", []string{"login-session-1"}, backChannelWG)
		performLoginFlow(t, reg, "1", cl)
		performLoginFlow(t, reg, "2", cl)
		performDeleteConsentSession(t, reg, "client-1", "login-session-1", true)
		c1, err := reg.ConsentManager().GetConsentRequest(context.Background(), "consent-challenge-1")
		require.Error(t, x.ErrNotFound, err)
		require.Nil(t, c1)
		c2, err := reg.ConsentManager().GetConsentRequest(context.Background(), "consent-challenge-2")
		require.NoError(t, err)
		require.NotNil(t, c2)
		backChannelWG.Wait()
	})

	t.Run("case=subject=subject-1,client=client-1,session=session-1,trigger_backchannel_logout=false", func(t *testing.T) {
		conf := internal.NewConfigurationWithDefaults()
		reg := internal.NewRegistryMemory(t, conf, &contextx.Default{})
		backChannelWG := newWg(0)
		cl := createClientWithBackChannelEndpoint(t, reg, "client-1", []string{}, backChannelWG)
		performLoginFlow(t, reg, "1", cl)
		performLoginFlow(t, reg, "2", cl)
		performDeleteConsentSession(t, reg, "client-1", "login-session-1", false)
		c1, err := reg.ConsentManager().GetConsentRequest(context.Background(), "consent-challenge-1")
		require.Error(t, x.ErrNotFound, err)
		require.Nil(t, c1)
		c2, err := reg.ConsentManager().GetConsentRequest(context.Background(), "consent-challenge-2")
		require.NoError(t, err)
		require.NotNil(t, c2)
		backChannelWG.Wait()
	})

	t.Run("case=subject=subject-1,client=client-1,trigger_backchannel_logout=true", func(t *testing.T) {
		conf := internal.NewConfigurationWithDefaults()
		reg := internal.NewRegistryMemory(t, conf, &contextx.Default{})
		backChannelWG := newWg(2)
		cl := createClientWithBackChannelEndpoint(t, reg, "client-1", []string{"login-session-1", "login-session-2"}, backChannelWG)
		performLoginFlow(t, reg, "1", cl)
		performLoginFlow(t, reg, "2", cl)

		performDeleteConsentSession(t, reg, "client-1", nil, true)

		c1, err := reg.ConsentManager().GetConsentRequest(context.Background(), "consent-challenge-1")
		require.Error(t, x.ErrNotFound, err)
		require.Nil(t, c1)
		c2, err := reg.ConsentManager().GetConsentRequest(context.Background(), "consent-challenge-2")
		require.Error(t, x.ErrNotFound, err)
		require.Nil(t, c2)
		backChannelWG.Wait()
	})

	t.Run("case=subject=subject-1,client=client-1,trigger_backchannel_logout=false", func(t *testing.T) {
		conf := internal.NewConfigurationWithDefaults()
		reg := internal.NewRegistryMemory(t, conf, &contextx.Default{})
		backChannelWG := newWg(0)
		cl := createClientWithBackChannelEndpoint(t, reg, "client-1", []string{}, backChannelWG)
		performLoginFlow(t, reg, "1", cl)
		performLoginFlow(t, reg, "2", cl)

		performDeleteConsentSession(t, reg, "client-1", nil, false)

		c1, err := reg.ConsentManager().GetConsentRequest(context.Background(), "consent-challenge-1")
		require.Error(t, x.ErrNotFound, err)
		require.Nil(t, c1)
		c2, err := reg.ConsentManager().GetConsentRequest(context.Background(), "consent-challenge-2")
		require.Error(t, x.ErrNotFound, err)
		require.Nil(t, c2)
		backChannelWG.Wait()
	})

	t.Run("case=subject=subject-1,all=true,session=session-1,trigger_backchannel_logout=true", func(t *testing.T) {
		conf := internal.NewConfigurationWithDefaults()
		reg := internal.NewRegistryMemory(t, conf, &contextx.Default{})
		backChannelWG := newWg(1)
		cl1 := createClientWithBackChannelEndpoint(t, reg, "client-1", []string{"login-session-1"}, backChannelWG)
		cl2 := createClientWithBackChannelEndpoint(t, reg, "client-2", []string{}, backChannelWG)
		performLoginFlow(t, reg, "1", cl1)
		performLoginFlow(t, reg, "2", cl2)

		performDeleteConsentSession(t, reg, nil, "login-session-1", true)

		c1, err := reg.ConsentManager().GetConsentRequest(context.Background(), "consent-challenge-1")
		require.Error(t, x.ErrNotFound, err)
		require.Nil(t, c1)
		c2, err := reg.ConsentManager().GetConsentRequest(context.Background(), "consent-challenge-2")
		require.NoError(t, err)
		require.NotNil(t, c2)
		backChannelWG.Wait()
	})

	t.Run("case=subject=subject-1,all=true,session=session-1,trigger_backchannel_logout=false", func(t *testing.T) {
		conf := internal.NewConfigurationWithDefaults()
		reg := internal.NewRegistryMemory(t, conf, &contextx.Default{})
		backChannelWG := newWg(0)
		cl1 := createClientWithBackChannelEndpoint(t, reg, "client-1", []string{}, backChannelWG)
		cl2 := createClientWithBackChannelEndpoint(t, reg, "client-2", []string{}, backChannelWG)
		performLoginFlow(t, reg, "1", cl1)
		performLoginFlow(t, reg, "2", cl2)

		performDeleteConsentSession(t, reg, nil, "login-session-1", false)

		c1, err := reg.ConsentManager().GetConsentRequest(context.Background(), "consent-challenge-1")
		require.Error(t, x.ErrNotFound, err)
		require.Nil(t, c1)
		c2, err := reg.ConsentManager().GetConsentRequest(context.Background(), "consent-challenge-2")
		require.NoError(t, err)
		require.NotNil(t, c2)
		backChannelWG.Wait()
	})

	t.Run("case=subject=subject-1,all=true,trigger_backchannel_logout=true", func(t *testing.T) {
		conf := internal.NewConfigurationWithDefaults()
		reg := internal.NewRegistryMemory(t, conf, &contextx.Default{})
		backChannelWG := newWg(2)
		cl1 := createClientWithBackChannelEndpoint(t, reg, "client-1", []string{"login-session-1"}, backChannelWG)
		cl2 := createClientWithBackChannelEndpoint(t, reg, "client-2", []string{"login-session-2"}, backChannelWG)
		performLoginFlow(t, reg, "1", cl1)
		performLoginFlow(t, reg, "2", cl2)

		performDeleteConsentSession(t, reg, nil, nil, true)

		c1, err := reg.ConsentManager().GetConsentRequest(context.Background(), "consent-challenge-1")
		require.Error(t, x.ErrNotFound, err)
		require.Nil(t, c1)
		c2, err := reg.ConsentManager().GetConsentRequest(context.Background(), "consent-challenge-2")
		require.Error(t, x.ErrNotFound, err)
		require.Nil(t, c2)
		backChannelWG.Wait()
	})

	t.Run("case=subject=subject-1,all=true,trigger_backchannel_logout=false", func(t *testing.T) {
		conf := internal.NewConfigurationWithDefaults()
		reg := internal.NewRegistryMemory(t, conf, &contextx.Default{})
		backChannelWG := newWg(0)
		cl1 := createClientWithBackChannelEndpoint(t, reg, "client-1", []string{}, backChannelWG)
		cl2 := createClientWithBackChannelEndpoint(t, reg, "client-2", []string{}, backChannelWG)
		performLoginFlow(t, reg, "1", cl1)
		performLoginFlow(t, reg, "2", cl2)

		performDeleteConsentSession(t, reg, nil, nil, false)

		c1, err := reg.ConsentManager().GetConsentRequest(context.Background(), "consent-challenge-1")
		require.Error(t, x.ErrNotFound, err)
		require.Nil(t, c1)
		c2, err := reg.ConsentManager().GetConsentRequest(context.Background(), "consent-challenge-2")
		require.Error(t, x.ErrNotFound, err)
		require.Nil(t, c2)
		backChannelWG.Wait()
	})
}

func performDeleteConsentSession(t *testing.T, reg driver.Registry, client, loginSessionId interface{}, triggerBackChannelLogout bool) {
	conf := internal.NewConfigurationWithDefaults()
	h := NewHandler(reg, conf)
	r := x.NewRouterAdmin(conf.AdminURL)
	h.SetRoutes(r)
	ts := httptest.NewServer(r)
	defer ts.Close()
	c := &http.Client{}

	u, _ := url.Parse(ts.URL + "/admin" + SessionsPath + "/consent")
	q := u.Query()
	q.Set("subject", "subject-1")
	if client != nil && len(client.(string)) != 0 {
		q.Set("client", client.(string))
	} else {
		q.Set("all", "true")
	}
	if loginSessionId != nil && len(loginSessionId.(string)) != 0 {
		q.Set("login_session_id", loginSessionId.(string))
	}
	if triggerBackChannelLogout {
		q.Set("trigger_backchannel_logout", "true")
	}
	u.RawQuery = q.Encode()
	req, err := http.NewRequest(http.MethodDelete, u.String(), nil)

	require.NoError(t, err)
	_, err = c.Do(req)
	require.NoError(t, err)
}

func performLoginFlow(t *testing.T, reg driver.Registry, flowId string, cl *client.Client) {
	subject := "subject-1"
	loginSessionId := "login-session-" + flowId
	loginChallenge := "login-challenge-" + flowId
	consentChallenge := "consent-challenge-" + flowId
	requestURL := "http://192.0.2.1"

	ls := &LoginSession{
		ID:      loginSessionId,
		Subject: subject,
	}
	lr := &LoginRequest{
		ID:         loginChallenge,
		Subject:    subject,
		Client:     cl,
		RequestURL: requestURL,
		Verifier:   "login-verifier-" + flowId,
		SessionID:  sqlxx.NullString(loginSessionId),
	}
	cr := &OAuth2ConsentRequest{
		Client:         cl,
		ID:             consentChallenge,
		Verifier:       consentChallenge,
		CSRF:           consentChallenge,
		Subject:        subject,
		LoginChallenge: sqlxx.NullString(loginChallenge),
		LoginSessionID: sqlxx.NullString(loginSessionId),
	}
	hcr := &AcceptOAuth2ConsentRequest{
		ConsentRequest: cr,
		ID:             consentChallenge,
		WasHandled:     true,
		HandledAt:      sqlxx.NullTime(time.Now().UTC()),
	}

	require.NoError(t, reg.ConsentManager().CreateLoginSession(context.Background(), ls))
	require.NoError(t, reg.ConsentManager().CreateLoginRequest(context.Background(), lr))
	require.NoError(t, reg.ConsentManager().CreateConsentRequest(context.Background(), cr))
	_, err := reg.ConsentManager().HandleConsentRequest(context.Background(), hcr)
	require.NoError(t, err)
}

func createClientWithBackChannelEndpoint(t *testing.T, reg driver.Registry, clientId string, expectedBackChannelLogoutFlowIds []string, wg *sync.WaitGroup) *client.Client {
	return func(t *testing.T, key string, wg *sync.WaitGroup, cb func(t *testing.T, logoutToken gjson.Result)) *client.Client {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer wg.Done()
			require.NoError(t, r.ParseForm())
			lt := r.PostFormValue("logout_token")
			assert.NotEmpty(t, lt)
			token, err := reg.OpenIDJWTStrategy().Decode(r.Context(), lt)
			require.NoError(t, err)
			var b bytes.Buffer
			require.NoError(t, json.NewEncoder(&b).Encode(token.Claims))
			cb(t, gjson.Parse(b.String()))
		}))
		t.Cleanup(server.Close)
		c := &client.Client{
			LegacyClientID:       clientId,
			BackChannelLogoutURI: server.URL,
		}
		err := reg.ClientManager().CreateClient(context.Background(), c)
		require.NoError(t, err)
		return c
	}(t, clientId, wg, func(t *testing.T, logoutToken gjson.Result) {
		sid := logoutToken.Get("sid").String()
		assert.Contains(t, expectedBackChannelLogoutFlowIds, sid)
		for i, v := range expectedBackChannelLogoutFlowIds {
			if v == sid {
				expectedBackChannelLogoutFlowIds = append(expectedBackChannelLogoutFlowIds[:i], expectedBackChannelLogoutFlowIds[i+1:]...)
				break
			}
		}
	})
}

func TestExtendConsentRequest(t *testing.T) {
	t.Run("case=extend consent expiry time", func(t *testing.T) {
		conf := internal.NewConfigurationWithDefaults()
		reg := internal.NewRegistryMemory(t, conf, &contextx.Default{})
		h := NewHandler(reg, conf)
		r := x.NewRouterAdmin(conf.AdminURL)
		h.SetRoutes(r)
		ts := httptest.NewServer(r)
		defer ts.Close()

		c := &http.Client{}
		cl := &client.Client{LegacyClientID: "client-1"}
		require.NoError(t, reg.ClientManager().CreateClient(context.Background(), cl))

		var initialRememberFor time.Duration = 300
		var remainingValidTime time.Duration = 100

		require.NoError(t, reg.ConsentManager().CreateLoginSession(context.Background(), &LoginSession{
			ID:      makeID("fk-login-session", "1", "1"),
			Subject: "subject-1",
		}))
		requestedTimeInPast := time.Now().UTC().Add(-(initialRememberFor - remainingValidTime) * time.Second)
		require.NoError(t, reg.ConsentManager().CreateLoginRequest(context.Background(), &LoginRequest{
			ID:          makeID("challenge", "1", "1"),
			SessionID:   sqlxx.NullString(makeID("fk-login-session", "1", "1")),
			Client:      cl,
			Subject:     "subject-1",
			RequestedAt: requestedTimeInPast,
		}))
		require.NoError(t, reg.ConsentManager().CreateConsentRequest(context.Background(), &OAuth2ConsentRequest{
			ID:             makeID("challenge", "1", "1"),
			Subject:        "subject-1",
			Client:         cl,
			LoginSessionID: sqlxx.NullString(makeID("fk-login-session", "1", "1")),
			LoginChallenge: sqlxx.NullString(makeID("challenge", "1", "1")),
			Verifier:       makeID("verifier", "1", "1"),
			CSRF:           "csrf1",
			Skip:           false,
			ACR:            "1",
		}))
		_, err := reg.ConsentManager().HandleConsentRequest(context.Background(), &AcceptOAuth2ConsentRequest{
			ID:          makeID("challenge", "1", "1"),
			Remember:    true,
			RememberFor: int(initialRememberFor),
			WasHandled:  true,
			HandledAt:   sqlxx.NullTime(time.Now().UTC()),
		})
		require.NoError(t, err)

		require.NoError(t, reg.ConsentManager().CreateLoginRequest(context.Background(), &LoginRequest{
			ID:          makeID("challenge", "1", "2"),
			SessionID:   sqlxx.NullString(makeID("fk-login-session", "1", "1")),
			Verifier:    makeID("verifier", "1", "1"),
			Client:      cl,
			RequestedAt: time.Now().UTC(),
			Subject:     "subject-1",
		}))
		require.NoError(t, reg.ConsentManager().CreateConsentRequest(context.Background(), &OAuth2ConsentRequest{
			ID:             makeID("challenge", "1", "2"),
			Subject:        "subject-1",
			Client:         cl,
			LoginSessionID: sqlxx.NullString(makeID("fk-login-session", "1", "1")),
			LoginChallenge: sqlxx.NullString(makeID("challenge", "1", "2")),
			Verifier:       makeID("verifier", "1", "2"),
			CSRF:           "csrf2",
			Skip:           true,
		}))

		var b bytes.Buffer
		var extendRememberFor time.Duration = 300
		require.NoError(t, json.NewEncoder(&b).Encode(&AcceptOAuth2ConsentRequest{
			Remember:    true,
			RememberFor: int(extendRememberFor),
		}))

		req, err := http.NewRequest(http.MethodPut, ts.URL+"/admin"+ConsentPath+"/accept?challenge=challenge-1-2", &b)
		require.NoError(t, err)
		resp, err := c.Do(req)
		require.NoError(t, err)
		require.EqualValues(t, 200, resp.StatusCode)

		crs, err := reg.ConsentManager().FindSubjectsGrantedConsentRequests(context.Background(), "subject-1", AllActive, 100, 0)
		require.NoError(t, err)
		require.NotNil(t, crs)
		require.EqualValues(t, 1, len(crs))
		expectedRememberFor := int(initialRememberFor + extendRememberFor - remainingValidTime)
		cr := crs[0]
		require.EqualValues(t, "challenge-1-1", cr.ID)
		require.InDelta(t, expectedRememberFor, cr.RememberFor, 1)
	})
}

func TestGetLoginSessionClaims(t *testing.T) {
	conf := internal.NewConfigurationWithDefaults()
	reg := internal.NewRegistryMemory(t, conf, &contextx.Default{})
	h := NewHandler(reg, conf)
	r := x.NewRouterAdmin(conf.AdminURL)
	h.SetRoutes(r)
	ts := httptest.NewServer(r)
	defer ts.Close()

	cl := &client.Client{LegacyClientID: "claims-client"}
	require.NoError(t, reg.ClientManager().CreateClient(context.Background(), cl))

	authTime := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)

	createLoginSession := func(t *testing.T, sid string) {
		require.NoError(t, reg.ConsentManager().CreateLoginSession(context.Background(), &LoginSession{ID: sid, Subject: "subject-1"}))
	}

	performFlow := func(t *testing.T, sid, flowId string, requestedAt time.Time, acr string, amr []string, idToken map[string]interface{}, consentErr *RequestDeniedError) {
		lr := &LoginRequest{
			ID:          "claims-login-challenge-" + flowId,
			Subject:     "subject-1",
			Client:      cl,
			RequestURL:  "http://192.0.2.1",
			Verifier:    "claims-login-verifier-" + flowId,
			SessionID:   sqlxx.NullString(sid),
			RequestedAt: requestedAt,
		}
		require.NoError(t, reg.ConsentManager().CreateLoginRequest(context.Background(), lr))
		_, err := reg.ConsentManager().HandleLoginRequest(context.Background(), lr.ID, &HandledLoginRequest{
			ID:              lr.ID,
			Subject:         "subject-1",
			ACR:             acr,
			AMR:             amr,
			AuthenticatedAt: sqlxx.NullTime(authTime),
			RequestedAt:     requestedAt,
			LoginRequest:    lr,
		})
		require.NoError(t, err)

		cr := &OAuth2ConsentRequest{
			Client:         cl,
			ID:             "claims-consent-challenge-" + flowId,
			Verifier:       "claims-consent-verifier-" + flowId,
			CSRF:           "claims-consent-csrf-" + flowId,
			Subject:        "subject-1",
			LoginChallenge: sqlxx.NullString(lr.ID),
			LoginSessionID: sqlxx.NullString(sid),
		}
		require.NoError(t, reg.ConsentManager().CreateConsentRequest(context.Background(), cr))
		_, err = reg.ConsentManager().HandleConsentRequest(context.Background(), &AcceptOAuth2ConsentRequest{
			ConsentRequest: cr,
			ID:             cr.ID,
			WasHandled:     true,
			HandledAt:      sqlxx.NullTime(time.Now().UTC()),
			Session:        &AcceptOAuth2ConsentRequestSession{IDToken: idToken},
			Error:          consentErr,
		})
		require.NoError(t, err)
	}

	get := func(t *testing.T, sid *string) (int, gjson.Result) {
		u, err := url.Parse(ts.URL + "/admin" + SessionsPath + "/login")
		require.NoError(t, err)
		if sid != nil {
			u.RawQuery = url.Values{"sid": {*sid}}.Encode()
		}
		res, err := http.Get(u.String())
		require.NoError(t, err)
		defer res.Body.Close()
		var b bytes.Buffer
		_, err = b.ReadFrom(res.Body)
		require.NoError(t, err)
		return res.StatusCode, gjson.Parse(b.String())
	}

	t.Run("case=returns claims of the latest granted consent", func(t *testing.T) {
		sid := "claims-login-session-1"
		createLoginSession(t, sid)
		performFlow(t, sid, "1a", time.Now().UTC().Add(-2*time.Minute), "acr-old", []string{"pwd"}, map[string]interface{}{
			"given_name": "Old", "family_name": "Name", "birthdate": "1990-01-01",
		}, nil)
		performFlow(t, sid, "1b", time.Now().UTC().Add(-time.Minute), "acr-new", []string{"mID", "smartid"}, map[string]interface{}{
			"given_name": "Mari", "family_name": "Maasikas", "birthdate": "1985-05-05",
			"phone_number": "+37200000766", "phone_number_verified": true, "other": "ignored",
		}, nil)

		status, body := get(t, &sid)
		require.Equal(t, http.StatusOK, status, body.Raw)
		assert.Equal(t, "subject-1", body.Get("subject").String())
		assert.Equal(t, "Mari", body.Get("given_name").String())
		assert.Equal(t, "Maasikas", body.Get("family_name").String())
		assert.Equal(t, "1985-05-05", body.Get("birthdate").String())
		assert.Equal(t, "+37200000766", body.Get("phone_number").String())
		assert.True(t, body.Get("phone_number_verified").Bool())
		assert.Equal(t, authTime.Unix(), body.Get("auth_time").Int())
		assert.Equal(t, "acr-new", body.Get("acr").String())
		assert.Equal(t, `["mID","smartid"]`, body.Get("amr").Raw)
		assert.False(t, body.Get("other").Exists())
	})

	t.Run("case=omits claims missing from the id token session", func(t *testing.T) {
		sid := "claims-login-session-2"
		createLoginSession(t, sid)
		performFlow(t, sid, "2", time.Now().UTC(), "acr", []string{"pwd"}, map[string]interface{}{"given_name": "Mari"}, nil)

		status, body := get(t, &sid)
		require.Equal(t, http.StatusOK, status, body.Raw)
		assert.Equal(t, "Mari", body.Get("given_name").String())
		assert.False(t, body.Get("family_name").Exists())
		assert.False(t, body.Get("birthdate").Exists())
		assert.False(t, body.Get("phone_number").Exists())
		assert.False(t, body.Get("phone_number_verified").Exists())
	})

	t.Run("case=rejected consent is not returned", func(t *testing.T) {
		sid := "claims-login-session-3"
		createLoginSession(t, sid)
		performFlow(t, sid, "3", time.Now().UTC(), "acr", nil, map[string]interface{}{"given_name": "Mari"}, &RequestDeniedError{Name: "access_denied"})

		status, _ := get(t, &sid)
		assert.Equal(t, http.StatusNotFound, status)
	})

	t.Run("case=unknown sid", func(t *testing.T) {
		sid := "claims-login-session-does-not-exist"
		status, _ := get(t, &sid)
		assert.Equal(t, http.StatusNotFound, status)
	})

	t.Run("case=missing sid", func(t *testing.T) {
		status, _ := get(t, nil)
		assert.Equal(t, http.StatusBadRequest, status)
	})
}
