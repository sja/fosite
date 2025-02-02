/*
 * Copyright © 2015-2018 Aeneas Rekkas <aeneas+oss@aeneas.io>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * @author		Aeneas Rekkas <aeneas+oss@aeneas.io>
 * @copyright 	2015-2018 Aeneas Rekkas <aeneas+oss@aeneas.io>
 * @license 	Apache-2.0
 *
 */

package integration_test

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
	goauth "golang.org/x/oauth2"

	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	hst "github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/internal"
)

func TestResourceOwnerPasswordCredentialsFlow(t *testing.T) {
	for _, strategy := range []hst.AccessTokenStrategy{
		hmacStrategy,
	} {
		runResourceOwnerPasswordCredentialsGrantTest(t, strategy)
	}
}

func runResourceOwnerPasswordCredentialsGrantTest(t *testing.T, strategy hst.AccessTokenStrategy) {
	f := compose.Compose(new(fosite.Config), fositeStore, strategy, compose.OAuth2ResourceOwnerPasswordCredentialsFactory)
	ts := mockServer(t, f, &fosite.DefaultSession{})
	defer ts.Close()

	var username, password string
	oauthClient := newOAuth2Client(ts)
	for k, c := range []struct {
		description string
		setup       func()
		check       func(t *testing.T, token *goauth.Token)
		err         bool
	}{
		{
			description: "should fail because invalid password",
			setup: func() {
				username = "peter"
				password = "something-wrong"
			},
			err: true,
		},
		{
			description: "should pass",
			setup: func() {
				password = "secret"
			},
		},
		{
			description: "should pass with custom client token lifespans",
			setup: func() {
				oauthClient = newOAuth2Client(ts)
				oauthClient.ClientID = "custom-lifespan-client"
			},
			check: func(t *testing.T, token *goauth.Token) {
				s, err := fositeStore.GetAccessTokenSession(nil, strings.Split(token.AccessToken, ".")[1], nil)
				require.NoError(t, err)
				atExp := s.GetSession().GetExpiresAt(fosite.AccessToken)
				internal.RequireEqualTime(t, time.Now().UTC().Add(*internal.TestLifespans.PasswordGrantAccessTokenLifespan), atExp, time.Minute)
				atExpIn := time.Duration(token.Extra("expires_in").(float64)) * time.Second
				internal.RequireEqualDuration(t, *internal.TestLifespans.PasswordGrantAccessTokenLifespan, atExpIn, time.Minute)
				rtExp := s.GetSession().GetExpiresAt(fosite.RefreshToken)
				internal.RequireEqualTime(t, time.Now().UTC().Add(*internal.TestLifespans.PasswordGrantRefreshTokenLifespan), rtExp, time.Minute)
			},
		},
	} {
		c.setup()

		token, err := oauthClient.PasswordCredentialsToken(oauth2.NoContext, username, password)
		require.Equal(t, c.err, err != nil, "(%d) %s\n%s\n%s", k, c.description, c.err, err)
		if !c.err {
			assert.NotEmpty(t, token.AccessToken, "(%d) %s\n%s", k, c.description, token)

			if c.check != nil {
				c.check(t, token)
			}
		}

		t.Logf("Passed test case %d", k)
	}
}
