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

package oauth2

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/fosite"
	"github.com/ory/fosite/internal"
	"github.com/ory/fosite/token/jwt"
)

var j = &DefaultJWTStrategy{
	JWTStrategy: &jwt.RS256JWTStrategy{
		PrivateKey: internal.MustRSAKey(),
	},
}

// returns a valid JWT type. The JWTClaims.ExpiresAt time is intentionally
// left empty to ensure it is pulled from the session's ExpiresAt map for
// the given fosite.TokenType.
var jwtValidCase = func(tokenType fosite.TokenType) *fosite.Request {
	r := &fosite.Request{
		Client: &fosite.DefaultClient{
			Secret: []byte("foobarfoobarfoobarfoobar"),
		},
		Session: &JWTSession{
			JWTClaims: &jwt.JWTClaims{
				Issuer:    "fosite",
				Subject:   "peter",
				IssuedAt:  time.Now().UTC(),
				NotBefore: time.Now().UTC(),
				Extra:     map[string]interface{}{"foo": "bar"},
			},
			JWTHeader: &jwt.Headers{
				Extra: make(map[string]interface{}),
			},
			ExpiresAt: map[fosite.TokenType]time.Time{
				tokenType: time.Now().UTC().Add(time.Hour),
			},
		},
	}
	r.SetRequestedScopes([]string{"email", "offline"})
	r.GrantScope("email")
	r.GrantScope("offline")
	r.SetRequestedAudience([]string{"group0"})
	r.GrantAudience("group0")
	return r
}

var jwtValidCaseWithZeroRefreshExpiry = func(tokenType fosite.TokenType) *fosite.Request {
	r := &fosite.Request{
		Client: &fosite.DefaultClient{
			Secret: []byte("foobarfoobarfoobarfoobar"),
		},
		Session: &JWTSession{
			JWTClaims: &jwt.JWTClaims{
				Issuer:    "fosite",
				Subject:   "peter",
				IssuedAt:  time.Now().UTC(),
				NotBefore: time.Now().UTC(),
				Extra:     map[string]interface{}{"foo": "bar"},
			},
			JWTHeader: &jwt.Headers{
				Extra: make(map[string]interface{}),
			},
			ExpiresAt: map[fosite.TokenType]time.Time{
				tokenType:           time.Now().UTC().Add(time.Hour),
				fosite.RefreshToken: {},
			},
		},
	}
	r.SetRequestedScopes([]string{"email", "offline"})
	r.GrantScope("email")
	r.GrantScope("offline")
	r.SetRequestedAudience([]string{"group0"})
	r.GrantAudience("group0")
	return r
}

var jwtValidCaseWithRefreshExpiry = func(tokenType fosite.TokenType) *fosite.Request {
	r := &fosite.Request{
		Client: &fosite.DefaultClient{
			Secret: []byte("foobarfoobarfoobarfoobar"),
		},
		Session: &JWTSession{
			JWTClaims: &jwt.JWTClaims{
				Issuer:    "fosite",
				Subject:   "peter",
				IssuedAt:  time.Now().UTC(),
				NotBefore: time.Now().UTC(),
				Extra:     map[string]interface{}{"foo": "bar"},
			},
			JWTHeader: &jwt.Headers{
				Extra: make(map[string]interface{}),
			},
			ExpiresAt: map[fosite.TokenType]time.Time{
				tokenType:           time.Now().UTC().Add(time.Hour),
				fosite.RefreshToken: time.Now().UTC().Add(time.Hour * 2).Round(time.Hour),
			},
		},
	}
	r.SetRequestedScopes([]string{"email", "offline"})
	r.GrantScope("email")
	r.GrantScope("offline")
	r.SetRequestedAudience([]string{"group0"})
	r.GrantAudience("group0")
	return r
}

var jwtValidCaseWithClientAccessTokenTTL = func(tokenType fosite.TokenType) *fosite.Request {
	r := &fosite.Request{
		Client: &fosite.DefaultClient{
			Secret: []byte("foobarfoobarfoobarfoobar"),
		},
		Session: &JWTSession{
			JWTClaims: &jwt.JWTClaims{
				Issuer:    "fosite",
				Subject:   "peter",
				Audience:  []string{"group0"},
				IssuedAt:  time.Now().UTC(),
				NotBefore: time.Now().UTC(),
				Extra:     map[string]interface{}{"foo": "bar"},
			},
			JWTHeader: &jwt.Headers{
				Extra: make(map[string]interface{}),
			},
			ExpiresAt: map[fosite.TokenType]time.Time{
				tokenType:           time.Now().UTC().Add(time.Hour),
				fosite.RefreshToken: time.Now().UTC().Add(time.Hour * 2).Round(time.Hour),
			},
		},
	}
	r.SetRequestedScopes([]string{"email", "offline"})
	r.GrantScope("email")
	r.GrantScope("offline")
	r.SetRequestedAudience([]string{"group0"})
	r.GrantAudience("group0")
	return r
}

// returns an expired JWT type. The JWTClaims.ExpiresAt time is intentionally
// left empty to ensure it is pulled from the session's ExpiresAt map for
// the given fosite.TokenType.
var jwtExpiredCase = func(tokenType fosite.TokenType) *fosite.Request {
	r := &fosite.Request{
		Client: &fosite.DefaultClient{
			Secret: []byte("foobarfoobarfoobarfoobar"),
		},
		Session: &JWTSession{
			JWTClaims: &jwt.JWTClaims{
				Issuer:    "fosite",
				Subject:   "peter",
				IssuedAt:  time.Now().UTC(),
				NotBefore: time.Now().UTC(),
				ExpiresAt: time.Now().UTC().Add(-time.Minute),
				Extra:     map[string]interface{}{"foo": "bar"},
			},
			JWTHeader: &jwt.Headers{
				Extra: make(map[string]interface{}),
			},
			ExpiresAt: map[fosite.TokenType]time.Time{
				tokenType: time.Now().UTC().Add(-time.Hour),
			},
		},
	}
	r.SetRequestedScopes([]string{"email", "offline"})
	r.GrantScope("email")
	r.GrantScope("offline")
	r.SetRequestedAudience([]string{"group0"})
	r.GrantAudience("group0")
	return r
}

func TestAccessToken(t *testing.T) {
	for s, scopeField := range []jwt.JWTScopeFieldEnum{
		jwt.JWTScopeFieldList,
		jwt.JWTScopeFieldString,
		jwt.JWTScopeFieldBoth,
	} {
		for k, c := range []struct {
			r    *fosite.Request
			pass bool
		}{
			{
				r:    jwtValidCase(fosite.AccessToken),
				pass: true,
			},
			{
				r:    jwtExpiredCase(fosite.AccessToken),
				pass: false,
			},
			{
				r:    jwtValidCaseWithZeroRefreshExpiry(fosite.AccessToken),
				pass: true,
			},
			{
				r:    jwtValidCaseWithRefreshExpiry(fosite.AccessToken),
				pass: true,
			},
			{
				r:    jwtValidCaseWithClientAccessTokenTTL(fosite.AccessToken),
				pass: true,
			},
		} {
			t.Run(fmt.Sprintf("case=%d/%d", s, k), func(t *testing.T) {
				jWithField := j.WithScopeField(scopeField)
				token, signature, err := jWithField.GenerateAccessToken(nil, c.r)
				assert.NoError(t, err)

				parts := strings.Split(token, ".")
				require.Len(t, parts, 3, "%s - %v", token, parts)
				assert.Equal(t, parts[2], signature)

				rawPayload, err := base64.RawURLEncoding.DecodeString(parts[1])
				require.NoError(t, err)
				var payload map[string]interface{}
				err = json.Unmarshal(rawPayload, &payload)
				require.NoError(t, err)
				if scopeField == jwt.JWTScopeFieldList || scopeField == jwt.JWTScopeFieldBoth {
					scope, ok := payload["scp"]
					require.True(t, ok)
					assert.Equal(t, []interface{}{"email", "offline"}, scope)
				}
				if scopeField == jwt.JWTScopeFieldString || scopeField == jwt.JWTScopeFieldBoth {
					scope, ok := payload["scope"]
					require.True(t, ok)
					assert.Equal(t, "email offline", scope)
				}

				extraClaimsSession, ok := c.r.GetSession().(fosite.ExtraClaimsSession)
				require.True(t, ok)
				claims := extraClaimsSession.GetExtraClaims()
				assert.Equal(t, "bar", claims["foo"])
				// Returned, but will be ignored by the introspect handler.
				assert.Equal(t, "peter", claims["sub"])
				assert.Equal(t, []string{"group0"}, claims["aud"])
				// Scope field is always a string.
				assert.Equal(t, "email offline", claims["scope"])

				validate := jWithField.signature(token)
				err = jWithField.ValidateAccessToken(nil, c.r, token)
				if c.pass {
					assert.NoError(t, err)
					assert.Equal(t, signature, validate)
				} else {
					assert.Error(t, err)
				}
			})
		}
	}
}
