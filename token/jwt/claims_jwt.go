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

package jwt

import (
	"strings"
	"time"

	"github.com/pborman/uuid"
)

// Enum for different types of scope encoding.
type JWTScopeFieldEnum int

const (
	JWTScopeFieldUnset JWTScopeFieldEnum = iota
	JWTScopeFieldList
	JWTScopeFieldString
	JWTScopeFieldBoth
)

type JWTClaimsDefaults struct {
	ExpiresAt time.Time
	IssuedAt  time.Time
	Issuer    string
	Scope     []string
}

type JWTClaimsContainer interface {
	// With returns a copy of itself with expiresAt, scope, audience set to the given values.
	With(expiry time.Time, scope, audience []string) JWTClaimsContainer

	// WithDefaults returns a copy of itself with issuedAt and issuer set to the given default values. If those
	// values are already set in the claims, they will not be updated.
	WithDefaults(iat time.Time, issuer string) JWTClaimsContainer

	// WithScopeField configures how a scope field should be represented in JWT.
	WithScopeField(scopeField JWTScopeFieldEnum) JWTClaimsContainer

	// ToMapClaims returns the claims as a github.com/dgrijalva/jwt-go.MapClaims type.
	ToMapClaims() MapClaims
}

// JWTClaims represent a token's claims.
type JWTClaims struct {
	Subject    string
	Issuer     string
	Audience   []string
	JTI        string
	IssuedAt   time.Time
	NotBefore  time.Time
	ExpiresAt  time.Time
	Scope      []string
	Extra      map[string]interface{}
	ScopeField JWTScopeFieldEnum
	Rid        string
	Authorities []string
}

func (c *JWTClaims) With(expiry time.Time, scope, audience []string) JWTClaimsContainer {
	c.ExpiresAt = expiry
	c.Scope = scope
	c.Audience = audience
	return c
}

func (c *JWTClaims) WithDefaults(iat time.Time, issuer string) JWTClaimsContainer {
	if c.IssuedAt.IsZero() {
		c.IssuedAt = iat
	}

	if c.Issuer == "" {
		c.Issuer = issuer
	}
	return c
}

func (c *JWTClaims) WithScopeField(scopeField JWTScopeFieldEnum) JWTClaimsContainer {
	c.ScopeField = scopeField
	return c
}

// ToMap will transform the headers to a map structure
func (c *JWTClaims) ToMap() map[string]interface{} {
	var ret = Copy(c.Extra)

	if c.Rid != "" {
		ret["rid"] = c.Rid
	} else {
		delete(ret, "rid")
	}

	if c.Subject != "" {
		ret["sub"] = c.Subject
	} else {
		delete(ret, "sub")
	}

	if c.Issuer != "" {
		ret["iss"] = c.Issuer
	} else {
		delete(ret, "iss")
	}

	if c.JTI != "" {
		ret["jti"] = c.JTI
	} else {
		ret["jti"] = uuid.New()
	}

	if len(c.Audience) > 0 {
		ret["aud"] = c.Audience
	} else {
		ret["aud"] = []string{}
	}

	if !c.IssuedAt.IsZero() {
		ret["iat"] = c.IssuedAt.Unix()
	} else {
		delete(ret, "iat")
	}

	if !c.NotBefore.IsZero() {
		ret["nbf"] = c.NotBefore.Unix()
	} else {
		delete(ret, "nbf")
	}

	if !c.ExpiresAt.IsZero() {
		ret["exp"] = c.ExpiresAt.Unix()
	} else {
		delete(ret, "exp")
	}

	if c.Scope != nil {
		// ScopeField default (when value is JWTScopeFieldUnset) is the list for backwards compatibility with old versions of fosite.
		if c.ScopeField == JWTScopeFieldUnset || c.ScopeField == JWTScopeFieldList || c.ScopeField == JWTScopeFieldBoth {
			ret["scp"] = c.Scope
		}
		if c.ScopeField == JWTScopeFieldString || c.ScopeField == JWTScopeFieldBoth {
			ret["scope"] = strings.Join(c.Scope, " ")
		}
	} else {
		delete(ret, "scp")
		delete(ret, "scope")
	}

	return ret
}

// FromMap will set the claims based on a mapping
func (c *JWTClaims) FromMap(m map[string]interface{}) {
	c.Extra = make(map[string]interface{})
	for k, v := range m {
		switch k {
		case "jti":
			if s, ok := v.(string); ok {
				c.JTI = s
			}
		case "sub":
			if s, ok := v.(string); ok {
				c.Subject = s
			}
		case "iss":
			if s, ok := v.(string); ok {
				c.Issuer = s
			}
		case "aud":
			if s, ok := v.(string); ok {
				c.Audience = []string{s}
			} else if s, ok := v.([]string); ok {
				c.Audience = s
			}
		case "iat":
			c.IssuedAt = toTime(v, c.IssuedAt)
		case "nbf":
			c.NotBefore = toTime(v, c.NotBefore)
		case "exp":
			c.ExpiresAt = toTime(v, c.ExpiresAt)
		case "scp":
			switch s := v.(type) {
			case []string:
				c.Scope = s
				if c.ScopeField == JWTScopeFieldString {
					c.ScopeField = JWTScopeFieldBoth
				} else if c.ScopeField == JWTScopeFieldUnset {
					c.ScopeField = JWTScopeFieldList
				}
			case []interface{}:
				c.Scope = make([]string, len(s))
				for i, vi := range s {
					if s, ok := vi.(string); ok {
						c.Scope[i] = s
					}
				}
				if c.ScopeField == JWTScopeFieldString {
					c.ScopeField = JWTScopeFieldBoth
				} else if c.ScopeField == JWTScopeFieldUnset {
					c.ScopeField = JWTScopeFieldList
				}
			}
		case "scope":
			if s, ok := v.(string); ok {
				c.Scope = strings.Split(s, " ")
				if c.ScopeField == JWTScopeFieldList {
					c.ScopeField = JWTScopeFieldBoth
				} else if c.ScopeField == JWTScopeFieldUnset {
					c.ScopeField = JWTScopeFieldString
				}
			}
		case "rid":
			if s, ok := v.(string); ok {
				c.Rid = s
			}
		default:
			c.Extra[k] = v
		}
	}
}

func toTime(v interface{}, def time.Time) (t time.Time) {
	t = def
	switch a := v.(type) {
	case float64:
		t = time.Unix(int64(a), 0).UTC()
	case int64:
		t = time.Unix(a, 0).UTC()
	}
	return
}

// Add will add a key-value pair to the extra field
func (c *JWTClaims) Add(key string, value interface{}) {
	if c.Extra == nil {
		c.Extra = make(map[string]interface{})
	}
	c.Extra[key] = value
}

// Get will get a value from the extra field based on a given key
func (c JWTClaims) Get(key string) interface{} {
	return c.ToMap()[key]
}

// ToMapClaims will return a jwt-go MapClaims representation
func (c JWTClaims) ToMapClaims() MapClaims {
	return c.ToMap()
}

// FromMapClaims will populate claims from a jwt-go MapClaims representation
func (c *JWTClaims) FromMapClaims(mc MapClaims) {
	c.FromMap(mc)
}
