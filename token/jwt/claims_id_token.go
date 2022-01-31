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
	"time"

	"github.com/pborman/uuid"
)

// IDTokenClaims represent the claims used in open id connect requests
type IDTokenClaims struct {
	JTI                                 string
	Issuer                              string
	Subject                             string
	Audience                            []string
	Nonce                               string
	ExpiresAt                           time.Time
	IssuedAt                            time.Time
	RequestedAt                         time.Time
	AuthTime                            time.Time
	AccessTokenHash                     string
	AuthenticationContextClassReference string
	AuthenticationMethodsReferences     []string
	CodeHash                            string
	Extra                               map[string]interface{}
	Rid                                 string
	Name                      string     `json:"name" mapstructure:"name"`
	FamilyName				  string 	 `json:"family_name" mapstructure:"family_name"`
	GivenName				  string 	 `json:"given_name" mapstructure:"given_name"`
	PreferredUsername		  string 	 `json:"preferred_username" mapstructure:"preferred_username"`
	Birthday                  *time.Time `time_format:"2006-01-02" json:"birthday" mapstructure:"birthday"`
	Email                     string     `json:"email" mapstructure:"email"`
	EmailVerified             bool		 `json:"email_verified" mapstructure:"email_verified"`
	Locale                    string     `json:"locale" mapstructure:"locale"`
	Thermomixes               []string   `json:"thermomixes" mapstructure:"thermomixes"`
}

// ToMap will transform the headers to a map structure
func (c *IDTokenClaims) ToMap() map[string]interface{} {
	var ret = Copy(c.Extra)

	if c.Name != "" {
		ret["name"] = c.Name
	}else {
		delete(ret, "name")
	}

	if c.FamilyName != "" {
		ret["family_name"] = c.FamilyName
	}else {
		delete(ret, "family_name")
	}

	if c.GivenName != "" {
		ret["given_name"] = c.GivenName
	}else {
		delete(ret, "given_name")
	}

	if c.PreferredUsername != "" {
		ret["preferred_username"] = c.PreferredUsername
	}else {
		delete(ret, "preferred_username")
	}

	if c.Birthday != nil {
		ret["birthday"] = c.Birthday
	}else {
		delete(ret, "birthday")
	}

	if c.Email != "" {
		ret["email"] = c.Email
	}else {
		delete(ret, "email")
	}

	ret["email_verified"] = c.EmailVerified

	if c.Locale != "" {
		ret["locale"] = c.Locale
	}else {
		delete(ret, "locale")
	}

	if c.Thermomixes != nil {
		ret["thermomixes"] = c.Thermomixes
	}else {
		delete(ret, "thermomixes")
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

	if !c.ExpiresAt.IsZero() {
		ret["exp"] = c.ExpiresAt.Unix()
	} else {
		delete(ret, "exp")
	}

	if !c.RequestedAt.IsZero() {
		ret["rat"] = c.RequestedAt.Unix()
	} else {
		delete(ret, "rat")
	}

	if len(c.Nonce) > 0 {
		ret["nonce"] = c.Nonce
	} else {
		delete(ret, "nonce")
	}

	if len(c.AccessTokenHash) > 0 {
		ret["at_hash"] = c.AccessTokenHash
	} else {
		delete(ret, "at_hash")
	}

	if len(c.CodeHash) > 0 {
		ret["c_hash"] = c.CodeHash
	} else {
		delete(ret, "c_hash")
	}

	if !c.AuthTime.IsZero() {
		ret["auth_time"] = c.AuthTime.Unix()
	} else {
		delete(ret, "auth_time")
	}

	if len(c.AuthenticationContextClassReference) > 0 {
		ret["acr"] = c.AuthenticationContextClassReference
	} else {
		delete(ret, "acr")
	}

	if len(c.AuthenticationMethodsReferences) > 0 {
		ret["amr"] = c.AuthenticationMethodsReferences
	} else {
		delete(ret, "amr")
	}

	if len(c.Rid) > 0 {
		ret["rid"] = c.Rid
	} else {
		delete(ret, "rid")
	}

	return ret

}

// Add will add a key-value pair to the extra field
func (c *IDTokenClaims) Add(key string, value interface{}) {
	if c.Extra == nil {
		c.Extra = make(map[string]interface{})
	}
	c.Extra[key] = value
}

// Get will get a value from the extra field based on a given key
func (c *IDTokenClaims) Get(key string) interface{} {
	return c.ToMap()[key]
}

// ToMapClaims will return a jwt-go MapClaims representation
func (c IDTokenClaims) ToMapClaims() MapClaims {
	return c.ToMap()
}
