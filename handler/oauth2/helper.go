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
	"context"
	"time"
	"github.com/dgrijalva/jwt-go"
	"github.com/ory/fosite"
)

type HandleHelper struct {
	AccessTokenStrategy  AccessTokenStrategy
	AccessTokenStorage   AccessTokenStorage
	AccessTokenLifespan  time.Duration
	RefreshTokenLifespan time.Duration
}

func (h *HandleHelper) IssueAccessToken(ctx context.Context, defaultLifespan time.Duration, requester fosite.AccessRequester, responder fosite.AccessResponder) error {
	token, signature, err := h.AccessTokenStrategy.GenerateAccessToken(ctx, requester)
	if err != nil {
		return err
	} else if err := h.AccessTokenStorage.CreateAccessTokenSession(ctx, signature, requester.Sanitize([]string{})); err != nil {
		return err
	}

	responder.SetAccessToken(token)
	responder.SetTokenType("bearer")
	responder.SetExpiresIn(getExpiresIn(requester, fosite.AccessToken, defaultLifespan, time.Now().UTC()))
	responder.SetScopes(requester.GetGrantedScopes())

	// Override: If Hydra Client defined an AccessToken TTL, use that.
	// Otherwise, let the expiry which was already set above.
	clientAccessTokenLifetime := time.Duration(requester.GetClient().GetAccessTokenTTL()) * time.Minute
	if clientAccessTokenLifetime > 0 {
		accessTokenExpiry := getExpiryDurationFromToken(token, clientAccessTokenLifetime)
		responder.SetExpiresIn(accessTokenExpiry)
	}

	return nil
}

func getExpiresIn(r fosite.Requester, key fosite.TokenType, defaultLifespan time.Duration, now time.Time) time.Duration {
	if r.GetSession().GetExpiresAt(key).IsZero() {
		return defaultLifespan
	}
	sessionDuration := time.Duration(r.GetSession().GetExpiresAt(key).UnixNano() - now.UnixNano())
	if defaultLifespan < sessionDuration {
		return defaultLifespan
	}
	return sessionDuration
}

func getExpiryDurationFromToken(tokenString string, defaultLifespan time.Duration) time.Duration{
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(tokenString, claims, func(accessToken *jwt.Token) (interface{}, error) {
		return "", nil
	})
	if err != nil {
		if claims == nil {
			return defaultLifespan
		}
	}

	iatClaim, ok := claims["iat"]
	if !ok {
		iatClaim = time.Now().UTC()
	}

	expClaim, ok := claims["exp"]
	if !ok {
		return defaultLifespan
	}

	iatUnix := time.Unix(int64(iatClaim.(float64)), int64(time.Second))
	expUnix := time.Unix(int64(expClaim.(float64)), int64(time.Second))

	tokenExpiryDuration := time.Duration(expUnix.UnixNano() - iatUnix.UnixNano())

	return tokenExpiryDuration

}

