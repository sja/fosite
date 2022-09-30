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
 * @author    Aeneas Rekkas <aeneas+oss@aeneas.io>
 * @copyright   2015-2018 Aeneas Rekkas <aeneas+oss@aeneas.io>
 * @license   Apache-2.0
 *
 */

package oauth2

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/opentracing/opentracing-go"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
	"time"

	uuid "github.com/satori/go.uuid"

	fosite_jwt "github.com/ory/fosite/token/jwt"

	"github.com/dgrijalva/jwt-go"
	"github.com/ory/x/errorsx"

	"github.com/pkg/errors"

	"github.com/ory/fosite"
	"github.com/ory/fosite/storage"
)

type RefreshTokenGrantHandler struct {
	AccessTokenStrategy    AccessTokenStrategy
	RefreshTokenStrategy   RefreshTokenStrategy
	TokenRevocationStorage TokenRevocationStorage

	// AccessTokenLifespan defines the lifetime of an access token.
	AccessTokenLifespan time.Duration

	// RefreshTokenLifespan defines the lifetime of a refresh token.
	RefreshTokenLifespan time.Duration

	ScopeStrategy            fosite.ScopeStrategy
	AudienceMatchingStrategy fosite.AudienceMatchingStrategy
	RefreshTokenScopes       []string
}

// HandleTokenEndpointRequest implements https://tools.ietf.org/html/rfc6749#section-6
func (c *RefreshTokenGrantHandler) HandleTokenEndpointRequest(ctx context.Context, request fosite.AccessRequester) error {
	if !c.CanHandleTokenEndpointRequest(request) {
		return errorsx.WithStack(fosite.ErrUnknownRequest)
	}

	if !request.GetClient().GetGrantTypes().Has("refresh_token") {
		return errorsx.WithStack(fosite.ErrInvalidGrant.WithHint("Wrong client for this refresh token."))
	}

	refresh := request.GetRequestForm().Get("refresh_token")
	signature := c.RefreshTokenStrategy.RefreshTokenSignature(refresh)

	originalRequest, err := c.TokenRevocationStorage.GetRefreshTokenSession(ctx, signature, request.GetSession())
	/*
		// VN-78222 Token Reuse Handling was disabled because we have many concurrent request to hydra from concurrent calls
		issued by Browsers and ssi.
		if errors.Is(err, fosite.ErrInactiveToken) {
			// Detected refresh token reuse
			if rErr := c.handleRefreshTokenReuse(ctx, signature, originalRequest); rErr != nil {
				return errorsx.WithStack(fosite.ErrServerError.WithWrap(rErr).WithDebug(rErr.Error()))
			}

			return errorsx.WithStack(fosite.ErrInactiveToken.WithWrap(err).WithDebug(err.Error()))
		} */
	if errors.Is(err, fosite.ErrInactiveToken) {
		traceHandlingResult(ctx, "reused-ignored")
		err = nil // Fast forward to c.RefreshTokenStrategy.ValidateRefreshToken
	}
	if errors.Is(err, fosite.ErrNotFound) {
		//return errorsx.WithStack(fosite.ErrInvalidGrant.WithWrap(err).WithDebugf("The refresh token has not been found: %s", err.Error()))
		traceHandlingResult(ctx, "not-found")
		return c.validateAcRefreshtoken(ctx, refresh, request)
	} else if err != nil {
		traceHandlingResult(ctx, "unhandled-error")
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	} else if err := c.RefreshTokenStrategy.ValidateRefreshToken(ctx, originalRequest, refresh); err != nil {
		// The authorization server MUST ... validate the refresh token.
		// This needs to happen after store retrieval for the session to be hydrated properly
		if errors.Is(err, fosite.ErrTokenExpired) {
			traceHandlingResult(ctx, "expired")
			return errorsx.WithStack(fosite.ErrInvalidGrant.WithWrap(err).WithDebug(err.Error()))
		}
		traceHandlingResult(ctx, "validate failed")
		return errorsx.WithStack(fosite.ErrInvalidRequest.WithWrap(err).WithDebug(err.Error()))
	}

	if !(len(c.RefreshTokenScopes) == 0 || originalRequest.GetGrantedScopes().HasOneOf(c.RefreshTokenScopes...)) {
		scopeNames := strings.Join(c.RefreshTokenScopes, " or ")
		hint := fmt.Sprintf("The OAuth 2.0 Client was not granted scope %s and may thus not perform the 'refresh_token' authorization grant.", scopeNames)
		traceHandlingResult(ctx, "refresh scope not granted")
		return errorsx.WithStack(fosite.ErrScopeNotGranted.WithHint(hint))

	}

	// The authorization server MUST ... and ensure that the refresh token was issued to the authenticated client
	if originalRequest.GetClient().GetID() != request.GetClient().GetID() {
		traceHandlingResult(ctx, "Client does not match")
		return errorsx.WithStack(fosite.ErrInvalidGrant.WithHint("The OAuth 2.0 Client ID from this request does not match the ID during the initial token issuance."))
	}

	request.SetSession(originalRequest.GetSession().Clone())
	request.SetRequestedScopes(originalRequest.GetRequestedScopes())
	request.SetRequestedAudience(originalRequest.GetRequestedAudience())

	for _, scope := range originalRequest.GetGrantedScopes() {
		if !c.ScopeStrategy(request.GetClient().GetScopes(), scope) {
			traceHandlingResult(ctx, "scope not allowed by client")
			return errorsx.WithStack(fosite.ErrInvalidScope.WithHintf("The OAuth 2.0 Client is not allowed to request scope '%s'.", scope))
		}
		request.GrantScope(scope)
	}

	if err := c.AudienceMatchingStrategy(request.GetClient().GetAudience(), originalRequest.GetGrantedAudience()); err != nil {
		traceHandlingResult(ctx, "audience does not match")
		return err
	}

	for _, audience := range originalRequest.GetGrantedAudience() {
		request.GrantAudience(audience)
	}

	atLifespan := fosite.GetEffectiveLifespan(request.GetClient(), fosite.GrantTypeRefreshToken, fosite.AccessToken, c.AccessTokenLifespan)
	request.GetSession().SetExpiresAt(fosite.AccessToken, time.Now().UTC().Add(atLifespan).Round(time.Second))

	rtLifespan := fosite.GetEffectiveLifespan(request.GetClient(), fosite.GrantTypeRefreshToken, fosite.RefreshToken, c.RefreshTokenLifespan)
	if rtLifespan > -1 {
		request.GetSession().SetExpiresAt(fosite.RefreshToken, time.Now().UTC().Add(rtLifespan).Round(time.Second))
	}
	traceHandlingResult(ctx, "success")
	return nil
}

func traceHandlingResult(ctx context.Context, s string) {
	amendSpan(ctx, "refresh_token", s)
}

func amendSpan(ctx context.Context, key, value string) {
	existingSpan := opentracing.SpanFromContext(ctx)
	if existingSpan != nil {
		existingSpan.SetTag(key, value)
	}
}

func (c *RefreshTokenGrantHandler) validateAcRefreshtoken(ctx context.Context, token string, request fosite.AccessRequester) error {
	var headers map[string]interface{}
	var rfClaims *jwt.MapClaims
	var auth []string
	_, err := jwt.ParseWithClaims(token, new(jwt.MapClaims), func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, errors.Errorf("Unexpected signing method: %v", t.Header["alg"])
		}

		claims, ok := t.Claims.(*jwt.MapClaims)
		if !ok {
			return nil, errors.New("cannot parse token claims")
		}

		if !claims.VerifyExpiresAt(time.Now().Unix(), false) {
			return nil, errors.New("token expired")
		}

		authClaims := *claims
		authInterface := authClaims["authorities"].([]interface{})
		authSize := len(authInterface)
		auth = make([]string, authSize)
		for i, v := range authInterface {
			auth[i] = v.(string)
		}
		publicKeyPath := os.Getenv("PUBLIC_KEY_PATH")
		dat, err := ioutil.ReadFile(publicKeyPath)
		if err != nil {
			return nil, err
		}

		verifyKey, err := jwt.ParseRSAPublicKeyFromPEM(dat)
		if err != nil {
			return nil, errors.New("cannot parse public key")
		}
		headers = t.Header
		rfClaims, ok = t.Claims.(*jwt.MapClaims)
		if !ok {
			return nil, errors.New(fmt.Sprintf("Cannot parse claims %T", t.Claims))
		}
		request.GrantScope("offline")
		return verifyKey, nil
	})
	if err != nil {
		traceHandlingResult(ctx, "not-found: invalid")
		return errorsx.WithStack(fosite.ErrInvalidTokenFormat.WithWrap(err).WithDebugf("Cannot convert access token to JSON"))
	}

	// We add Issuer and expire date
	if iss, ok := (*rfClaims)["iss"].(string); ok {
		amendSpan(ctx, "issuer", iss)
	} else {
		amendSpan(ctx, "issuer", "not given - perhaps marCoSS")
	}

	switch exp := (*rfClaims)["exp"].(type) {
	case float64:
		amendSpan(ctx, "exp", strconv.FormatInt(int64(exp), 10))
	case json.Number:
		amendSpan(ctx, "exp", exp.String())
	}

	switch iat := (*rfClaims)["iat"].(type) {
	case float64:
		amendSpan(ctx, "iat", strconv.FormatInt(int64(iat), 10))
	case json.Number:
		amendSpan(ctx, "iat", iat.String())
	}

	switch authTime := (*rfClaims)["auth_time"].(type) {
	case float64:
		amendSpan(ctx, "auth_time", strconv.FormatInt(int64(authTime), 10))
	case json.Number:
		amendSpan(ctx, "auth_time", authTime.String())
	}

	// Create a new session as there is not original request in hydra becouse original request were created in account web
	claims := fosite_jwt.JWTClaims{
		Audience:    []string{},
		Issuer:      os.Getenv("URLS_SELF_ISSUER"),
		IssuedAt:    time.Now().UTC(),
		NotBefore:   time.Now().UTC(),
		Authorities: auth,
	}

	session := &JWTSession{
		JWTClaims: &claims,
		JWTHeader: &fosite_jwt.Headers{
			Extra: headers,
		},
		ExpiresAt: map[fosite.TokenType]time.Time{
			fosite.RefreshToken: time.Now().UTC().Add(c.RefreshTokenLifespan).Round(time.Second),
		},
	}
	if sub, ok := (*rfClaims)["sub"].(string); ok {
		session.Subject = sub
	}
	traceHandlingResult(ctx, "not-found: success")
	request.SetSession(session)
	return nil
}

// PopulateTokenEndpointResponse implements https://tools.ietf.org/html/rfc6749#section-6
func (c *RefreshTokenGrantHandler) PopulateTokenEndpointResponse(ctx context.Context, requester fosite.AccessRequester, responder fosite.AccessResponder) (err error) {
	if !c.CanHandleTokenEndpointRequest(requester) {
		return errorsx.WithStack(fosite.ErrUnknownRequest)
	}

	atLifespan := fosite.GetEffectiveLifespan(requester.GetClient(), fosite.GrantTypeRefreshToken, fosite.AccessToken, c.AccessTokenLifespan)
	requester.GetSession().SetExpiresAt(fosite.TokenType("access_token"), time.Now().UTC().Add(atLifespan).Round(time.Second))
	accessToken, accessSignature, err := c.AccessTokenStrategy.GenerateAccessToken(ctx, requester)
	if err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	refreshToken, refreshSignature, err := c.RefreshTokenStrategy.GenerateRefreshToken(ctx, requester)
	if err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	signature := c.RefreshTokenStrategy.RefreshTokenSignature(requester.GetRequestForm().Get("refresh_token"))

	ctx, err = storage.MaybeBeginTx(ctx, c.TokenRevocationStorage)
	if err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}
	defer func() {
		err = c.handleRefreshTokenEndpointStorageError(ctx, err)
	}()

	/* TODO; put it back after migration. Until that error will not be returned as those migh be because
	tokens migth be issued by account web then we cannot revoke the tokens are they are not presented in hydra
	database... We keep the revoke invokations for tokens issued in migrated verticals by hydra
	*/
	ts, err := c.TokenRevocationStorage.GetRefreshTokenSession(ctx, signature, nil)
	if err != nil {
		// return c.handleRefreshTokenEndpointStorageError(ctx, true, err)
	} else if err := c.TokenRevocationStorage.RevokeAccessToken(ctx, ts.GetID()); err != nil {
		// return c.handleRefreshTokenEndpointStorageError(ctx, true, err)
	} else if err := c.TokenRevocationStorage.RevokeRefreshTokenMaybeGracePeriod(ctx, ts.GetID(), signature); err != nil {
		// return c.handleRefreshTokenEndpointStorageError(ctx, true, err)
	}

	storeReq := requester.Sanitize([]string{})

	// TODO Adjust after migration. when ts is nil it is becaouse the refrest token was issued by account then we set some id in the request
	storeReq.SetID(uuid.NewV4().String())
	if ts != nil {
		storeReq.SetID(ts.GetID())
	}

	if err = c.TokenRevocationStorage.CreateAccessTokenSession(ctx, accessSignature, storeReq); err != nil {
		return err
	}

	if err = c.TokenRevocationStorage.CreateRefreshTokenSession(ctx, refreshSignature, storeReq); err != nil {
		return err
	}

	responder.SetAccessToken(accessToken)
	responder.SetTokenType("bearer")
	atLifespan = fosite.GetEffectiveLifespan(requester.GetClient(), fosite.GrantTypeRefreshToken, fosite.AccessToken, c.AccessTokenLifespan)
	atLifespan = getExpiryDurationFromToken(accessToken, atLifespan)
	responder.SetExpiresIn(getExpiresIn(requester, fosite.AccessToken, atLifespan, time.Now().UTC()))
	responder.SetScopes(requester.GetGrantedScopes())
	responder.SetExtra("refresh_token", refreshToken)

	if err = storage.MaybeCommitTx(ctx, c.TokenRevocationStorage); err != nil {
		return err
	}

	return nil
}

// Reference: https://tools.ietf.org/html/rfc6819#section-5.2.2.3
//
//	The basic idea is to change the refresh token
//	value with every refresh request in order to detect attempts to
//	obtain access tokens using old refresh tokens.  Since the
//	authorization server cannot determine whether the attacker or the
//	legitimate client is trying to access, in case of such an access
//	attempt the valid refresh token and the access authorization
//	associated with it are both revoked.
func (c *RefreshTokenGrantHandler) handleRefreshTokenReuse(ctx context.Context, signature string, req fosite.Requester) (err error) {
	ctx, err = storage.MaybeBeginTx(ctx, c.TokenRevocationStorage)
	if err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}
	defer func() {
		err = c.handleRefreshTokenEndpointStorageError(ctx, err)
	}()

	if err = c.TokenRevocationStorage.DeleteRefreshTokenSession(ctx, signature); err != nil {
		return err
	} else if err = c.TokenRevocationStorage.RevokeRefreshToken(
		ctx, req.GetID(),
	); err != nil && !errors.Is(err, fosite.ErrNotFound) {
		return err
	} else if err = c.TokenRevocationStorage.RevokeAccessToken(
		ctx, req.GetID(),
	); err != nil && !errors.Is(err, fosite.ErrNotFound) {
		return err
	}

	if err = storage.MaybeCommitTx(ctx, c.TokenRevocationStorage); err != nil {
		return err
	}

	return nil
}

func (c *RefreshTokenGrantHandler) handleRefreshTokenEndpointStorageError(ctx context.Context, storageErr error) (err error) {
	if storageErr == nil {
		return nil
	}

	defer func() {
		if rollBackTxnErr := storage.MaybeRollbackTx(ctx, c.TokenRevocationStorage); rollBackTxnErr != nil {
			err = errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebugf("error: %s; rollback error: %s", err, rollBackTxnErr))
		}
	}()

	if errors.Is(storageErr, fosite.ErrSerializationFailure) {
		return errorsx.WithStack(fosite.ErrInvalidRequest.
			WithDebugf(storageErr.Error()).
			WithHint("Failed to refresh token because of multiple concurrent requests using the same token which is not allowed."))
	}

	if errors.Is(storageErr, fosite.ErrNotFound) || errors.Is(storageErr, fosite.ErrInactiveToken) {
		return errorsx.WithStack(fosite.ErrInvalidRequest.
			WithDebugf(storageErr.Error()).
			WithHint("Failed to refresh token because of multiple concurrent requests using the same token which is not allowed."))
	}

	return errorsx.WithStack(fosite.ErrServerError.WithWrap(storageErr).WithDebug(storageErr.Error()))
}

func (c *RefreshTokenGrantHandler) CanSkipClientAuth(requester fosite.AccessRequester) bool {
	return false
}

func (c *RefreshTokenGrantHandler) CanHandleTokenEndpointRequest(requester fosite.AccessRequester) bool {
	// grant_type REQUIRED.
	// Value MUST be set to "refresh_token".
	return requester.GetGrantTypes().ExactOne("refresh_token")
}
