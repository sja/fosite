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
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/fosite"
	"github.com/ory/fosite/internal"
)

func TestGetExpiresIn(t *testing.T) {
	now := time.Now().UTC()
	r := fosite.NewAccessRequest(&fosite.DefaultSession{
		ExpiresAt: map[fosite.TokenType]time.Time{
			fosite.AccessToken: now.Add(time.Hour),
		},
	})
	assert.Equal(t, time.Hour, getExpiresIn(r, fosite.AccessToken, time.Hour, now))
}

func TestIssueAccessToken(t *testing.T) {
	ctrl := gomock.NewController(t)
	areq := &fosite.AccessRequest{}
	aresp := &fosite.AccessResponse{Extra: map[string]interface{}{}}
	accessStrat := internal.NewMockAccessTokenStrategy(ctrl)
	accessStore := internal.NewMockAccessTokenStorage(ctrl)
	defer ctrl.Finish()

	helper := HandleHelper{
		AccessTokenStorage:  accessStore,
		AccessTokenStrategy: accessStrat,
		AccessTokenLifespan: time.Hour,
	}

	areq.Session = &fosite.DefaultSession{}
	areq.Client = &fosite.DefaultClient{
		GrantTypes:     fosite.Arguments{"authorization_code", "refresh_token"},
		AccessTokenTTL: 10,
	}
	for k, c := range []struct {
		mock func()
		err  error
	}{
		{
			mock: func() {
				accessStrat.EXPECT().GenerateAccessToken(nil, areq).Return("", "", errors.New(""))
			},
			err: errors.New(""),
		},
		{
			mock: func() {
				accessStrat.EXPECT().GenerateAccessToken(nil, areq).Return("token", "signature", nil)
				accessStore.EXPECT().CreateAccessTokenSession(nil, "signature", gomock.Eq(areq.Sanitize([]string{}))).Return(errors.New(""))
			},
			err: errors.New(""),
		},
		{
			mock: func() {
				accessStrat.EXPECT().GenerateAccessToken(nil, areq).Return("token", "signature", nil)
				accessStore.EXPECT().CreateAccessTokenSession(nil, "signature", gomock.Eq(areq.Sanitize([]string{}))).Return(nil)
			},
			err: nil,
		},
	} {
		c.mock()
		err := helper.IssueAccessToken(nil, helper.AccessTokenLifespan, areq, aresp)
		require.Equal(t, err == nil, c.err == nil)
		if c.err != nil {
			assert.EqualError(t, err, c.err.Error(), "Case %d", k)
		}
	}
}

func TestGetExpiryDurationFromToken(t *testing.T) {
	testParams := []struct{
		token string
		expiry time.Duration
	}{
		{
			token: "eyJhbGciOiJSUzI1NiIsImtpZCI6InB1YmxpYzpiZjVmOWVhMy02NWYwLTRhY2YtYTA5NS02YWFlZTJjYjdlNmMiLCJ0eXAiOiJKV1QifQ.eyJhdWQiOltdLCJhdXRob3JpdGllcyI6WyJST0xFX1ZPUldFUktDVVNUT01FUkdST1VQIl0sImNhdGFsb2dWZXJzaW9uIjoiT25saW5lIiwiY2xpZW50X2lkIjoib2lkYy1jbGllbnQ1IiwiY2xpZW50YXBwcm92ZWQiOnRydWUsImV4cCI6MTY0MTU1MTcxMCwiZXh0Ijp7ImF1dGhvcml0aWVzIjpbIlJPTEVfVk9SV0VSS0NVU1RPTUVSR1JPVVAiXSwiY2F0YWxvZ1ZlcnNpb24iOiJPbmxpbmUiLCJjbGllbnRhcHByb3ZlZCI6dHJ1ZSwibWFyY29zc191c2VyX3BrIjo5LjA3NzAyNDA2MzQ5MmUrMTIsInJpZCI6InJpZDEyMzQ1Njdxd2VydHkiLCJ1c2VyX25hbWUiOiJ1c2VyQGVtYWlsLmNvbSJ9LCJpYXQiOjE2NDE1NTE0MTAsImlzcyI6Imh0dHA6Ly8xMjcuMC4wLjE6NDQ0NC8iLCJqdGkiOiJmNDUyYjU5OC01NGQ0LTRmZGMtYTkwMy01ZmIwZGMxYTQzNDMiLCJtYXJjb3NzX3VzZXJfcGsiOjkuMDc3MDI0MDYzNDkyZSsxMiwibmJmIjoxNjQxNTUxNDEwLCJyaWQiOiJyaWQxMjM0NTY3cXdlcnR5Iiwic2NwIjpbIm9wZW5pZCIsImVtYWlsIiwicHJvZmlsZSIsIndlZWtseV9wbGFuZXIiLCJvZmZsaW5lIl0sInN1YiI6IjIiLCJ1c2VyX25hbWUiOiJ1c2VyQGVtYWlsLmNvbSJ9.ALQCS4OUYL-NNcRBw3vkQdk4cuAUX7uwuJoFkQuG8iLihC5VwShyXTzgBeoanRLCDcKkTXPnuDkQyzBrkxheIncno_pA23d33CWenpyVcX3zngpFnHz-1UjXmnUFx8uvZBNBClUhQZZ-EyqwGWcDeGEin1am5smUQgJyVkTvPUNdZgHRJ_JJpyMXp4KvKf85gNIBuJrKkFPu3o2lGbpZORO8uGrjBZEcAaCPsGbeR9rKUwLIXKdUbbVwxyP97eRgdyFJ5cgB0VYGcxTOtcUx2wd4MdwvRt5Itm5jQPx0niHiVjGG9D0BOWgZ7GEWDGMhZc-98uSq3eYbFg-k8HyVqA2RzFmjEHyNg44yHSLZBXF6nIvvtMOQbNYSoJNqzl1oveUX2IVsbD61zr7c-lXZvWvXuUlb2AG2DoJAZLwtLXmpTLv_35cHLMIMdkJDSB4HxXgg5uC3e4x0EOl-PShisKO6-yl8gBKEnga9NOJCbYRHFA2v7u6wQT9HgsVBeNjr0ySURKmVMOFIKlkXBzNpW6Sc4uORRHYDiwvfW3dNXXLl4xt6zVngkhD2uy7mjnQYX7lp4-aEdUIFAMhJvPM-NN9aUGiH1B90TuAgN72jrseVTYHL3SLcq9DLAAf_G67o5R9gjLSyYwRvoPADrdUxraVARui7sKyCAqGpLcdqWlk",
			expiry: time.Duration(300 * int64(time.Second)),
		}, {
			token: "eyJhbGciOiJSUzI1NiIsImtpZCI6InB1YmxpYzpiZjVmOWVhMy02NWYwLTRhY2YtYTA5NS02YWFlZTJjYjdlNmMiLCJ0eXAiOiJKV1QifQ.eyJhdWQiOltdLCJhdXRob3JpdGllcyI6WyJST0xFX1ZPUldFUktDVVNUT01FUkdST1VQIl0sImNhdGFsb2dWZXJzaW9uIjoiT25saW5lIiwiY2xpZW50X2lkIjoib2lkYy1jbGllbnQ1IiwiY2xpZW50YXBwcm92ZWQiOnRydWUsImV4cCI6MTY0MTU1NTIxNiwiZXh0Ijp7ImF1dGhvcml0aWVzIjpbIlJPTEVfVk9SV0VSS0NVU1RPTUVSR1JPVVAiXSwiY2F0YWxvZ1ZlcnNpb24iOiJPbmxpbmUiLCJjbGllbnRhcHByb3ZlZCI6dHJ1ZSwibWFyY29zc191c2VyX3BrIjo5LjA3NzAyNDA2MzQ5MmUrMTIsInJpZCI6InJpZDEyMzQ1Njdxd2VydHkiLCJ1c2VyX25hbWUiOiJ1c2VyQGVtYWlsLmNvbSJ9LCJpYXQiOjE2NDE1NTQzMTYsImlzcyI6Imh0dHA6Ly8xMjcuMC4wLjE6NDQ0NC8iLCJqdGkiOiIwMGY4NWQxNC0zNDlhLTRlYmMtYjkyOC04YjdkNTcwNTRhMmIiLCJtYXJjb3NzX3VzZXJfcGsiOjkuMDc3MDI0MDYzNDkyZSsxMiwibmJmIjoxNjQxNTU0MzE2LCJyaWQiOiJyaWQxMjM0NTY3cXdlcnR5Iiwic2NwIjpbIm9wZW5pZCIsImVtYWlsIiwicHJvZmlsZSIsIndlZWtseV9wbGFuZXIiLCJvZmZsaW5lIl0sInN1YiI6IjIiLCJ1c2VyX25hbWUiOiJ1c2VyQGVtYWlsLmNvbSJ9.gSqzJoXtAjyGGLFOrbkdlTxDlegugjNu7-erXdsVMknCT-G23ULjz2XNWcJV-vE6l1n3HbSAoJs1LeISCT9a3tG4ysgA55NQv4pJI-IpRKS6fWZPgi7x1pUeUMKpMgQBQ4AOMkP3_QHWlflB3z0Zh5OTJa0RgC9sH491S55vw5_M9ReEHTlnexE5nFUWwZsKuuQFQeslw1Yrw7Emi5U3IsInS2oCfDTd6MYfCJgq_Uk8FMLfEn3vSaXJ_CAH4_6nI5y-iCzo36mSiaxXVi_jghtceNGmDAXuvh-skL8fOk0Jtuxxzoyt063O85wZw7ZJspKeDhHjWeBwQ6ij4hrRWTf17eA8O5muy0ijanejbC0Mt4xqTN-YywFwJIzZ9Lot2bgCiuKCEAEfdRJJ_EDMDbDtGBcz_5CB2wmCJsUqKZ0nEVCoI6H7jIbh0vX1-Ziv4Y0gnmCBg5_z8IVLAdMhm27pYk7T2uC6b5jrQV-WLXwj5pIozA1jnURCkIVZjtmfoXfBHQu_xmdkIlzNf_3T2moEpbxx3E_IYXs18lE7Ua193ef4fTWDHeTdC1HXoTmHQNlFctQZ8lnXGRriwuoxyE6Efg1DMT7ipaiQ3QI99MccZgyES0Ve7Z2Hu96ea-CxGU2zJSqPQoDyuuR1vOgt7S6giAQPFFSgwk3ewcYP5Xw",
			expiry: time.Duration(900 * int64(time.Second)),
		},
	}

	for _, testCase := range testParams {
		tokenExpiryDuration := getExpiryDurationFromToken(testCase.token, time.Duration(5 * int64(time.Minute)),)
		if tokenExpiryDuration != testCase.expiry {
			t.Errorf("Expiry duration not matched.")
		}
	}

}
