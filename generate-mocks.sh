#!/bin/bash

mockgen -package internal -destination internal/hash.go  gitlab.tmecosys.net/nwot/cross-functional/auth/authentication-manager/fosite Hasher
mockgen -package internal -destination internal/storage.go  gitlab.tmecosys.net/nwot/cross-functional/auth/authentication-manager/fosite Storage
mockgen -package internal -destination internal/transactional.go  gitlab.tmecosys.net/nwot/cross-functional/auth/authentication-manager/fosite/storage Transactional
mockgen -package internal -destination internal/oauth2_storage.go  gitlab.tmecosys.net/nwot/cross-functional/auth/authentication-manager/fosite/handler/oauth2 CoreStorage
mockgen -package internal -destination internal/oauth2_strategy.go  gitlab.tmecosys.net/nwot/cross-functional/auth/authentication-manager/fosite/handler/oauth2 CoreStrategy
mockgen -package internal -destination internal/authorize_code_storage.go  gitlab.tmecosys.net/nwot/cross-functional/auth/authentication-manager/fosite/handler/oauth2 AuthorizeCodeStorage
mockgen -package internal -destination internal/oauth2_auth_jwt_storage.go  gitlab.tmecosys.net/nwot/cross-functional/auth/authentication-manager/fosite/handler/rfc7523 RFC7523KeyStorage
mockgen -package internal -destination internal/access_token_storage.go  gitlab.tmecosys.net/nwot/cross-functional/auth/authentication-manager/fosite/handler/oauth2 AccessTokenStorage
mockgen -package internal -destination internal/refresh_token_strategy.go  gitlab.tmecosys.net/nwot/cross-functional/auth/authentication-manager/fosite/handler/oauth2 RefreshTokenStorage
mockgen -package internal -destination internal/oauth2_client_storage.go  gitlab.tmecosys.net/nwot/cross-functional/auth/authentication-manager/fosite/handler/oauth2 ClientCredentialsGrantStorage
mockgen -package internal -destination internal/oauth2_owner_storage.go  gitlab.tmecosys.net/nwot/cross-functional/auth/authentication-manager/fosite/handler/oauth2 ResourceOwnerPasswordCredentialsGrantStorage
mockgen -package internal -destination internal/oauth2_revoke_storage.go  gitlab.tmecosys.net/nwot/cross-functional/auth/authentication-manager/fosite/handler/oauth2 TokenRevocationStorage
mockgen -package internal -destination internal/openid_id_token_storage.go  gitlab.tmecosys.net/nwot/cross-functional/auth/authentication-manager/fosite/handler/openid OpenIDConnectRequestStorage
mockgen -package internal -destination internal/access_token_strategy.go  gitlab.tmecosys.net/nwot/cross-functional/auth/authentication-manager/fosite/handler/oauth2 AccessTokenStrategy
mockgen -package internal -destination internal/refresh_token_strategy.go  gitlab.tmecosys.net/nwot/cross-functional/auth/authentication-manager/fosite/handler/oauth2 RefreshTokenStrategy
mockgen -package internal -destination internal/authorize_code_strategy.go  gitlab.tmecosys.net/nwot/cross-functional/auth/authentication-manager/fosite/handler/oauth2 AuthorizeCodeStrategy
mockgen -package internal -destination internal/id_token_strategy.go  gitlab.tmecosys.net/nwot/cross-functional/auth/authentication-manager/fosite/handler/openid OpenIDConnectTokenStrategy
mockgen -package internal -destination internal/pkce_storage_strategy.go  gitlab.tmecosys.net/nwot/cross-functional/auth/authentication-manager/fosite/handler/pkce PKCERequestStorage
mockgen -package internal -destination internal/authorize_handler.go  gitlab.tmecosys.net/nwot/cross-functional/auth/authentication-manager/fosite AuthorizeEndpointHandler
mockgen -package internal -destination internal/revoke_handler.go  gitlab.tmecosys.net/nwot/cross-functional/auth/authentication-manager/fosite RevocationHandler
mockgen -package internal -destination internal/token_handler.go  gitlab.tmecosys.net/nwot/cross-functional/auth/authentication-manager/fosite TokenEndpointHandler
mockgen -package internal -destination internal/introspector.go  gitlab.tmecosys.net/nwot/cross-functional/auth/authentication-manager/fosite TokenIntrospector
mockgen -package internal -destination internal/client.go  gitlab.tmecosys.net/nwot/cross-functional/auth/authentication-manager/fosite Client
mockgen -package internal -destination internal/request.go  gitlab.tmecosys.net/nwot/cross-functional/auth/authentication-manager/fosite Requester
mockgen -package internal -destination internal/access_request.go  gitlab.tmecosys.net/nwot/cross-functional/auth/authentication-manager/fosite AccessRequester
mockgen -package internal -destination internal/access_response.go  gitlab.tmecosys.net/nwot/cross-functional/auth/authentication-manager/fosite AccessResponder
mockgen -package internal -destination internal/authorize_request.go  gitlab.tmecosys.net/nwot/cross-functional/auth/authentication-manager/fosite AuthorizeRequester
mockgen -package internal -destination internal/authorize_response.go  gitlab.tmecosys.net/nwot/cross-functional/auth/authentication-manager/fosite AuthorizeResponder

goimports -w internal/