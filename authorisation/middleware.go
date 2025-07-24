package authorisation

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/ONSdigital/dp-api-clients-go/v2/headers"
	"github.com/ONSdigital/dp-authorisation/v2/identityclient"
	"github.com/ONSdigital/dp-authorisation/v2/jwt"
	"github.com/ONSdigital/dp-authorisation/v2/permissions"
	"github.com/ONSdigital/dp-authorisation/v2/zebedeeclient"
	health "github.com/ONSdigital/dp-healthcheck/healthcheck"
	"github.com/ONSdigital/dp-net/v3/request"
	permsdk "github.com/ONSdigital/dp-permissions-api/sdk"
	"github.com/ONSdigital/log.go/v2/log"
)

const (
	collectionIDAttributeKey = "collection_id"
	IdentityClientError      = "identity client cannot be nil"
)

// PermissionCheckMiddleware is used to wrap HTTP handlers with JWT token based authorisation
type PermissionCheckMiddleware struct {
	jwtParser          JWTParser
	permissionsChecker PermissionsChecker
	zebedeeClient      ZebedeeClient
	IdentityClient     *identityclient.IdentityClient
}

// GetAttributesFromRequest defines the func that retrieves and returns attributes from the request. Used by
// RequireWithAttributes. Use an implementation provided within this package or alternatively use a custom
// implementation that meets your requirements.
type GetAttributesFromRequest func(req *http.Request) (attributes map[string]string, err error)

// NewFeatureFlaggedMiddleware returns a different Middleware implementation depending on the configured feature flag value
// Use this constructor when first adding authorisation as middleware so that it can be toggled off if required.
func NewFeatureFlaggedMiddleware(ctx context.Context, config *Config, jwtRSAPublicKeys map[string]string) (Middleware, error) {
	if config.Enabled {
		return NewMiddlewareFromConfig(ctx, config, jwtRSAPublicKeys)
	}
	return NewNoopMiddleware(), nil
}

// NewMiddlewareFromDependencies creates a new instance of PermissionCheckMiddleware, using injected dependencies
func NewMiddlewareFromDependencies(jwtParser JWTParser, permissionsChecker PermissionsChecker, zebedeeClient ZebedeeClient, identityClient *identityclient.IdentityClient) *PermissionCheckMiddleware {
	return &PermissionCheckMiddleware{
		jwtParser:          jwtParser,
		permissionsChecker: permissionsChecker,
		zebedeeClient:      zebedeeClient,
		IdentityClient:     identityClient,
	}
}

// NewMiddlewareFromConfig creates a new instance of PermissionCheckMiddleware, instantiating the required dependencies from
// the given configuration values.
//
// This constructor uses default dependencies - the Cognito specific JWT parser, caching permissions checker and JWT RSA public signing keys (optional)
// If different dependencies are required, use the NewMiddlewareFromDependencies constructor.
func NewMiddlewareFromConfig(ctx context.Context, config *Config, jwtRSAPublicKeys map[string]string) (*PermissionCheckMiddleware, error) {
	// identity client retrieves jwt keys from identity service
	identityClient, err := identityclient.NewIdentityClient(config.IdentityWebKeySetURL, config.IdentityClientMaxRetries)
	if err != nil {
		return nil, err
	}

	// get the JWT verification keys - from identity service initially
	if jwtRSAPublicKeys != nil {
		identityClient.JWTKeys = jwtRSAPublicKeys
	} else {
		err = identityClient.GetJWTVerificationKeys(ctx)
		if err != nil {
			return nil, err
		}
	}

	jwtParser, err := NewCognitoRSAParser(identityClient.JWTKeys)
	if err != nil {
		return nil, err
	}
	identityClient.CognitoRSAParser = jwtParser

	permissionsChecker := permissions.NewChecker(
		ctx,
		config.PermissionsAPIURL,
		config.PermissionsCacheUpdateInterval,
		config.PermissionsMaxCacheTime,
	)

	zebedeeClient := zebedeeclient.NewZebedeeClient(config.ZebedeeURL)

	return NewMiddlewareFromDependencies(jwtParser, permissionsChecker, zebedeeClient, identityClient), nil
}

// NewCognitoRSAParser returns a CognitoRSAParser with correct RSA Public Signing Keys set
func NewCognitoRSAParser(identityClientKeys map[string]string) (*jwt.CognitoRSAParser, error) {
	return jwt.NewCognitoRSAParser(identityClientKeys)
}

// RequireWithAttributes wraps an existing handler, only allowing it to be called if the request is
// authorised against the given permission. Includes any attributes returned by getAttributes in the permission check.
func (m PermissionCheckMiddleware) RequireWithAttributes(permission string, handlerFunc http.HandlerFunc, getAttributes GetAttributesFromRequest) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		ctx := req.Context()
		logData := log.Data{
			"url":        req.URL.String(),
			"permission": permission,
		}

		authToken := req.Header.Get("Authorization")
		if authToken == "" {
			log.Info(ctx, "authorisation failed: no authorisation header in request", logData)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		authToken = strings.TrimPrefix(authToken, "Bearer ")

		// process the token accordingly
		var (
			entityData              = &permsdk.EntityData{}
			zebedeeIdentityResponse = &request.IdentityResponse{}
			err                     error
		)
		if strings.Contains(authToken, ".") {
			entityData, err = m.jwtParser.Parse(authToken)
			if err != nil {
				if errors.Is(err, jwt.ErrPublickeysEmpty) {
					log.Error(ctx, "no public keys", err)
					w.WriteHeader(http.StatusInternalServerError)
				} else {
					logData["message"] = err.Error()
					log.Error(ctx, "authorisation failed: unable to parse jwt", err, logData)
					w.WriteHeader(http.StatusUnauthorized)
				}
				return
			}
		} else {
			zebedeeIdentityResponse, err = m.zebedeeClient.CheckTokenIdentity(ctx, authToken)
			if err != nil {
				logData["message"] = err.Error()
				log.Error(ctx, "authorisation failed: service token issue", err, logData)
				w.WriteHeader(http.StatusForbidden)
				return
			}
			// extract user name and proceed
			entityData.UserID = zebedeeIdentityResponse.Identifier
		}

		var attributes map[string]string
		if getAttributes != nil {
			attributes, err = getAttributes(req)
			if err != nil {
				log.Error(ctx, "authorisation failed: request attributes retrieval error", err, logData)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
		}

		hasPermission, err := m.permissionsChecker.HasPermission(req.Context(), *entityData, permission, attributes)
		if err != nil {
			log.Error(ctx, "authorisation failed: permissions lookup error", err, logData)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		if !hasPermission {
			log.Info(ctx, "authorisation failed: request has no permission", logData)
			w.WriteHeader(http.StatusForbidden)
			return
		}

		handlerFunc(w, req)
	}
}

// Require wraps an existing handler, only allowing it to be called if the request is
// authorised against the given permission. Calls method RequireWithAttributes() with nil getAttributes
func (m PermissionCheckMiddleware) Require(permission string, handlerFunc http.HandlerFunc) http.HandlerFunc {
	return m.RequireWithAttributes(permission, handlerFunc, GetCollectionIDAttribute)
}

// Close resources used by the middleware.
func (m PermissionCheckMiddleware) Close(ctx context.Context) error {
	return m.permissionsChecker.Close(ctx)
}

// HealthCheck updates the health status of the permissions checker
func (m PermissionCheckMiddleware) HealthCheck(ctx context.Context, state *health.CheckState) error {
	return m.permissionsChecker.HealthCheck(ctx, state)
}

// IdentityHealthCheck updates the health status of the jwt keys request against identity api
func (m PermissionCheckMiddleware) IdentityHealthCheck(ctx context.Context, state *health.CheckState) error {
	return m.IdentityClient.IdentityHealthCheck(ctx, state)
}

// Parse token using returned Parser object
func (m PermissionCheckMiddleware) Parse(token string) (*permsdk.EntityData, error) {
	return m.jwtParser.Parse(token)
}

// GetCollectionIdAttribute provides an implementation of GetAttributesFromRequest. Retrieves and returns
// header 'Collection-Id' from the request if it exists, otherwise returns an empty map.
// It may return an error only if the header cannot be retrieved by some other reason (e.g. nil request).
func GetCollectionIDAttribute(req *http.Request) (map[string]string, error) {
	attributes := make(map[string]string, 0)

	collectionIDAttribute, err := headers.GetCollectionID(req)
	if err != nil {
		if err == headers.ErrHeaderNotFound {
			// empty header is allowed (no value returned in attributes map for CollectionID)
			return attributes, nil
		}
		// any other error must be returned
		return nil, fmt.Errorf("error getting Collection-Id header from request: %w", err)
	}

	attributes[collectionIDAttributeKey] = collectionIDAttribute
	return attributes, nil
}
