package authorisation

import (
	"context"
	"net/http"
	"strings"

	"github.com/ONSdigital/dp-authorisation/v2/jwt"
	"github.com/ONSdigital/dp-authorisation/v2/permissions"
	"github.com/ONSdigital/dp-authorisation/v2/zebedeeclient"
	health "github.com/ONSdigital/dp-healthcheck/healthcheck"
	"github.com/ONSdigital/log.go/v2/log"

	b64 "encoding/base64"
	"encoding/json"
)

type tokenHeaderData struct{
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

// PermissionCheckMiddleware is used to wrap HTTP handlers with JWT token based authorisation
type PermissionCheckMiddleware struct {
	jwtParser          JWTParser
	permissionsChecker PermissionsChecker
	zebedeeClient      ZebedeeClient
}

// NewFeatureFlaggedMiddleware returns a different Middleware implementation depending on the configured feature flag value
// Use this constructor when first adding authorisation as middleware so that it can be toggled off if required.
func NewFeatureFlaggedMiddleware(ctx context.Context, config *Config) (Middleware, error) {
	if config.Enabled {
		return NewMiddlewareFromConfig(ctx, config)
	}

	return NewNoopMiddleware(), nil
}

// NewMiddlewareFromDependencies creates a new instance of PermissionCheckMiddleware, using injected dependencies
func NewMiddlewareFromDependencies(jwtParser JWTParser, permissionsChecker PermissionsChecker, zebedeeClient ZebedeeClient) *PermissionCheckMiddleware {
	return &PermissionCheckMiddleware{
		jwtParser:          jwtParser,
		permissionsChecker: permissionsChecker,
		zebedeeClient:      zebedeeClient,
	}
}

// NewMiddlewareFromConfig creates a new instance of PermissionCheckMiddleware, instantiating the required dependencies from
// the given configuration values.
//
// This constructor uses default dependencies - the Cognito specific JWT parser, and caching permissions checker.
// If different dependencies are required, use the NewMiddlewareFromDependencies constructor.
func NewMiddlewareFromConfig(ctx context.Context, config *Config) (*PermissionCheckMiddleware, error) {
	jwtParser, err := jwt.NewCognitoRSAParser(config.JWTVerificationPublicKeys)
	if err != nil {
		return nil, err
	}

	permissionsChecker := permissions.NewChecker(
		ctx,
		config.PermissionsAPIURL,
		config.PermissionsCacheUpdateInterval,
		config.PermissionsCacheExpiryCheckInterval,
		config.PermissionsMaxCacheTime,
	)

	zebedeeClient := zebedeeclient.NewZebedeeClient(config.ZebedeeURL)

	return NewMiddlewareFromDependencies(jwtParser, permissionsChecker, zebedeeClient), nil
}

// Require wraps an existing handler, only allowing it to be called if the request is
// authorised against the given permission.
func (m PermissionCheckMiddleware) Require(permission string, handlerFunc http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		ctx := req.Context()
		logData := log.Data{
			"url":        req.URL.String(),
			"permission": permission,
		}

		authToken := req.Header.Get("Authorization")
		if len(authToken) == 0 {
			log.Info(ctx, "authorisation failed due to no authorisation header being in the request", logData)
			w.WriteHeader(http.StatusForbidden)
			return
		}

		authToken = strings.TrimPrefix(authToken, "Bearer ")

		// is the token of the form xxx.yyy.zzz (i.e. JWT)?
		sDec, _ := b64.StdEncoding.DecodeString(strings.Split(authToken, ".")[0])

		var headerData = tokenHeaderData{}
		json.Unmarshal(sDec, &headerData)

		var (
			entityData = &permissions.EntityData{}
			err error
		)
		if headerData.Typ == "JWT" {
			entityData, err = m.jwtParser.Parse(authToken)
			if err != nil {
				logData["message"] = err.Error()
				log.Info(ctx, "authorisation failed due to jwt parsing issue", logData)
				w.WriteHeader(http.StatusForbidden) 
				return
			}
		} else {
			zebedeeIdentityResponse, err := m.zebedeeClient.CheckTokenIdentity(ctx, authToken)
			if err != nil {
				logData["message"] = err.Error()
				log.Info(ctx, "authorisation failed due to service token issue", logData)
				w.WriteHeader(http.StatusForbidden)
				return
			}
			// extract user name and proceed
			entityData.UserID = zebedeeIdentityResponse.Identifier
		}

		hasPermission, err := m.permissionsChecker.HasPermission(req.Context(), *entityData, permission, nil)
		if err != nil {
			log.Error(ctx, "authorisation failed due to permissions lookup error", err, logData)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		if !hasPermission {
			log.Info(ctx, "request does not have permission", logData)
			w.WriteHeader(http.StatusForbidden)
			return
		}

		handlerFunc(w, req)
	}
}

// Close resources used by the middleware.
func (m PermissionCheckMiddleware) Close(ctx context.Context) error {
	return m.permissionsChecker.Close(ctx)
}

// HealthCheck updates the health status of the permissions checker
func (m PermissionCheckMiddleware) HealthCheck(ctx context.Context, state *health.CheckState) error {
	return m.permissionsChecker.HealthCheck(ctx, state)
}
