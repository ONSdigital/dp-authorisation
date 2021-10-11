package authorisation

import (
	"context"
	"github.com/ONSdigital/dp-authorisation/v2/jwt"
	"github.com/ONSdigital/dp-authorisation/v2/permissions"
	"github.com/ONSdigital/log.go/v2/log"
	"net/http"
	"strings"
)

// Middleware is used to wrap HTTP handlers with authorisation using JWT tokens
type Middleware struct {
	jwtParser          JWTParser
	permissionsChecker PermissionsChecker
}

// NewMiddlewareFromDependencies creates a new instance of Middleware, using injected dependencies.
func NewMiddlewareFromDependencies(jwtParser JWTParser, permissionsChecker PermissionsChecker) *Middleware {
	return &Middleware{
		jwtParser:          jwtParser,
		permissionsChecker: permissionsChecker,
	}
}

// NewMiddlewareFromConfig creates a new instance of Middleware, instantiating the required dependencies from
// the given configuration values.
//
// This constructor uses default dependencies - the Cognito specific JWT parser, and caching permissions checker.
// If different dependencies are required, use the NewMiddlewareFromDependencies constructor.
func NewMiddlewareFromConfig(context context.Context, config *Config) (*Middleware, error) {
	jwtParser, err := jwt.NewCognitoRSAParser(config.JWTVerificationPublicKey)
	if err != nil {
		return nil, err
	}

	permissionsChecker := permissions.NewChecker(
		context,
		config.PermissionsAPIURL,
		config.PermissionsCacheUpdateInterval,
		config.PermissionsCacheExpiryCheckInterval,
		config.PermissionsMaxCacheTime)

	return NewMiddlewareFromDependencies(jwtParser, permissionsChecker), nil
}

// Require wraps an existing handler, only allowing it to be called if the request is
// authorised against the given permission.
func (m Middleware) Require(permission string, handlerFunc http.HandlerFunc) http.HandlerFunc {
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

		entityData, err := m.jwtParser.Parse(authToken)
		if err != nil {
			logData["message"] = err.Error()
			log.Info(ctx, "authorisation failed due to jwt parsing issue", logData)
			w.WriteHeader(http.StatusForbidden)
			return
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
