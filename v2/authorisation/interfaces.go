package authorisation

import (
	"context"
	"github.com/ONSdigital/dp-authorisation/v2/permissions"
	health "github.com/ONSdigital/dp-healthcheck/healthcheck"
	"net/http"
)

//go:generate moq -out mock/jwt_parser.go -pkg mock . JWTParser
//go:generate moq -out mock/permissions_checker.go -pkg mock . PermissionsChecker
//go:generate moq -out mock/middleware.go -pkg mock . Middleware

// Middleware represents the high level interface for authorisation middleware
type Middleware interface {
	Require(permission string, handlerFunc http.HandlerFunc) http.HandlerFunc
	Close(ctx context.Context) error
	HealthCheck(ctx context.Context, state *health.CheckState) error
}

// JWTParser takes a raw JWT token string, verifying it and extracting the required entity data.
type JWTParser interface {
	Parse(tokenString string) (*permissions.EntityData, error)
}

// PermissionsChecker checks if the given entity data matches the given permission
type PermissionsChecker interface {
	HasPermission(ctx context.Context,
		entityData permissions.EntityData,
		permission string,
		attributes map[string]string,
	) (bool, error)
	Close(ctx context.Context) error
	HealthCheck(ctx context.Context, state *health.CheckState) error
}
