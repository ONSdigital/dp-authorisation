package authorisation

import (
	"context"
	"net/http"

	health "github.com/ONSdigital/dp-healthcheck/healthcheck"
	dprequest "github.com/ONSdigital/dp-net/request"
	permsdk "github.com/ONSdigital/dp-permissions-api/sdk"
)

//go:generate moq -out mock/jwt_parser.go -pkg mock . JWTParser
//go:generate moq -out mock/permissions_checker.go -pkg mock . PermissionsChecker
//go:generate moq -out mock/middleware.go -pkg mock . Middleware
//go:generate moq -out mock/zebedeeclient.go -pkg mock . ZebedeeClient

// Middleware represents the high level interface for authorisation middleware
type Middleware interface {
	Require(permission string, handlerFunc http.HandlerFunc) http.HandlerFunc
	RequireWithAttributes(permission string, handlerFunc http.HandlerFunc, getAttributes GetAttributesFromRequest) http.HandlerFunc
	Close(ctx context.Context) error
	Parse(token string) (*permsdk.EntityData, error)
	HealthCheck(ctx context.Context, state *health.CheckState) error
	IdentityHealthCheck(ctx context.Context, state *health.CheckState) error
}

// JWTParser takes a raw JWT token string, verifying it and extracting the required entity data.
type JWTParser interface {
	Parse(tokenString string) (*permsdk.EntityData, error)
}

// PermissionsChecker checks if the given entity data matches the given permission
type PermissionsChecker interface {
	HasPermission(ctx context.Context,
		entityData permsdk.EntityData,
		permission string,
		attributes map[string]string,
	) (bool, error)
	Close(ctx context.Context) error
	HealthCheck(ctx context.Context, state *health.CheckState) error
}

// ZebedeeClient validates old world token
type ZebedeeClient interface {
	CheckTokenIdentity(ctx context.Context, token string) (*dprequest.IdentityResponse, error)
}
