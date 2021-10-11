package authorisation

import (
	"context"
	"github.com/ONSdigital/dp-authorisation/v2/permissions"
)

//go:generate moq -out mock/jwt_parser.go -pkg mock . JWTParser
//go:generate moq -out mock/permissions_checker.go -pkg mock . PermissionsChecker

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
}
