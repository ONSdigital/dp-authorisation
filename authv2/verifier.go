package authv2

import (
	"context"

	"github.com/ONSdigital/log.go/log"
)

type PermissionsVerifier struct {
}

func NewPermissionsVerifier() *PermissionsVerifier {
	return &PermissionsVerifier{}
}

func (verifier *PermissionsVerifier) CheckAuthorisation(ctx context.Context, actual *Permissions, required *Permissions) error {
	required = getDefaultIfBlank(required)
	actual = getDefaultIfBlank(actual)

	missingPermissions := make([]permissionType, 0)

	if required.Create && !actual.Create {
		missingPermissions = append(missingPermissions, Create)
	}
	if required.Read && !actual.Read {
		missingPermissions = append(missingPermissions, Read)
	}
	if required.Update && !actual.Update {
		missingPermissions = append(missingPermissions, Update)
	}
	if required.Delete && !actual.Delete {
		missingPermissions = append(missingPermissions, Delete)
	}

	if len(missingPermissions) > 0 {
		log.Event(ctx, "action forbidden caller does not process the required permissions", log.Data{
			"required_permissions": required,
			"caller_permissions":   actual,
			"missing_permissions":  missingPermissions,
		})
		return callerForbiddenError
	}

	log.Event(ctx, "caller authorised to perform the requested action")
	return nil
}

func getDefaultIfBlank(p *Permissions) *Permissions {
	if p == nil {
		return &Permissions{}
	}
	return p
}
