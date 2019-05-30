package permissions

import (
	"context"
	"net/http"

	"github.com/ONSdigital/log.go/log"
)

const (
	Create permission = "CREATE"
	Read   permission = "READ"
	Update permission = "UPDATE"
	Delete permission = "DELETE"

	gerPermissionsURL = "%s?dataset_id=%s&collection_id=%s"
)

type Error struct {
	Status  int
	Message string
	Cause   error
}

type permission string

type callerPermissions struct {
	List []permission `json:"permissions"`
}

type errorEntity struct {
	Message string `json:"message"`
}

type HTTPClient interface {
	Do(ctx context.Context, req *http.Request) (*http.Response, error)
}

type Permissions struct {
	host string
	cli  HTTPClient
}

// CRUD is a representation of permissionsList required by an endpoint or held by a user/service.
type CRUD struct {
	Create bool
	Read   bool
	Update bool
	Delete bool
}

// Satisfied is a verification function that checks a callers permissions contains each of the required permissions.
// Returns nil if the caller has all of the stated required permissions otherwise returns Error with Status 403
func (required *CRUD) Satisfied(ctx context.Context, caller *CRUD) error {
	missingPermissions := make([]permission, 0)

	if required.Create && !caller.Create {
		missingPermissions = append(missingPermissions, Create)
	}
	if required.Read && !caller.Read {
		missingPermissions = append(missingPermissions, Read)
	}
	if required.Update && !caller.Update {
		missingPermissions = append(missingPermissions, Update)
	}
	if required.Delete && !caller.Delete {
		missingPermissions = append(missingPermissions, Delete)
	}

	if len(missingPermissions) > 0 {
		log.Event(ctx, "caller does not have the required permission", log.Data{
			"required_permissions": required,
			"caller_permissions":   caller,
			"missing_permissions":  missingPermissions,
		})
		return Error{
			Status:  403,
			Message: "caller does not have the required permission to perform the requested action",
		}
	}

	log.Event(ctx, "caller has permissionsList required required permission", log.Data{
		"required_permissions": required,
		"caller_permissions":   caller,
	})
	return nil
}

func (e Error) Error() string {
	if e.Cause != nil {
		return e.Cause.Error()
	}
	return e.Message
}
