package auth

import (
	"context"
	"net/http"

	"github.com/ONSdigital/log.go/log"
)

//go:generate moq -out generated_mocks.go -pkg auth . Clienter Verifier HTTPClienter Parameters GetPermissionsRequestBuilder

const (
	// CollectionIDHeader is the collection ID request header key.
	CollectionIDHeader = "Collection-Id"
)

// GetRequestVarsFunc is a utility function for retrieving URL path parameters and request headers from a HTTP Request
type GetRequestVarsFunc func(r *http.Request) map[string]string

// HTTPClienter is the interface that defines a client for making HTTP requests
type HTTPClienter interface {
	Do(ctx context.Context, req *http.Request) (*http.Response, error)
}

// Clienter is the interface that defines a client for obtaining Permissions from a Permissions API. The Parameters
// argument encapsulates the specifics of the request to make.
type Clienter interface {
	GetPermissions(ctx context.Context, getPermissionsRequest *http.Request) (*Permissions, error)
}

// Verifier is an interface defining a permissions checker. Checks that the caller's permissions satisfy the required
// permissions
type Verifier interface {
	CheckAuthorisation(ctx context.Context, callerPermissions *Permissions, requiredPermissions *Permissions) error
}

type GetPermissionsRequestBuilder interface {
	NewPermissionsRequest(req *http.Request) (getPermissionsRequest *http.Request, err error)
}

// LoggerNamespace set the log namespace for auth package logging.
func LoggerNamespace(logNamespace string) {
	log.Namespace = logNamespace
}

