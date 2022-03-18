package authorisation

import (
	"context"
	"net/http"

	health "github.com/ONSdigital/dp-healthcheck/healthcheck"
)

// NoopMiddleware provides a middleware implementation that does not do any permissions checking.
type NoopMiddleware struct{}

// NewNoopMiddleware creates a new instance of NoopMiddleware.
func NewNoopMiddleware() *NoopMiddleware {
	return &NoopMiddleware{}
}

// RequireWithAttributes wraps an existing handler. The Noop implementation just calls the underlying handler.
func (m NoopMiddleware) RequireWithAttributes(permission string, handlerFunc http.HandlerFunc, getAttributesFunc GetAttributesFromRequest) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		handlerFunc(w, req)
	}
}

// Require wraps an existing handler. The Noop implementation just calls the underlying handler.
func (m NoopMiddleware) Require(permission string, handlerFunc http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		handlerFunc(w, req)
	}
}

// Close resources used by the middleware.
func (m NoopMiddleware) Close(ctx context.Context) error {
	return nil
}

// HealthCheck updates the health status of the permissions checker
func (m NoopMiddleware) HealthCheck(ctx context.Context, state *health.CheckState) error {
	return state.Update(health.StatusOK, "noop permissions check", 0)
}

// IdentityHealthCheck updates the health status of the jwt keys request against identity api
func (m NoopMiddleware) IdentityHealthCheck(ctx context.Context, state *health.CheckState) error {
	return state.Update(health.StatusOK, "noop jwt keys request", 0)
}
