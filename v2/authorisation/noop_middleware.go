package authorisation

import (
	"context"
	health "github.com/ONSdigital/dp-healthcheck/healthcheck"
	"net/http"
)

// NoopMiddleware provides a middleware implementation that does not do any permissions checking.
type NoopMiddleware struct{}

// NewNoopMiddleware creates a new instance of NoopMiddleware.
func NewNoopMiddleware() *NoopMiddleware {
	return &NoopMiddleware{}
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
