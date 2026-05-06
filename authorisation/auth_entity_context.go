package authorisation

import "context"

// authEntityDataKey is the key used to store the AuthEntityData in the context
// it is a private type to prevent collisions with other keys in the context
type authEntityDataKey struct{}

// ContextWithAuthEntityData adds the AuthEntityData to the context
func ContextWithAuthEntityData(ctx context.Context, data *AuthEntityData) context.Context {
	return context.WithValue(ctx, authEntityDataKey{}, data)
}

// AuthEntityDataFromContext retrieves the AuthEntityData from the context
func AuthEntityDataFromContext(ctx context.Context) (*AuthEntityData, bool) {
	data, ok := ctx.Value(authEntityDataKey{}).(*AuthEntityData)
	return data, ok
}
