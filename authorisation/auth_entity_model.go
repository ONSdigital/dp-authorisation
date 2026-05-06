package authorisation

import permsdk "github.com/ONSdigital/dp-permissions-api/sdk"

// AuthEntityData holds the entity data for an authenticated request along with
// whether the request was made by a service account or user
type AuthEntityData struct {
	EntityData    *permsdk.EntityData
	IsServiceAuth bool
}

// CreateAuthEntityData creates an AuthEntityData from the provided EntityData and
// a bool indicating whether the token belongs to a service account
func CreateAuthEntityData(entityData *permsdk.EntityData, isService bool) *AuthEntityData {
	return &AuthEntityData{
		EntityData: &permsdk.EntityData{
			UserID: entityData.UserID,
			Groups: entityData.Groups,
		},
		IsServiceAuth: isService,
	}
}
