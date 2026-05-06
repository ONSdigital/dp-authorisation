package authorisation

import (
	"testing"

	permsdk "github.com/ONSdigital/dp-permissions-api/sdk"
)

func TestCreateAuthEntityData(t *testing.T) {
	entityData := &permsdk.EntityData{
		UserID: "test-user",
		Groups: []string{"group-a", "group-b"},
	}

	tests := []struct {
		name      string
		isService bool
	}{
		{
			name:      "service auth",
			isService: true,
		},
		{
			name:      "user auth",
			isService: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := CreateAuthEntityData(entityData, tc.isService)
			if got == nil {
				t.Fatal("expected auth entity data, got nil")
			}

			if got.EntityData == nil {
				t.Fatal("expected entity data, got nil")
			}

			if got.EntityData.UserID != entityData.UserID {
				t.Fatalf("expected user id %q, got %q", entityData.UserID, got.EntityData.UserID)
			}

			if len(got.EntityData.Groups) != len(entityData.Groups) {
				t.Fatalf("expected %d groups, got %d", len(entityData.Groups), len(got.EntityData.Groups))
			}

			for i := range entityData.Groups {
				if got.EntityData.Groups[i] != entityData.Groups[i] {
					t.Fatalf("expected group %q at index %d, got %q", entityData.Groups[i], i, got.EntityData.Groups[i])
				}
			}

			if got.IsServiceAuth != tc.isService {
				t.Fatalf("expected IsServiceAuth %t, got %t", tc.isService, got.IsServiceAuth)
			}
		})
	}
}
