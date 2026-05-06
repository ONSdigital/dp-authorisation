package authorisation

import (
	"context"
	"testing"

	permsdk "github.com/ONSdigital/dp-permissions-api/sdk"
)

func TestContextWithAuthEntityDataAndFromContext(t *testing.T) {
	ctx := context.Background()
	expected := &AuthEntityData{
		EntityData: &permsdk.EntityData{
			UserID: "test-user",
			Groups: []string{"group-a"},
		},
		IsServiceAuth: true,
	}

	ctxWithData := ContextWithAuthEntityData(ctx, expected)
	got, ok := AuthEntityDataFromContext(ctxWithData)
	if !ok {
		t.Fatal("expected auth entity data in context, got none")
	}

	if got != expected {
		t.Fatalf("expected same auth entity data pointer, got different pointer")
	}
}

func TestAuthEntityDataFromContextWhenMissing(t *testing.T) {
	ctx := context.Background()

	got, ok := AuthEntityDataFromContext(ctx)
	if ok {
		t.Fatal("expected no auth entity data in context")
	}

	if got != nil {
		t.Fatalf("expected nil auth entity data, got %#v", got)
	}
}
