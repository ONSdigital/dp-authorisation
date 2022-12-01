package authorisationtest

import (
	"context"
	"encoding/json"

	permsdk "github.com/ONSdigital/dp-permissions-api/sdk"
	"github.com/ONSdigital/log.go/v2/log"
	"github.com/maxcnunes/httpfake"
)

// FakePermissionsAPI provides a fake HTTP server for the permissions API.
type FakePermissionsAPI struct {
	*httpfake.HTTPFake
}

// NewFakePermissionsAPI creates a new instance of FakePermissionsAPI with a default permissions bundle response.
func NewFakePermissionsAPI() *FakePermissionsAPI {
	httpFake := httpfake.New()
	fakePermissionsAPI := &FakePermissionsAPI{
		HTTPFake: httpFake,
	}

	bundle := GetDefaultPermissionsBundle()
	if err := fakePermissionsAPI.UpdatePermissionsBundleResponse(bundle); err != nil {
		// Note that this error should never happen, as we are using a hardcoded bundle
		log.Error(context.Background(), "failed to update permissions bundle response", err)
	}

	return fakePermissionsAPI
}

// URL returns the URL of the HTTP server. This can be used in the setup of the component test to override
// the default URL for the permission API.
func (f *FakePermissionsAPI) URL() string {
	return f.HTTPFake.Server.URL
}

// UpdatePermissionsBundleResponse overrides the default response to return custom permission bundle data.
func (f *FakePermissionsAPI) UpdatePermissionsBundleResponse(bundle *permsdk.Bundle) error {
	bundleJson, err := json.Marshal(bundle)
	if err != nil {
		return err
	}

	f.NewHandler().Get("/v1/permissions-bundle").Response.Body(bundleJson).Status(200)
	return nil
}

// GetDefaultPermissionsBundle returns a default set permissions bundle data.
func GetDefaultPermissionsBundle() *permsdk.Bundle {
	return &permsdk.Bundle{
		"users:create": { // role
			"groups/role-admin": { // group
				{
					ID: "1", // policy
				},
			},
		},
	}
}
