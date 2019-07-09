package authv2

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestPermissionsResponseEntityToPermissions(t *testing.T) {

	testCases := []struct {
		entity   *permissionsResponseEntity
		expected *Permissions
	}{
		{
			entity:   &permissionsResponseEntity{List: []permissionType{Create, Read, Update, Delete}},
			expected: &Permissions{Create: true, Read: true, Update: true, Delete: true},
		},
		{
			entity:   &permissionsResponseEntity{List: []permissionType{Create}},
			expected: &Permissions{Create: true},
		},
		{
			entity:   &permissionsResponseEntity{List: []permissionType{Create, Read}},
			expected: &Permissions{Create: true, Read: true},
		},
		{
			entity:   &permissionsResponseEntity{List: []permissionType{Create, Read, Update}},
			expected: &Permissions{Create: true, Read: true, Update: true},
		},
		{
			entity:   &permissionsResponseEntity{List: []permissionType{Read, Update}},
			expected: &Permissions{Read: true, Update: true},
		},
		{
			entity:   nil,
			expected: &Permissions{},
		},
		{
			entity:   &permissionsResponseEntity{},
			expected: &Permissions{},
		},
		{
			entity:   &permissionsResponseEntity{List: []permissionType{}},
			expected: &Permissions{},
		},
	}

	Convey("should create expected Permissions from permissionsResponseEntity", t, func() {
		for _, tc := range testCases {
			actual := permissionsResponseEntityToPermissions(tc.entity)
			So(actual, ShouldResemble, tc.expected)
		}
	})

}
