package authv2

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

func TestUnmarshalPermissionsResponseEntity(t *testing.T) {
	testCases := []struct {
		scenario     string
		getInput     func() []byte
		assertEntity func(*permissionsResponseEntity)
		assertError  func(error)
	}{
		{
			scenario: "Given an empty byte array",
			getInput: func() []byte {
				return []byte{}
			},
			assertEntity: func(actual *permissionsResponseEntity) {
				So(actual, ShouldResemble, &permissionsResponseEntity{})
			},
			assertError: func(err error) {
				So(err, ShouldBeNil)
			},
		},
		{
			scenario: "Given an nil byte array",
			getInput: func() []byte {
				return nil
			},
			assertEntity: func(actual *permissionsResponseEntity) {
				So(actual, ShouldResemble, &permissionsResponseEntity{})
			},
			assertError: func(err error) {
				So(err, ShouldBeNil)
			},
		},
		{
			scenario: "Given an byte array that is not a valid permissionsResponseEntity",
			getInput: func() []byte {
				return []byte("I AM NOT VALID")
			},
			assertEntity: func(actual *permissionsResponseEntity) {
				So(actual, ShouldBeNil)
			},
			assertError: func(err error) {
				So(err, ShouldNotBeNil)
				permErr, ok := err.(Error)
				So(ok, ShouldBeTrue)
				So(permErr.Status, ShouldEqual, 500)
				So(permErr.Message, ShouldEqual, "internal server error failed marshalling permissions response entity")
			},
		},
		{
			scenario: "Given a byte array containing valid permissionsResponseEntity data",
			getInput: func() []byte {
				b, err := json.Marshal(&permissionsResponseEntity{
					List: []permissionType{
						Create, Read, Update, Delete},
				})
				So(err, ShouldBeNil)
				return b
			},
			assertEntity: func(actual *permissionsResponseEntity) {
				So(actual, ShouldResemble, &permissionsResponseEntity{
					List: []permissionType{
						Create, Read, Update, Delete},
				})
			},
			assertError: func(err error) {
				So(err, ShouldBeNil)
			},
		},
	}

	for i, tc := range testCases {
		Convey(fmt.Sprintf("%d/%d) %s", i+1, len(testCases), tc.scenario), t, func() {

			Convey("when unmarshalPermissionsResponseEntity is called", func() {
				actual, err := unmarshalPermissionsResponseEntity(tc.getInput())

				Convey("then the expected permissionsResponseEntity is returned", func() {
					tc.assertEntity(actual)
				})

				Convey("and the expected error is returned", func() {
					tc.assertError(err)
				})
			})
		})
	}
}

func TestGetResponseBytes(t *testing.T) {
	testCases := []struct {
		scenario    string
		reader      io.Reader
		assertBytes func([]byte)
		assertError func(error)
	}{
		{
			scenario: "Given a nil reader",
			reader:   nil,
			assertBytes: func(b []byte) {
				So(b, ShouldBeNil)
			},
			assertError: func(err error) {
				So(err, ShouldResemble, getPermissionsResponseBodyNilError)
			},
		},
		{
			scenario: "Given reader returns an empty byte array",
			reader: &readCloserMock{
				GetEntityFunc: func() (bytes []byte, e error) {
					return []byte{}, nil
				},
			},
			assertBytes: func(b []byte) {
				So(b, ShouldBeEmpty)
			},
			assertError: func(err error) {
				So(err, ShouldBeNil)
			},
		},
		{
			scenario: "Given ioutil.ReadAll returns an error",
			reader: &readCloserMock{
				GetEntityFunc: func() (bytes []byte, e error) {
					return nil, errors.New("bork")
				},
			},
			assertBytes: func(b []byte) {
				So(b, ShouldBeNil)
			},
			assertError: func(err error) {
				permErr, ok := err.(Error)
				So(ok, ShouldBeTrue)
				So(permErr.Message, ShouldEqual, "internal server error failed reading get permissions response body")
				So(permErr.Status, ShouldEqual, 500)
			},
		},
		{
			scenario: "Given reader returns a valid byte array",
			reader: &readCloserMock{
				GetEntityFunc: func() (bytes []byte, e error) {
					return []byte("hello world"), nil
				},
			},
			assertBytes: func(b []byte) {
				So(b, ShouldResemble, []byte("hello world"))
			},
			assertError: func(err error) {
				So(err, ShouldBeNil)
			},
		},
	}

	for i, tc := range testCases {
		Convey(fmt.Sprintf("%d/%d) %s", i+1, len(testCases), tc.scenario), t, func() {

			Convey("when getResponseBytes is called", func() {
				actual, err := getResponseBytes(tc.reader)

				Convey("then the expected bytes are returned", func() {
					tc.assertBytes(actual)
				})

				Convey("and the expected error is returned", func() {
					tc.assertError(err)
				})
			})
		})
	}
}
