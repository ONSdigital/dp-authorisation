package permissions

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/ONSdigital/dp-permissions/permissions/mocks"
	"github.com/ONSdigital/log.go/log"
	"github.com/pkg/errors"
	. "github.com/smartystreets/goconvey/convey"
)

func Test_unmarshalPermissionsResponse(t *testing.T) {

	type scenario struct {
		desc       string
		input      interface{}
		crud       *CRUD
		checkError func(err error) bool
	}

	scenarios := []scenario{
		{
			desc:       "Given a valid permissions response",
			input:      permissions{Permissions: []permission{Create, Read, Update, Delete}},
			crud:       &CRUD{Create: true, Read: true, Update: true, Delete: true},
			checkError: func(err error) bool { return true },
		},
		{
			desc:       "Given empty permissions response",
			input:      permissions{Permissions: []permission{}},
			crud:       &CRUD{Create: false, Read: false, Update: false, Delete: false},
			checkError: func(err error) bool { return true },
		},
		{
			desc:       "Given a single permission response",
			input:      permissions{Permissions: []permission{Read}},
			crud:       &CRUD{Create: false, Read: true, Update: false, Delete: false},
			checkError: func(err error) bool { return true },
		},
		{
			desc:  "Given an invalid permissions response",
			input: "This is not a valid permissions response",
			crud:  nil,
			checkError: func(err error) bool {
				_, ok := err.(*json.UnmarshalTypeError)
				return ok
			},
		},
		{
			desc:  "Given an invalid permissions response",
			input: "This is not a valid permissions response",
			crud:  nil,
			checkError: func(err error) bool {
				_, ok := err.(*json.UnmarshalTypeError)
				return ok
			},
		},
	}

	for i, s := range scenarios {
		Convey(fmt.Sprintf("%d) %s", i, s.desc), t, func() {
			b, err := json.Marshal(s.input)
			So(err, ShouldBeNil)

			Convey("When unmarshalPermissions is called", func() {
				crud, err := unmarshalPermissions(nil, bytes.NewReader(b))

				Convey("Then the expected CRUD permissions are returned", func() {
					So(crud, ShouldResemble, s.crud)
				})

				Convey("And the expected error is returned", func() {
					So(s.checkError(err), ShouldBeTrue)
				})
			})
		})
	}
}

func TestHandleErrorResponse(t *testing.T) {

	type scenario struct {
		desc           string
		body           []byte
		readerErr      error
		status         int
		expectedStatus int
	}

	scenarios := []scenario{
		{
			desc:           "Should return the expected status for a valid error entity response body",
			body:           toJson(t, errorEntity{"unauthorized"}),
			readerErr:      nil,
			status:         401,
			expectedStatus: 401,
		},
		{
			desc:           "Should return status 500 if read body returns an error",
			body:           nil,
			readerErr:      errors.New("pop!"),
			status:         401,
			expectedStatus: 500,
		},
		{
			desc:           "Should return status 500 if unmarshal body to error entity fails",
			body:           toJson(t, []int{1, 2, 3, 4, 5}),
			readerErr:      nil,
			status:         401,
			expectedStatus: 500,
		},
	}

	for i, s := range scenarios {
		Convey(fmt.Sprintf("%d) %s", i, s.desc), t, func() {
			resp := getErrorResponse(s.status, s.body, s.readerErr)
			So(handleErrorResponse(nil, resp, log.Data{}), ShouldEqual, s.expectedStatus)
		})
	}
}

func TestUnmarshalPermissions(t *testing.T) {

	type scenario struct {
		desc  string
		body  []byte
		err   error
		crud  *CRUD
		perms permissions
	}

	scenarios := []scenario{
		{
			desc: "should return expected error if read response body fails",
			body: nil,
			err:  errors.New("boom"),
			crud: nil,
		},
		{
			desc: "should return expected error if response body not valid permissions json",
			body: toJson(t, 666),
			err:  errors.New("json: cannot unmarshal number into Go value of type permissions.permissions"),
			crud: nil,
		},
		{
			desc: "should return CRUD for permissions json [Create, Read, Update,  Delete]",
			body: toJson(t, permissions{Permissions: []permission{Create, Read, Update, Delete}}),
			err:  nil,
			crud: &CRUD{Create: true, Read: true, Update: true, Delete: true},
		},
		{
			desc: "should return R for permissions json [Read]",
			body: toJson(t, permissions{Permissions: []permission{Read}}),
			err:  nil,
			crud: &CRUD{Create: false, Read: true, Update: false, Delete: false},
		},
	}

	for i, s := range scenarios {
		Convey(fmt.Sprintf("%d) %s", i, s.desc), t, func() {
			reader := &mocks.ReadCloser{
				GetEntityFunc: func() (i []byte, e error) {
					return s.body, s.err
				},
			}

			crud, err := unmarshalPermissions(nil, reader)
			So(crud, ShouldResemble, s.crud)
			So(err, ShouldResemble, s.err)
		})
	}
}

func getErrorResponse(status int, b []byte, err error) *http.Response {
	return &http.Response{
		StatusCode: status,
		Body: &mocks.ReadCloser{
			GetEntityFunc: func() ([]byte, error) {
				return b, err
			},
		},
	}
}

func toJson(t *testing.T, i interface{}) []byte {
	b, err := json.Marshal(i)
	if err != nil {
		t.Fatalf("failed to marshal object to json: %s", err.Error())
	}
	return b
}
