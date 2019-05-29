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
				crud, err := unmarshalPermissions(bytes.NewReader(b))

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

	Convey("Should return the expected status for a valid error entity response body", t, func() {
		entity := errorEntity{"unauthorized"}
		b, err := json.Marshal(entity)
		So(err, ShouldBeNil)

		resp := getErrorResponse(401, b, nil)
		So(handleErrorResponse(nil, resp, log.Data{}), ShouldEqual, 401)
	})

	Convey("Should return status 500 if read body returns an error", t, func() {
		resp := getErrorResponse(401, nil, errors.New("pop!"))
		So(handleErrorResponse(nil, resp, log.Data{}), ShouldEqual, 500)
	})

	Convey("Should return status 500 if unmarshal body to error entity fails", t, func() {

		invalidBody := []int{1, 2, 3, 4, 5}
		b, err := json.Marshal(invalidBody)
		So(err, ShouldBeNil)

		resp := getErrorResponse(401, b, nil)
		So(handleErrorResponse(nil, resp, log.Data{}), ShouldEqual, 500)
	})

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
