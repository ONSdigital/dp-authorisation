package auth

import (
	"encoding/json"
	"errors"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestError_Error(t *testing.T) {
	Convey("should return message if cause nil", t, func() {
		err := Error{
			Message: "internal server error",
			Status:  500,
			Cause:   nil,
		}

		So(err.Error(), ShouldEqual, "internal server error")
	})

	Convey("should return message and cause if cause not nil", t, func() {
		err := Error{
			Message: "internal server error",
			Status:  500,
			Cause:   errors.New("inner error"),
		}

		So(err.Error(), ShouldEqual, "internal server error: inner error")
	})
}

func TestGetErrorEntityFromResponse(t *testing.T) {
	Convey("given a valid response body", t, func() {
		expected := &errorEntity{Message: "hello world"}

		readerMock := &readCloserMock{
			done: false,
			GetEntityFunc: func() (bytes []byte, e error) {
				return json.Marshal(expected)
			},
		}

		Convey("when getErrorEntityFromResponse is called", func() {
			actual, err := getErrorEntityFromResponse(readerMock)

			Convey("then the expected errorEntity is returned", func() {
				So(actual, ShouldResemble, expected)
			})

			Convey("and err is nil", func() {
				So(err, ShouldBeNil)
			})
		})
	})

	Convey("given a ioutil.ReadAll returns an error", t, func() {
		readAllErr := errors.New("bork")

		expected := Error{
			Status:  500,
			Message: "internal server error failed reading get permissions error response body",
			Cause:   readAllErr,
		}

		readerMock := &readCloserMock{
			done: false,
			GetEntityFunc: func() (bytes []byte, e error) {
				return nil, readAllErr
			},
		}

		Convey("when getErrorEntityFromResponse is called", func() {
			actual, err := getErrorEntityFromResponse(readerMock)

			Convey("then errorEntity is nil", func() {
				So(actual, ShouldBeNil)
			})

			Convey("and the expected err is returned", func() {
				So(err, ShouldResemble, expected)
			})
		})
	})

	Convey("given an invalid response body", t, func() {
		readerMock := &readCloserMock{
			done: false,
			GetEntityFunc: func() (bytes []byte, e error) {
				return json.Marshal([]string{"hello", "world"})
			},
		}

		Convey("when getErrorEntityFromResponse is called", func() {
			actual, err := getErrorEntityFromResponse(readerMock)

			Convey("then errorEntity is nil", func() {
				So(actual, ShouldBeNil)
			})

			Convey("and the expected err is returned", func() {
				So(err, ShouldNotBeNil)

				permErr, ok := err.(Error)
				So(ok, ShouldBeTrue)
				So(permErr.Status, ShouldEqual, 500)
				So(permErr.Message, ShouldEqual, "internal server error failed unmarshalling get permissions error response body")
			})
		})
	})
}

func TestHandleGetPermissionsErrorResponse(t *testing.T) {
	Convey("given a valid error response", t, func() {
		expected := &errorEntity{Message: "I am borked"}

		readerMock := &readCloserMock{
			done: false,
			GetEntityFunc: func() (bytes []byte, e error) {
				return json.Marshal(expected)
			},
		}

		Convey("when handleGetPermissionsErrorResponse is called", func() {
			err := handleGetPermissionsErrorResponse(nil, readerMock, 500)

			Convey("then getPermissionsUnauthorizedError is returned", func() {
				So(err, ShouldResemble, getPermissionsUnauthorizedError)
			})
		})
	})

	Convey("given an invalid error response", t, func() {
		readerMock := &readCloserMock{
			done: false,
			GetEntityFunc: func() (bytes []byte, e error) {
				return json.Marshal([]string{"I", "am", "borked"})
			},
		}

		Convey("when handleGetPermissionsErrorResponse is called", func() {
			err := handleGetPermissionsErrorResponse(nil, readerMock, 500)

			Convey("then getPermissionsUnauthorizedError is returned", func() {
				So(err, ShouldResemble, getPermissionsUnauthorizedError)
			})
		})
	})
}
