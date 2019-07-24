package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ONSdigital/go-ns/common"
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
		reader      func() io.Reader
		assertBytes func([]byte)
		assertError func(error)
	}{
		{
			scenario: "Given a nil reader",
			reader: func() io.Reader {
				return nil
			},
			assertBytes: func(b []byte) {
				So(b, ShouldBeNil)
			},
			assertError: func(err error) {
				So(err, ShouldResemble, getPermissionsResponseBodyNilError)
			},
		},
		{
			scenario: "Given reader returns an empty byte array",
			reader:   newReaderFunc([]byte{}, nil),

			assertBytes: func(b []byte) {
				So(b, ShouldBeNil)
			},
			assertError: func(err error) {
				So(err, ShouldResemble, getPermissionsResponseBodyNilError)
			},
		},
		{
			scenario: "Given ioutil.ReadAll returns an error",
			reader:   newReaderFunc(nil, errors.New("bork")),
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
			scenario: "Given reader returns an invalid byte array",
			reader:   newReaderFunc([]byte("hello world"), nil),
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
				actual, err := getResponseBytes(tc.reader())

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

func TestGetPermissionsFromResponse(t *testing.T) {
	Convey("given a valid permissions response", t, func() {
		responseEntity := permissionsResponseEntity{
			List: []permissionType{Read, Create},
		}

		expected := &Permissions{Create: true, Read: true}

		responseBody := &readCloserMock{
			GetEntityFunc: func() (bytes []byte, e error) {
				return json.Marshal(responseEntity)
			},
		}

		Convey("when getPermissionsFromResponse is called", func() {
			actual, err := getPermissionsFromResponse(responseBody)

			Convey("then the expected permissions object is returned", func() {
				So(actual, ShouldResemble, expected)
			})

			Convey("and no error is returned", func() {
				So(err, ShouldBeNil)
			})
		})
	})

	Convey("given an empty permissions response", t, func() {
		responseEntity := permissionsResponseEntity{
			List: []permissionType{},
		}

		expected := &Permissions{Create: false, Read: false, Update: false, Delete: false}

		responseBody := &readCloserMock{
			GetEntityFunc: func() (bytes []byte, e error) {
				return json.Marshal(responseEntity)
			},
		}

		Convey("when getPermissionsFromResponse is called", func() {
			actual, err := getPermissionsFromResponse(responseBody)

			Convey("then the expected permissions object is returned", func() {
				So(actual, ShouldResemble, expected)
			})

			Convey("and no error is returned", func() {
				So(err, ShouldBeNil)
			})
		})
	})

	Convey("given getResponseBytes returns an error", t, func() {

		Convey("when getPermissionsFromResponse is called", func() {
			getReader := newReaderFunc(nil, nil)
			actual, err := getPermissionsFromResponse(getReader())

			Convey("then the expected permissions object is returned", func() {
				So(actual, ShouldBeNil)
			})

			Convey("and the expected error is returned", func() {
				So(err, ShouldResemble, getPermissionsResponseBodyNilError)
			})
		})
	})

	Convey("given unmarshalPermissionsResponseEntity returns an error", t, func() {

		Convey("when getPermissionsFromResponse is called", func() {
			getReader := newReaderFunc([]byte("INVALID ENTITY"), nil)

			actual, err := getPermissionsFromResponse(getReader())

			Convey("then the expected permissions object is returned", func() {
				So(actual, ShouldBeNil)
			})

			Convey("and the expected error is returned", func() {
				So(err, ShouldNotBeNil)
				permErr, ok := err.(Error)
				So(ok, ShouldBeTrue)
				So(permErr.Status, ShouldEqual, 500)
				So(permErr.Message, ShouldEqual, "internal server error failed marshalling permissions response entity")
			})
		})
	})

}

func TestDoGetPermissionsRequest(t *testing.T) {
	Convey("given request is nil", t, func() {
		httpClient := &HTTPClienterMock{}

		permissionsClient := &PermissionsClient{
			host:    "",
			httpCli: httpClient,
		}

		Convey("when doGetPermissionsRequest is called", func() {
			resp, err := permissionsClient.doGetPermissionsRequest(nil, nil)

			Convey("then response should be nil", func() {
				So(resp, ShouldBeNil)
			})

			Convey("and the expected error is returned", func() {
				So(err, ShouldResemble, getPermissionsRequestNilError)
			})

			Convey("and httpClient.Do is never called", func() {
				So(httpClient.DoCalls(), ShouldHaveLength, 0)
			})
		})
	})

	Convey("given httpclient.Do returns an error", t, func() {
		httpClient := &HTTPClienterMock{
			DoFunc: func(ctx context.Context, req *http.Request) (response *http.Response, e error) {
				return nil, errors.New("bork")
			},
		}

		permissionsClient := &PermissionsClient{
			host:    "",
			httpCli: httpClient,
		}

		request, err := http.NewRequest("GET", "http://localhost:8080", nil)
		So(err, ShouldBeNil)

		Convey("when doGetPermissionsRequest is called", func() {
			resp, err := permissionsClient.doGetPermissionsRequest(nil, request)

			Convey("then response should be nil", func() {
				So(resp, ShouldBeNil)
			})

			Convey("and the expected error is returned", func() {
				So(err, ShouldNotBeNil)

				permErr, ok := err.(Error)
				So(ok, ShouldBeTrue)
				So(permErr.Status, ShouldEqual, 500)
				So(permErr.Message, ShouldEqual, "get permissions request returned an error")
				So(permErr.Cause, ShouldResemble, errors.New("bork"))

			})

			Convey("and httpClient.Do is called once with the expected parameters", func() {
				calls := httpClient.DoCalls()
				So(calls, ShouldHaveLength, 1)
				So(calls[0].Req, ShouldResemble, request)
			})
		})
	})

	Convey("given a valid request", t, func() {
		request, err := http.NewRequest("GET", "http://localhost:8080", nil)
		So(err, ShouldBeNil)

		response := &http.Response{}

		httpClient := &HTTPClienterMock{
			DoFunc: func(ctx context.Context, req *http.Request) (*http.Response, error) {
				return response, nil
			},
		}

		permissionsClient := &PermissionsClient{host: "", httpCli: httpClient}

		Convey("when doGetPermissionsRequest is called", func() {
			actual, err := permissionsClient.doGetPermissionsRequest(nil, request)

			Convey("then the expected response is returned", func() {
				So(actual, ShouldResemble, response)
			})

			Convey("and error is nil", func() {
				So(err, ShouldBeNil)
			})

			Convey("and httpClient.Do is called once with the expected parameters", func() {
				calls := httpClient.DoCalls()
				So(calls, ShouldHaveLength, 1)
				So(calls[0].Req, ShouldResemble, request)
			})
		})
	})
}

func TestPermissionsClient_GetPermissions(t *testing.T) {
	Convey("should return the expected error if getPermissionsRequest is nil", t, func() {
		httpclient := &HTTPClienterMock{}
		cli := NewPermissionsClient(host, httpclient)

		actual, err := cli.GetPermissions(nil, nil)

		So(err, ShouldResemble, getPermissionsRequestNilError)
		So(actual, ShouldBeNil)

		calls := httpclient.DoCalls()
		So(calls, ShouldHaveLength, 0)
	})

	Convey("should return expected error if httpCli.Do returns error", t, func() {
		cliErr := errors.New("caboooooom")
		httpclient := newHttpCliMock(nil, cliErr)

		getPermReq := httptest.NewRequest("GET", host, nil)

		cli := NewPermissionsClient(host, httpclient)

		actual, err := cli.GetPermissions(nil, getPermReq)

		permErr, ok := err.(Error)
		So(ok, ShouldBeTrue)
		So(permErr.Status, ShouldEqual, 500)
		So(permErr.Message, ShouldEqual, "get permissions request returned an error")
		So(permErr.Cause, ShouldResemble, cliErr)
		So(actual, ShouldBeNil)

		calls := httpclient.DoCalls()
		So(calls, ShouldHaveLength, 1)
		So(calls[0].Req, ShouldResemble, getPermReq)
	})

	Convey("should return expected error is get permissions returns an error status response", t, func() {
		body := newReadCloserMock(json.Marshal(&errorEntity{Message: "caboom"}))

		response := &http.Response{Body: body, StatusCode: 500}

		httpclient := newHttpCliMock(response, nil)

		getPermReq := httptest.NewRequest("GET", host, nil)

		cli := NewPermissionsClient(host, httpclient)

		actual, err := cli.GetPermissions(nil, getPermReq)

		So(err, ShouldResemble, getPermissionsUnauthorizedError)
		So(actual, ShouldBeNil)

		calls := httpclient.DoCalls()
		So(calls, ShouldHaveLength, 1)
		So(calls[0].Req, ShouldResemble, getPermReq)
		So(body.IsClosed, ShouldBeTrue)
	})

	Convey("should return expected error if get permissions response body invalid", t, func() {
		body := newReadCloserMock(json.Marshal("invalid json"))

		response := &http.Response{Body: body, StatusCode: 200}

		httpclient := newHttpCliMock(response, nil)

		getPermReq := httptest.NewRequest("GET", host, nil)

		cli := NewPermissionsClient(host, httpclient)

		actual, err := cli.GetPermissions(nil, getPermReq)

		permErr, ok := err.(Error)
		So(ok, ShouldBeTrue)
		So(permErr.Status, ShouldEqual, 500)
		So(permErr.Message, ShouldEqual, "internal server error failed marshalling permissions response entity")
		So(actual, ShouldBeNil)

		calls := httpclient.DoCalls()
		So(calls, ShouldHaveLength, 1)
		So(calls[0].Req, ShouldResemble, getPermReq)

		So(body.IsClosed, ShouldBeTrue)
	})

	Convey("should return expected permissions given a valid request and valid response", t, func() {
		entity := &permissionsResponseEntity{List: []permissionType{Read}}

		body := newReadCloserMock(json.Marshal(entity))

		response := &http.Response{Body: body, StatusCode: 200}

		httpclient := newHttpCliMock(response, nil)

		getPermReq := httptest.NewRequest("GET", host, nil)

		cli := NewPermissionsClient(host, httpclient)

		actual, err := cli.GetPermissions(nil, getPermReq)

		expected := &Permissions{Read:true}
		So(err, ShouldBeNil)
		So(actual, ShouldResemble, expected)

		calls := httpclient.DoCalls()
		So(calls, ShouldHaveLength, 1)
		So(calls[0].Req, ShouldResemble, getPermReq)

		So(body.IsClosed, ShouldBeTrue)
	})
}

func TestPermissionsClient_GetCallerDatasetPermissionsSuccess(t *testing.T) {
	host := "http://localhost:8080"

	Convey("given valid parameters", t, func() {
		params := &UserDatasetParameters{
			UserAuthToken: userAuthToken,
			CollectionID:  collectionID,
			DatasetID:     datasetID,
		}

		permissionsEntity := &permissionsResponseEntity{
			List: []permissionType{Read},
		}

		resp := &http.Response{
			Body: &readCloserMock{
				GetEntityFunc: func() (i []byte, e error) {
					return json.Marshal(permissionsEntity)
				},
			},
			StatusCode: 200,
		}

		httpclient := &HTTPClienterMock{
			DoFunc: func(ctx context.Context, req *http.Request) (*http.Response, error) {
				return resp, nil
			},
		}

		permissionsClient := &PermissionsClient{host: "http://localhost:8080", httpCli: httpclient}

		Convey("when get caller permissions is invoked", func() {
			actual, err := permissionsClient.GetCallerPermissions(nil, params)

			Convey("then the expected permissions are returned", func() {
				expected := &Permissions{Read: true}
				So(actual, ShouldResemble, expected)
			})

			Convey("and error is nil", func() {
				So(err, ShouldBeNil)
			})

			Convey("and httpclient.Do is called once with the expected parameters", func() {
				calls := httpclient.DoCalls()
				So(calls, ShouldHaveLength, 1)
				So(calls[0].Req.URL.String(), ShouldResemble, fmt.Sprintf(userDatasetPermissionsURL, host, datasetID, collectionID))
				So(calls[0].Req.Header.Get(common.FlorenceHeaderKey), ShouldResemble, userAuthToken)
			})
		})
	})
}

func TestPermissionsClient_GetCallerDatasetPermissionsErrorCases(t *testing.T) {
	host := "http://localhost:8080"

	Convey("given params.CreateGetPermissionsRequest returns an error", t, func() {
		httpclient := &HTTPClienterMock{}

		permissionsClient := &PermissionsClient{host: host, httpCli: httpclient}

		params := &ParametersMock{
			CreateGetPermissionsRequestFunc: func(host string) (*http.Request, error) {
				return nil, errors.New("i am borked")
			},
		}

		Convey("when get caller permissions is invoked", func() {
			actual, err := permissionsClient.GetCallerPermissions(nil, params)

			Convey("then permissions is nil", func() {
				So(actual, ShouldBeNil)
			})

			Convey("and the expected error is returned", func() {
				So(err, ShouldResemble, errors.New("i am borked"))
			})

			Convey("and params.CreateGetPermissionsRequest is called 1 time with the expected parameters", func() {
				calls := params.CreateGetPermissionsRequestCalls()
				So(calls, ShouldHaveLength, 1)
				So(calls[0].Host, ShouldEqual, host)
			})

			Convey("and httpclient.Do is never called", func() {
				So(httpclient.DoCalls(), ShouldHaveLength, 0)
			})
		})
	})

	Convey("given httpclient.Do returns an error", t, func() {
		httpclient := &HTTPClienterMock{
			DoFunc: func(ctx context.Context, req *http.Request) (*http.Response, error) {
				return nil, errors.New("broken")
			},
		}

		request := httptest.NewRequest("GET", host, nil)

		permissionsClient := &PermissionsClient{host: host, httpCli: httpclient}

		params := &ParametersMock{
			CreateGetPermissionsRequestFunc: func(host string) (*http.Request, error) {
				return request, nil
			},
		}

		Convey("when get caller permissions is invoked", func() {
			actual, err := permissionsClient.GetCallerPermissions(nil, params)

			Convey("then permission is nil", func() {
				So(actual, ShouldBeNil)
			})

			Convey("and the expected error is returned", func() {
				permErr, ok := err.(Error)
				So(ok, ShouldBeTrue)
				So(permErr.Status, ShouldEqual, 500)
				So(permErr.Message, ShouldEqual, "get permissions request returned an error")
				So(permErr.Cause, ShouldResemble, errors.New("broken"))
			})

			Convey("and httpclient.Do is called 1 time with the expected parameters", func() {
				So(httpclient.DoCalls(), ShouldHaveLength, 1)
				So(httpclient.DoCalls()[0].Req, ShouldResemble, request)
			})
		})
	})

	Convey("given httpclient.Do returns an error entity", t, func() {
		response := &http.Response{
			Body: &readCloserMock{
				GetEntityFunc: func() ([]byte, error) {
					return json.Marshal(&errorEntity{Message: "internal server error"})
				},
			},
			StatusCode: 500,
		}

		httpclient := &HTTPClienterMock{
			DoFunc: func(ctx context.Context, req *http.Request) (*http.Response, error) {
				return response, nil
			},
		}

		request := httptest.NewRequest("GET", host, nil)

		permissionsClient := &PermissionsClient{host: host, httpCli: httpclient}

		params := &ParametersMock{
			CreateGetPermissionsRequestFunc: func(host string) (*http.Request, error) {
				return request, nil
			},
		}

		Convey("when get caller permissions is invoked", func() {
			actual, err := permissionsClient.GetCallerPermissions(nil, params)

			Convey("then permission is nil", func() {
				So(actual, ShouldBeNil)
			})

			Convey("and the expected error is returned", func() {
				So(err, ShouldResemble, getPermissionsUnauthorizedError)
			})

			Convey("and httpclient.Do is called 1 time with the expected parameters", func() {
				So(httpclient.DoCalls(), ShouldHaveLength, 1)
				So(httpclient.DoCalls()[0].Req, ShouldResemble, request)
			})
		})
	})

	Convey("given httpclient.Do returns an invalid entity", t, func() {
		response := &http.Response{
			Body: &readCloserMock{
				GetEntityFunc: func() ([]byte, error) {
					return json.Marshal("I am no valid")
				},
			},
			StatusCode: 200,
		}

		httpclient := &HTTPClienterMock{
			DoFunc: func(ctx context.Context, req *http.Request) (*http.Response, error) {
				return response, nil
			},
		}

		request := httptest.NewRequest("GET", host, nil)

		permissionsClient := &PermissionsClient{host: host, httpCli: httpclient}

		params := &ParametersMock{
			CreateGetPermissionsRequestFunc: func(host string) (*http.Request, error) {
				return request, nil
			},
		}

		Convey("when get caller permissions is invoked", func() {
			actual, err := permissionsClient.GetCallerPermissions(nil, params)

			Convey("then permission is nil", func() {
				So(actual, ShouldBeNil)
			})

			Convey("and the expected error is returned", func() {
				permErr, ok := err.(Error)
				So(ok, ShouldBeTrue)
				So(permErr.Status, ShouldEqual, 500)
				So(permErr.Message, ShouldEqual, "internal server error failed marshalling permissions response entity")
			})

			Convey("and httpclient.Do is called 1 time with the expected parameters", func() {
				So(httpclient.DoCalls(), ShouldHaveLength, 1)
				So(httpclient.DoCalls()[0].Req, ShouldResemble, request)
			})
		})
	})
}

func newReaderFunc(b []byte, err error) func() io.Reader {
	return func() io.Reader {
		return &readCloserMock{
			GetEntityFunc: func() (bytes []byte, e error) {
				return b, err
			},
		}
	}
}

func newReadCloserMock(b []byte, err error) *readCloserMock {
	return &readCloserMock{
		GetEntityFunc: func() (bytes []byte, e error) {
			return b, err
		},
	}
}

func newHttpCliMock(resp *http.Response, err error) *HTTPClienterMock {
	return &HTTPClienterMock{
		DoFunc: func(ctx context.Context, req *http.Request) (response *http.Response, e error) {
			return resp, err
		},
	}
}
