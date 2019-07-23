package auth

import (
	"net/http/httptest"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestNopHandler_Require(t *testing.T) {
	Convey("should invoke the provided handlerFunc", t, func() {
		Configure("test-test-123")
		authHandler := &NopHandler{}

		wrappedEndpoint := &HandlerMock{count: 0}

		authorisedOnly := authHandler.Require(Permissions{Create: true}, wrappedEndpoint.handleFunc)

		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "http://localhost:8080", nil)

		authorisedOnly.ServeHTTP(w, r)

		So(wrappedEndpoint.count, ShouldEqual, 1)
	})
}
