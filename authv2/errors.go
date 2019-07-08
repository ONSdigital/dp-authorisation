package authv2

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"net/http"

	"github.com/ONSdigital/log.go/log"
)

var (
	hostRequiredButEmptyError = Error{
		Status:  500,
		Message: "error creating get permissions request host required but was empty",
	}

	noUserOrServiceAuthTokenProvidedError = Error{
		Message: "invalid request require user or service auth token but none provide",
		Status:  400,
	}

	callerForbiddenError = Error{
		Message: "access denied caller does not have the required permissions to perform this action",
		Status:  403,
	}

	responseBodyNilError = Error{
		Status:  500,
		Message: "internal server error response body was nil",
	}
)

type Error struct {
	Status  int
	Message string
	Cause   error
}

func (e Error) Error() string {
	if e.Cause != nil {
		return e.Cause.Error()
	}
	return e.Message
}

func errorEntityToError(ctx context.Context, resp *http.Response) error {
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return Error{
			Status:  500,
			Message: "internal server error failed reading get permissions error response body",
			Cause:   err,
		}
	}

	var entity errorEntity
	if err = json.Unmarshal(body, &entity); err != nil {
		return Error{
			Status:  500,
			Message: "internal server error failed unmarshalling get permissions error response body",
			Cause:   err,
		}
	}

	log.Event(ctx, "get caller permissions request returned an error status", log.Data{
		"status_code": resp.StatusCode,
		"body":        entity,
	})

	permErr := statusCodeToError(resp.StatusCode)
	log.Event(ctx, "mapped get permissions error response status to permissions.Error", log.Data{
		"original_error_status":     resp.StatusCode,
		"original_error_message":    entity.Message,
		"permissions_error_status":  permErr.Status,
		"permissions_error_message": permErr.Message,
	})
	return permErr
}

func statusCodeToError(status int) (err Error) {
	switch status {
	case 400, 401, 404:
		// treat as caller unauthorized
		return Error{Status: 401, Message: "unauthorized"}
	case 403:
		return Error{Status: 403, Message: "forbidden"}
	default:
		return Error{Status: 500, Message: "internal server error"}
	}
}
