package authv2

var (
	hostRequiredButEmptyError = Error{
		Status:  500,
		Message: "error creating get permissions request host required but was empty",
	}

	noUserOrServiceAuthTokenProvidedError = Error{
		Message: "invalid request require user or service auth token but none provide",
		Status:  400,
	}

	callerUnauthorisedError = Error{
		Message: "access denied caller does not have the required permissions to perform this action",
		Status:  403,
	}

	userDatasetPermissionsURL    = "%s/userDatasetPermissions?dataset_id=%s&collection_id=%s"
	serviceDatasetPermissionsURL = "%s/serviceDatasetPermissions?dataset_id=%s"
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
