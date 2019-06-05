package permissions

import (
	"context"

	"github.com/ONSdigital/log.go/log"
)

func New(host string, httpClient HTTPClienter) *Permissions {
	return &Permissions{
		host: host,
		cli:  httpClient,
	}
}

func (p *Permissions) Vet(ctx context.Context, required CRUD, serviceToken string, userToken string, collectionID string, datasetID string) error {
	r, err := p.getPermissionsRequest(serviceToken, userToken, collectionID, datasetID)
	if err != nil {
		return Error{
			Status:  500,
			Message: "error making get permissions http request",
			Cause:   err,
		}
	}

	resp, err := p.cli.Do(ctx, r)
	if err != nil {
		return Error{
			Status:  500,
			Message: "get permissions request returned an error",
			Cause:   err,
		}
	}

	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Event(ctx, "error closing response body", log.Error(err))
		}

	}()

	if resp.StatusCode != 200 {
		return getErrorFromResponse(r.Context(), resp)
	}

	callerPerms, err := unmarshalPermissions(resp.Body)
	if err != nil {
		return err
	}

	return required.Satisfied(ctx, callerPerms)
}
