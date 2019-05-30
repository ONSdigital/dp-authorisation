package permissions

import (
	"context"

	"github.com/ONSdigital/log.go/log"
)

func New(host string, httpClient HTTPClient) *Permissions {
	return &Permissions{
		host: host,
		cli:  httpClient,
	}
}

func (p *Permissions) Vet(ctx context.Context, required CRUD, serviceToken string, userToken string, collectionID string, datasetID string) (int, error) {
	data := log.Data{
		"collection_id": collectionID,
		"dataset_id":    datasetID,
		"user_token":    userToken != "",
		"service_token": serviceToken != "",
	}

	r, err := p.getPermissionsRequest(serviceToken, userToken, collectionID, datasetID)
	if err != nil {
		return 0, err
	}

	resp, err := p.cli.Do(ctx, r)
	if err != nil {
		return 0, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return handleErrorResponse(ctx, resp, data), nil
	}

	callerPerms, err := unmarshalPermissions(resp.Body)
	if err != nil {
		log.Event(ctx, "error unmarshalling caller permissions json", log.Error(err), data)
		return 500, err
	}

	// If the callers permissions do not satisfy the required permissions return a 403 - we know who they are but they
	// are not allowed to perform this action.
	if !required.Satisfied(ctx, callerPerms) {
		return 403, nil
	}
	return 200, nil
}
