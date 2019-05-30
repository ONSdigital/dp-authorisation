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

func (p *Permissions) Vet(ctx context.Context, required CRUD, serviceToken string, userToken string, collectionID string, datasetID string) error {
	data := log.Data{
		"collection_id": collectionID,
		"dataset_id":    datasetID,
		"user_token":    userToken != "",
		"service_token": serviceToken != "",
	}

	r, err := p.getPermissionsRequest(serviceToken, userToken, collectionID, datasetID)
	if err != nil {
		return err
	}

	resp, err := p.cli.Do(ctx, r)
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return getErrorFromResponse(resp)
	}

	callerPerms, err := unmarshalPermissions(resp.Body)
	if err != nil {
		log.Event(ctx, "error unmarshalling caller permissions json", log.Error(err), data)
		return err
	}

	return required.Satisfied(ctx, callerPerms)
}
