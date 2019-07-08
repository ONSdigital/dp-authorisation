package authv2

type Permissions struct {
	Create bool
	Read   bool
	Update bool
	Delete bool
}

type PermissionsClient struct {
	host    string
	httpCli HTTPClienter
}

func NewPermissionsClient(host string, httpClient HTTPClienter) *PermissionsClient {
	return &PermissionsClient{
		host:    host,
		httpCli: httpClient,
	}
}

func (client *PermissionsClient) GetCallerPermissions(params Parameters) (callerPermissions *Permissions, err error) {
	return nil, nil
}
