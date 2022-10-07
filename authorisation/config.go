package authorisation

import "time"

// Config contains the required configuration / environment variables for the typical authorisation setup
type Config struct {
	Enabled                        bool              `envconfig:"AUTHORISATION_ENABLED"`
	JWTVerificationPublicKeys      map[string]string `envconfig:"JWT_VERIFICATION_PUBLIC_KEYS" json:"-"`
	PermissionsAPIURL              string            `envconfig:"PERMISSIONS_API_URL"`
	PermissionsCacheUpdateInterval time.Duration     `envconfig:"PERMISSIONS_CACHE_UPDATE_INTERVAL"`
	PermissionsMaxCacheTime        time.Duration     `envconfig:"PERMISSIONS_MAX_CACHE_TIME"`
	ZebedeeURL                     string            `envconfig:"ZEBEDEE_URL"`
	IdentityWebKeySetURL           string            `envconfig:"IDENTITY_WEB_KEY_SET_URL"`
	IdentityClientMaxRetries       int               `envconfig:"AUTHORISATION_IDENTITY_CLIENT_MAX_RETRIES"`
}

// NewDefaultConfig populates the config struct with default values suitable for local development.
func NewDefaultConfig() *Config {
	return &Config{
		JWTVerificationPublicKeys:      map[string]string{"NeKb65194Jo=": "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA0TpTemKodQNChMNj1f/NF19nMAbjKbwRENSKujO5iwXLIt0hCjh5dz4egKQo7KEr2ex3qdy50LWKD871gRfAgDoRD5/1kUUVqII5K09IDCVY/EohukrI+Uep/Z5ymPNPXXD1yJvBx/YmmuMGUAT5UKHKBCP+FcoAxYAKcaKhtL0iyVjhtD0Y4V8gcQnQq3bOYhF4FEHoHBNh23AKcJM1VvNVtSHViMuTOzsFLHAgy2lLsRLnxtXovEovAiTay+Sn1FuDOq2gswl2Uujh1GO8kfkXE1gNRn/l7RUYIRrql8kROHMSYvPBAIqYhGSWOG3JX1oFlI1erYaeIPI4l4Qj/P+YSnrRx0di3vy6ZDAnhs8kdZP81F+3rFrNUNIOVFBRKscMnvOH4HO4f9PpXynde5xTlVvqdgXVlWkxGgQk0d323ka8fPY1xsmxV99idmmgmfglPOeLxuOkFxfXJSpbP/kn9AEyKBcF2BImfc12uvdSn46zZ1f/8nvzQ9naruwEtho4t6cIb7A+5KxVAILCQHvm3xIxfxMy5RFIeR7T3KhW2URDtiGMKuEE44EQwtxXxnMUdmvBUyHg2iQ54ELD4uVVVkGZkT5cTIf8iwfWI808B+CE5T8I3YrK7DiaVkJqTWX9LqWqetwHQxY48iTN+nPguHQ6dkZwmxuWBEuQ9eECAwEAAQ=="},
		PermissionsAPIURL:              "http://localhost:25400",
		ZebedeeURL:                     "http://localhost:8082",
		IdentityWebKeySetURL:           "http://localhost:25600",
		PermissionsCacheUpdateInterval: time.Minute * 1,
		PermissionsMaxCacheTime:        time.Minute * 5,
		IdentityClientMaxRetries:       2,
	}
}
