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
		JWTVerificationPublicKeys:      map[string]string{"XXcFBMOH6ldrCRYziR8SvEDSx2mVBWkqiXiBBiKTjxM=": "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu4oZvGdWclGAowaQOVeYNS7jBC9+jHVlk1uWsaA9wTYTsBfO1figVWqjalc4IOvZh1EERgrmoFOueL9/3PyFOxcFx9WePgFQoaM90uPesp584VB19kUq7tGlrlEej671bxARD+VRQqGDPWBDZdgW+D/a3qejqlFB6b3pTWOTKsskG6jY66oBNUW3ShHcKQZH/VL5s9oXVgZu88/KGkiQuorHhr0O43yoQ5WScrz3r72m2IkC53GOrsvefzoAz8A4Yy8eXFpmZqSAlY+jKEQycNaXT4XnsufU9g3wH/yVr/9i9Hta5lZnB+RXIV/igss7CE7yHLshgKBuAzY+gFVVZQIDAQAB", "jxYokzgTDyQUMoUS3G483hkEccxEJIJt+GV0+huREJA=": "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArcCrt0UB2S06x5AjppX9aU1d8wNQ2ODIBkdUWVNmbbHfZqVYfgjmvrYpBKo69ddYJg95g7mouqEVSWYlbsktbWQJGAWkaY3p8uIM36QJYAOlD3k8EnYA/3ptFEo8sY6+9MEIgXD4UBVLfz2YP3N73hk8cyDkEcV+riz74XJCfgKVtP2yyGDsNYzprHihDX4NgbTiaXVvrvrMGkiXSrkUKS9Fd1p0VvB0jgPtFYuD5HVVWmjWvva8+gLKozvUKi/nVU1iv1qKKmtKgPCsCiWg9ZMYjDcJDCw34SD1Nm/vu2/3h0zjDjlrRUKkXQo9SFs34otLQrPv+tfKljKTP7uktQIDAQAB"},
		PermissionsAPIURL:              "http://localhost:25400",
		ZebedeeURL:                     "http://localhost:8082",
		IdentityWebKeySetURL:           "http://localhost:25600",
		PermissionsCacheUpdateInterval: time.Minute * 1,
		PermissionsMaxCacheTime:        time.Minute * 5,
		IdentityClientMaxRetries:       2,
	}
}
