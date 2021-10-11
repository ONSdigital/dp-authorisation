package authorisation

import "time"

// Config contains the required configuration / environment variables for the typical authorisation setup
type Config struct {
	Enabled                             bool          `envconfig:"AUTHORISATION_ENABLED"`
	JWTVerificationPublicKey            string        `envconfig:"JWT_VERIFICATION_PUBLIC_KEY" json:"-"`
	PermissionsAPIURL                   string        `envconfig:"PERMISSIONS_API_URL"`
	PermissionsCacheUpdateInterval      time.Duration `envconfig:"PERMISSIONS_CACHE_UPDATE_INTERVAL"`
	PermissionsMaxCacheTime             time.Duration `envconfig:"PERMISSIONS_MAX_CACHE_TIME"`
	PermissionsCacheExpiryCheckInterval time.Duration `envconfig:"PERMISSIONS_CACHE_EXPIRY_CHECK_INTERVAL"`
}

// NewDefaultConfig populates the config struct with default values suitable for local development.
func NewDefaultConfig() *Config {
	return &Config{
		Enabled:                             false,
		JWTVerificationPublicKey:            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u+qKhbwKfBstIs+bMY2Zkp18gnTxKLxoS2tFczGkPLPgizskuemMghRniWaoLcyehkd3qqGElvW/VDL5AaWTg0nLVkjRo9z+40RQzuVaE8AkAFmxZzow3x+VJYKdjykkJ0iT9wCS0DRTXu269V264Vf/3jvredZiKRkgwlL9xNAwxXFg0x/XFw005UWVRIkdgcKWTjpBP2dPwVZ4WWC+9aGVd+Gyn1o0CLelf4rEjGoXbAAEgAqeGUxrcIlbjXfbcmwIDAQAB",
		PermissionsAPIURL:                   "http://localhost:25400",
		PermissionsCacheUpdateInterval:      time.Minute * 5,
		PermissionsMaxCacheTime:             time.Minute * 15,
		PermissionsCacheExpiryCheckInterval: time.Second * 10,
	}
}
