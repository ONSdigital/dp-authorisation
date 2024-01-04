module github.com/ONSdigital/dp-authorisation/v2

go 1.19

// to avoid [CVE-2023-48795] CWE-354: Improper Validation of Integrity Check Value
replace golang.org/x/crypto => golang.org/x/crypto v0.17.0

require (
	github.com/ONSdigital/dp-api-clients-go/v2 v2.254.1
	github.com/ONSdigital/dp-healthcheck v1.6.2
	github.com/ONSdigital/dp-net/v2 v2.11.2
	github.com/ONSdigital/dp-permissions-api v0.22.0
	github.com/ONSdigital/log.go/v2 v2.4.3
	github.com/golang-jwt/jwt/v4 v4.5.0
	github.com/maxcnunes/httpfake v1.2.4
	github.com/pkg/errors v0.9.1
	github.com/smartystreets/goconvey v1.8.1
)

require (
	github.com/fatih/color v1.16.0 // indirect
	github.com/go-logr/logr v1.4.1 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/gopherjs/gopherjs v1.17.2 // indirect
	github.com/hokaccha/go-prettyjson v0.0.0-20211117102719-0474bc63780f // indirect
	github.com/jtolds/gls v4.20.0+incompatible // indirect
	github.com/justinas/alice v1.2.0 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/smarty/assertions v1.15.1 // indirect
	go.opentelemetry.io/otel v1.21.0 // indirect
	go.opentelemetry.io/otel/metric v1.21.0 // indirect
	go.opentelemetry.io/otel/trace v1.21.0 // indirect
	golang.org/x/net v0.19.0 // indirect
	golang.org/x/sys v0.16.0 // indirect
)
