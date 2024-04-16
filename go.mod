module github.com/ONSdigital/dp-authorisation

go 1.13

// to avoid the following vulnerabilities:
//     - CVE-2022-29153 # pkg:golang/github.com/hashicorp/consul/api@v1.1.0 and pkg:golang/github.com/hashicorp/consul/sdk@v0.1.1
//     - sonatype-2021-1401 # pkg:golang/github.com/miekg/dns@v1.0.14
//     - sonatype-2019-0890 # pkg:golang/github.com/pkg/sftp@v1.10.1
replace github.com/spf13/cobra => github.com/spf13/cobra v1.7.0

require (
	github.com/ONSdigital/dp-api-clients-go/v2 v2.254.1
	github.com/ONSdigital/dp-frontend-models v1.1.0 // indirect
	github.com/ONSdigital/dp-net/v2 v2.11.2 // indirect
	github.com/ONSdigital/log.go/v2 v2.4.3
	github.com/go-avro/avro v0.0.0-20171219232920-444163702c11 // indirect
	github.com/gorilla/mux v1.8.1
	github.com/gorilla/schema v1.1.0 // indirect
	github.com/smartystreets/goconvey v1.8.1
	github.com/unrolled/render v1.0.2 // indirect
)
