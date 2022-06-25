SHELL=bash

example:
	go build -o ./example/example example/main.go
	go run -race example/main.go
.PHONY: example

test:
	go test -race -cover ./...
.PHONY: test

clean:
	rm example/example
.PHONY: test

audit:
	set -o pipefail; go list -json -m all | nancy sleuth
.PHONY: audit

build:
	go build ./...
.PHONY: build

lint:
	golangci-lint --deadline=10m --fast --enable=gosec --enable=gocritic --enable=gofmt --enable=gocyclo --enable=bodyclose --enable=gocognit run
.PHONY: lint
