test:
	go test -count=1 -v -race -cover ./...
.PHONY: test

audit:
	go list -json -m all | nancy sleuth
.PHONY: audit

build:
	go build ./...
.PHONY: build

.PHONY: lint
lint:
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.64.5
	golangci-lint run ./...
