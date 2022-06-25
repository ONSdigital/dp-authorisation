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
	exit
.PHONY: lint
