example:
	go build -o ./example/example example/main.go
	go run -race example/main.go
.PHONY: example

test: test-v2
	go test -race -cover ./...
.PHONY: test

test-v2:
	cd v2 && make test
.PHONY: test-v2

clean:
	rm example/example
.PHONY: test

audit: audit-v2
	go list -json -m all | nancy sleuth
.PHONY: audit

audit-v2:
	cd v2 && make audit
.PHONY: audit-v2

build: build-v2
	go build ./...
.PHONY: build

build-v2:
	cd v2 && make build
.PHONY: build-v2

lint: lint-v2
	exit
.PHONY: lint

lint-v2:
	cd v2 && make lint
.PHONY: lint-v2
