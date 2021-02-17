example:
	go build -o ./example/example example/main.go
	go run -race example/main.go

test:
	go test -race -cover ./...

clean:
	rm example/example
.PHONY: example test clean

audit:
	go list -m all | nancy sleuth
.PHONY: audit

build:
	go build ./...
.PHONY: build