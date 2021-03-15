example:
	go build -o ./example/example example/main.go
	go run -race example/main.go

test:
	go test -race -cover ./...

clean:
	rm example/example
.PHONY: example test clean

audit:
	go list -json -m all | nancy sleuth --exclude-vulnerability-file ./.nancy-ignore
.PHONY: audit

build:
	go build ./...
.PHONY: build