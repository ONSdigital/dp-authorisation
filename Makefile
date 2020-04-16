build-example:
	go build -o ./example/example example/main.go

debug-example:
	go run -race example/main.go

test:
	go test -race -cover ./...

clean:
	rm example/example

.PHONY: build test clean
