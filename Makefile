build-example:
	go build -o ./example/example example/main.go

test:
	go test -race -cover ./...

clean:
	rm example/example

.PHONY: build test clean
