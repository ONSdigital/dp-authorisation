SHELL=bash

test:
	go test -race -cover ./...
.PHONY: test

audit:
	set -o pipefail; go list -json -m all | nancy sleuth
.PHONY: audit
