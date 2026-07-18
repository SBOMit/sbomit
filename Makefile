GO ?= go
BINARY ?= bin/sbomit

.PHONY: all build test fmt vet clean generate-sample

all: test build

build:
	mkdir -p $(dir $(BINARY))
	$(GO) build -o $(BINARY) .

test:
	$(GO) test ./...

fmt:
	$(GO) fmt ./...

vet:
	$(GO) vet ./...

generate-sample:
	$(GO) run . generate test/sample-attestation.json

clean:
	$(RM) $(BINARY)
	@if [ -d .gomodcache ]; then chmod -R u+w .gomodcache; fi
	$(RM) -r .gocache .gomodcache
