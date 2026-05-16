GOFLAGS         := -trimpath
BINARY          := dnssec-publish-ds
PROBE           := xymon-ext-dnssec
PKG_FLAGS       ?=
GO              ?= go
COMPLETIONS_DIR := completions

.PHONY: all build build-amd64 build-arm64 fmt vet test check ci completions man package-deb clean

all: check build completions man

build:
	CGO_ENABLED=0 $(GO) build $(GOFLAGS) $(if $(PKG_FLAGS),-ldflags "$(PKG_FLAGS)") -o $(BINARY) .

build-amd64:
	CGO_ENABLED=0 GOARCH=amd64 GOOS=linux $(GO) build $(GOFLAGS) -o $(BINARY)-linux-amd64 .

build-arm64:
	CGO_ENABLED=0 GOARCH=arm64 GOOS=linux $(GO) build $(GOFLAGS) -o $(BINARY)-linux-arm64 .

fmt:
	@$(GO) fmt ./...

test:
	@$(GO) test ./...

vet:
	@$(GO) vet ./...

check: fmt vet test

ci: check build-amd64

completions: build
	@mkdir -p $(COMPLETIONS_DIR)
	./$(BINARY) completion bash > $(COMPLETIONS_DIR)/$(BINARY).bash
	./$(BINARY) completion zsh > $(COMPLETIONS_DIR)/_$(BINARY)
	./$(BINARY) completion fish > $(COMPLETIONS_DIR)/$(BINARY).fish

man:
	@mkdir -p man
	gzip -kf man/$(BINARY).8
	gzip -kf man/$(PROBE).1

package-deb:
	dpkg-buildpackage -us -uc -b $(PKG_FLAGS)

clean:
	rm -f $(BINARY) $(BINARY)-linux-amd64 $(BINARY)-linux-arm64
	rm -rf $(COMPLETIONS_DIR)
	rm -f man/$(BINARY).8.gz man/$(PROBE).1.gz
