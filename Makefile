VERSION=2.1
REPO_OWNER=optionfactory
REPO_NAME=legopfa

build: bin/$(REPO_NAME)-linux-amd64

bin/$(REPO_NAME)-linux-amd64: $(SRCS) go.mod
	@mkdir -p bin
	@echo "Formatting and vetting..."
	@go fmt ./...
	@go vet ./...
	@echo "Building $(REPO_NAME)..."
	@CGO_ENABLED=0 go build -ldflags="-s -w -X main.version=$(VERSION)" -o bin/$(REPO_NAME)-linux-amd64 .

clean:
	@echo "Removing $(REPO_NAME)..."
	@rm -rf bin/

check-updates:
	#go install golang.org/x/vuln/cmd/govulncheck@latest
	-@govulncheck -show verbose  ./...
	#go install github.com/securego/gosec/v2/cmd/gosec@latest
	-@gosec ./...
	@echo Available direct updates
	@go list -u -m -f '{{if and (not .Indirect) .Update}}{{.Path}}: {{.Version}} -> {{.Update.Version}}{{end}}' all


publish-github: build
	@cd target && sha256sum $(REPO_NAME)-linux-amd64 > SHA256SUMS
	@gh release create "v$(VERSION)" \
		"target/$(REPO_NAME)-linux-amd64" \
		"target/SHA256SUMS" \
		--repo "$(REPO_OWNER)/$(REPO_NAME)" \
		--title "v$(VERSION)" \
		--target "master" \
		--notes ""
	-@rm target/SHA256SUMS
