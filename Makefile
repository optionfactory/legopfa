VERSION=2.0
REPO_OWNER=optionfactory
REPO_NAME=legopfa

build: 
	@echo reformatting
	@gofmt -w=true -s=true *.go
	@echo vetting
	@CGO_ENABLED=0 go vet ./...
	@echo building
	@CGO_ENABLED=0 go build -ldflags "-s -w -X main.version=$(VERSION)"

clean:
	rm -rf legopfa


check-updates:
	#go install golang.org/x/vuln/cmd/govulncheck@latest
	-@govulncheck -show verbose  ./...
	#go install github.com/securego/gosec/v2/cmd/gosec@latest
	-@gosec ./...
	@echo Available direct updates
	@go list -u -m -f '{{if and (not .Indirect) .Update}}{{.Path}}: {{.Version}} -> {{.Update.Version}}{{end}}' all


publish-github: build
	gh release create "v$(VERSION)" \
		"legopfa#$(REPO_NAME)-linux-amd64" \
		--repo "$(REPO_OWNER)/$(REPO_NAME)" \
		--title "v$(VERSION)" \
		--target "master" \
		--notes ""
