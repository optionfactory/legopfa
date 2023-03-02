VERSION=$(shell git describe --always --tags --dirty)
REPO_OWNER=optionfactory
REPO_NAME=legopfa
ARTIFACT_NAME=legopfa-$(VERSION)

build: 
	@echo reformatting…
	@gofmt -w=true -s=true *.go */*.go 
	@echo vetting…
	@CGO_ENABLED=0 go vet -ldflags "-X main.version=$(VERSION)" ./...
	@echo building…
	@CGO_ENABLED=0 go build -ldflags "-X main.version=$(VERSION)"
	@echo stripping…
	@strip legopfa

clean:
	rm -rf legopfa

release: build
	$(eval github_token=$(shell echo url=https://github.com/$(REPO_OWNER)/$(REPO_NAME) | git credential fill | grep '^password=' | sed 's/password=//'))
	$(eval release_id=$(shell curl -X POST \
		-H "Accept: application/vnd.github+json" \
		-H "Authorization: Bearer $(github_token)" \
		-H "X-GitHub-Api-Version: 2022-11-28" \
		https://api.github.com/repos/$(REPO_OWNER)/$(REPO_NAME)/releases \
	  	-d '{"tag_name":"$(VERSION)","name":"$(VERSION)"}' | jq .id))
	@curl -X POST \
		-H "Accept: application/vnd.github+json" \
		-H "Authorization: Bearer $(github_token)" \
		-H "X-GitHub-Api-Version: 2022-11-28" \
		-H "Content-Type: application/octet-stream" \
		https://uploads.github.com/repos/$(REPO_OWNER)/$(REPO_NAME)/releases/$(release_id)/assets?name=$(ARTIFACT_NAME) \
  		--data-binary "@legopfa"
