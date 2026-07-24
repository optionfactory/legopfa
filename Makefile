VERSION=2.0-dev
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

publish-github: build
	$(eval github_token=$(shell echo url=https://github.com/$(REPO_OWNER)/$(REPO_NAME) | git credential fill | grep '^password=' | sed 's/password=//'))
	$(eval release_id=$(shell curl -s -X POST \
		-H "Accept: application/vnd.github+json" \
		-H "Authorization: Bearer $(github_token)" \
		-H "X-GitHub-Api-Version: 2022-11-28" \
		https://api.github.com/repos/$(REPO_OWNER)/$(REPO_NAME)/releases \
	  	-d '{"tag_name":"v$(VERSION)","target_commitish":"master","name":"v$(VERSION)"}' | jq .id))
	@curl -X POST \
		-H "Accept: application/vnd.github+json" \
		-H "Authorization: Bearer $(github_token)" \
		-H "X-GitHub-Api-Version: 2022-11-28" \
		-H "Content-Type: application/octet-stream" \
		"https://uploads.github.com/repos/$(REPO_OWNER)/$(REPO_NAME)/releases/$(release_id)/assets?name=$(REPO_NAME)-linux-amd64" \
  		--data-binary "@legopfa"
