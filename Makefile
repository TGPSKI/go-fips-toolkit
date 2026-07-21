.PHONY: clone audit audit-first-party audit-component audit-json clean

REPOS_FILE ?= repos.txt

clone: ## Clone repos listed in REPOS_FILE (default: repos.txt)
	@test -f "$(REPOS_FILE)" || (echo "Create a repos.txt with one org/repo per line, or set REPOS_FILE=path" && exit 1)
	./audit/clone.sh $(REPOS_FILE)

audit: clone ## Run full audit with vendor summary
	./audit/audit-crypto.sh --vendor-summary

audit-first-party: clone ## Run audit on first-party code only
	./audit/audit-crypto.sh --first-party-only

audit-json: clone ## Run full audit with JSON output
	./audit/audit-crypto.sh --vendor-summary --json

audit-component: ## Audit a single component (COMPONENT=name)
	@test -n "$(COMPONENT)" || (echo "Usage: make audit-component COMPONENT=my-service" && exit 1)
	./audit/audit-crypto.sh --component $(COMPONENT) --json

clean: ## Remove audit results
	rm -f audit/results/*.txt audit/results/*.json

clean-repos: ## Remove cloned repos
	rm -rf repos/

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'
