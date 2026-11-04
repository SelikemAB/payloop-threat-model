.PHONY: build check diagrams mutate
build:      ## validate and regenerate docs
	python3 scripts/build.py
check:      ## CI: validate and fail on stale generated files
	python3 scripts/build.py --check
diagrams:   ## render all Mermaid diagrams (set CHROME_PATH if mermaid-cli cannot find a browser)
	./scripts/check_diagrams.sh

mutate:     ## prove the validator can fail: known mistakes must be rejected
	python3 scripts/mutation_check.py
