.PHONY: ci-local

ci-local:
	@set -eu; \
	if [ -n "$$(git status --porcelain=v1 --untracked-files=normal)" ]; then \
		echo 'ci-local requires a clean committed HEAD' >&2; exit 1; \
	fi; \
	head="$$(git rev-parse HEAD)"; \
	npm ci --ignore-scripts --no-audit --no-fund; \
	npm run typecheck; \
	npm test; \
	npm run build; \
	npm run verify:pack; \
	npm audit --omit=dev --audit-level=moderate; \
	if [ "$$(git rev-parse HEAD)" != "$$head" ] || \
	   [ -n "$$(git status --porcelain=v1 --untracked-files=normal)" ]; then \
		echo 'ci-local HEAD or working tree changed during verification' >&2; exit 1; \
	fi; \
	printf '%s\n' "$$head" > "$$(git rev-parse --git-path ci-local-pass)"
