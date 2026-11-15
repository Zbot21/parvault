# Formal verification targets; see docs/VERIFY_RUNNER.md. Every variable passes through
# to scripts/verify.sh, e.g. `make verify-tlc SPEC=ParVaultProtocol`.
#
# Under pvjob (PVJOB_SRC_SHA is set) other jobs share the host, so TLC pins a smaller heap
# and Kani runs fewer workers unless you set them yourself.
ifdef PVJOB_SRC_SHA
TLC_HEAP_PCT ?= 30
KANI_JOBS ?= 16
else
TLC_HEAP_PCT ?= 70
endif

export TLC_HEAP_PCT KANI_JOBS TLC_WORKERS TLC_SHM_MIN_MB TLA2TOOLS_JAR SPEC HARNESS \
       KANI_SHARD_TARGETS FAIL_FAST VERIFY_MOLD VERIFY_LOG_DIR VERIFY_DRY_RUN

.PHONY: verify-tlc verify-kani verify-all verify-test verify-list test-verify-runner

verify-tlc:
	bash scripts/verify.sh tlc

verify-kani:
	bash scripts/verify.sh kani

verify-all:
	bash scripts/verify.sh all

# cargo test through the runner (VERIFY_MOLD=1 links with mold in its own target dir).
verify-test:
	bash scripts/verify.sh test $(TEST_ARGS)

verify-list:
	@bash scripts/verify.sh list-tlc
	@bash scripts/verify.sh list-kani

test-verify-runner:
	bash scripts/test_verify.sh
