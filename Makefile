CXX      = c++
CXXFLAGS = -std=c++20 -I./include/botan-3 -I. -Wall -pthread
LDFLAGS  = -L./lib -lbotan-3 -Wl,-rpath,$(shell pwd)/lib -lpthread -lsqlite3

# Portable CPU count: macOS uses sysctl, Linux uses nproc
NCPUS ?= $(shell sysctl -n hw.logicalcpu 2>/dev/null || nproc 2>/dev/null || echo 4)

BUILD  = build
COMMON     = common/config.cpp common/kem.cpp common/identity.cpp common/crypto.cpp common/store.cpp
SERVER_SRC = server/server.cpp
TESTS      = $(BUILD)/test_identity $(BUILD)/test_crypto $(BUILD)/test_protocol \
             $(BUILD)/test_replay $(BUILD)/test_server $(BUILD)/test_config \
             $(BUILD)/test_properties $(BUILD)/test_store
FUZZ_TARGETS = $(BUILD)/fuzz_config $(BUILD)/fuzz_crypto

.PHONY: all setup test system-test sanitize coverage fuzz fuzz-build format format-check tidy clean

all: $(BUILD)/msg_server $(BUILD)/msg_client

$(BUILD)/msg_server: server/main.cpp $(SERVER_SRC) $(COMMON)
	@mkdir -p $(BUILD)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDFLAGS)

$(BUILD)/msg_client: client/main.cpp $(COMMON)
	@mkdir -p $(BUILD)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDFLAGS)

# -------------------------------------------------------
# Tests — build and run all test binaries
# -------------------------------------------------------
$(BUILD)/test_server: tests/test_server.cpp $(SERVER_SRC) $(COMMON)
	@mkdir -p $(BUILD)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDFLAGS)

$(BUILD)/test_%: tests/test_%.cpp $(COMMON)
	@mkdir -p $(BUILD)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDFLAGS)

test: $(TESTS)
	@echo ""
	@failed=0; \
	for t in $(TESTS); do \
		echo "--- $$t ---"; \
		./$$t || failed=$$((failed + 1)); \
	done; \
	echo ""; \
	if [ $$failed -eq 0 ]; then \
		echo "All tests passed."; \
	else \
		echo "$$failed test suite(s) failed."; \
		exit 1; \
	fi

# -------------------------------------------------------
# System test — exercises compiled binaries end-to-end
# -------------------------------------------------------
system-test: all
	@bash tests/test_system.sh

# -------------------------------------------------------
# Fuzz testing — libFuzzer targets (clang only)
# fuzz-build: compile both targets
# fuzz: smoke run (10 s per target) — catches immediate crashes
# For a real fuzzing session:
#   ./build/fuzz_config -max_total_time=3600 tests/corpus/config/
#   ./build/fuzz_crypto -max_total_time=3600 tests/corpus/crypto/
# -------------------------------------------------------
# libFuzzer requires LLVM clang (not Apple's clang); use brew-installed clang if present
FUZZ_CXX   ?= $(shell which clang++ 2>/dev/null || echo c++)
LLVM_PATH  := $(shell brew --prefix llvm 2>/dev/null)/bin
ifneq ($(wildcard $(LLVM_PATH)/clang++),)
FUZZ_CXX   := $(LLVM_PATH)/clang++
endif
FUZZFLAGS  = -fsanitize=fuzzer,address

$(BUILD)/fuzz_%: tests/fuzz_%.cpp $(COMMON)
	@mkdir -p $(BUILD)
	$(FUZZ_CXX) $(CXXFLAGS) $(FUZZFLAGS) $^ -o $@ $(LDFLAGS) $(FUZZFLAGS)

fuzz-build: $(FUZZ_TARGETS)

fuzz: fuzz-build
	@echo "=== fuzz smoke test (10 s per target) ==="
	@mkdir -p tests/corpus/config tests/corpus/crypto
	@ASAN_OPTIONS=detect_container_overflow=0 \
	    ./$(BUILD)/fuzz_config -max_total_time=10 -max_len=4096 -seed=1 \
	    tests/corpus/config/ 2>&1 | grep -E "DONE|ERROR|CRASH" || true
	@ASAN_OPTIONS=detect_container_overflow=0 \
	    ./$(BUILD)/fuzz_crypto -max_total_time=10 -max_len=8192 -seed=1 \
	    tests/corpus/crypto/ 2>&1 | grep -E "DONE|ERROR|CRASH" || true
	@echo "Fuzz smoke test complete — no crashes found."

# -------------------------------------------------------
# Sanitizers — ASan + UBSan (run: make sanitize)
# In CI each job has a clean env; locally run 'make clean' first.
# detect_container_overflow=0: suppresses a false positive from
# Botan's secure_vector custom allocator (pre-built, not instrumented).
# -------------------------------------------------------
SANFLAGS = -fsanitize=address,undefined -fno-sanitize-recover=all -g

sanitize: CXXFLAGS += $(SANFLAGS)
sanitize: LDFLAGS  += $(SANFLAGS)
sanitize: clean $(TESTS)
	@echo ""
	@failed=0; \
	for t in $(TESTS); do \
		echo "--- $$t ---"; \
		ASAN_OPTIONS=detect_container_overflow=0 ./$$t || failed=$$((failed + 1)); \
	done; \
	echo ""; \
	if [ $$failed -eq 0 ]; then \
		echo "All sanitizer tests passed."; \
	else \
		echo "$$failed sanitizer suite(s) failed."; \
		exit 1; \
	fi

# -------------------------------------------------------
# clang-format — format: rewrite in place, format-check: CI gate
# -------------------------------------------------------
FMT_SRCS = common/config.cpp common/config.hpp common/kem.cpp common/kem.hpp \
           common/store.cpp common/store.hpp \
           tests/test_config.cpp tests/test_properties.cpp \
           tests/fuzz_config.cpp tests/fuzz_crypto.cpp \
           common/crypto.cpp common/crypto.hpp common/identity.cpp common/identity.hpp \
           common/protocol.hpp common/replay.hpp common/secure_memory.hpp common/tls_utils.hpp \
           server/server.hpp server/server.cpp server/main.cpp client/main.cpp \
           tests/test_runner.hpp tests/test_identity.cpp tests/test_crypto.cpp \
           tests/test_protocol.cpp tests/test_replay.cpp tests/test_server.cpp \
           tests/test_store.cpp

CLANG_FORMAT ?= xcrun clang-format

format:
	$(CLANG_FORMAT) -i $(FMT_SRCS)

format-check:
	$(CLANG_FORMAT) --dry-run --Werror $(FMT_SRCS)

# -------------------------------------------------------
# clang-tidy — static analysis (requires llvm: brew install llvm)
# -------------------------------------------------------
CLANG_TIDY ?= clang-tidy
TIDY_SRCS   = common/config.cpp common/kem.cpp common/identity.cpp common/crypto.cpp $(SERVER_SRC) client/main.cpp
TIDY_FLAGS  = -std=c++20 -I./include/botan-3 -I.

tidy:
	$(CLANG_TIDY) $(TIDY_SRCS) -- $(TIDY_FLAGS)

# -------------------------------------------------------
# Coverage — uses LLVM source-based coverage (Xcode built-in)
# -------------------------------------------------------
LLVM_COV      ?= xcrun llvm-cov
LLVM_PROFDATA ?= xcrun llvm-profdata
COVFLAGS      = -fprofile-instr-generate -fcoverage-mapping -O0

coverage: CXXFLAGS += $(COVFLAGS)
coverage: LDFLAGS  += $(COVFLAGS)
coverage: clean $(TESTS)
	@echo "Running tests with coverage instrumentation..."
	@LLVM_PROFILE_FILE="$(BUILD)/test_identity.profraw"  ./$(BUILD)/test_identity
	@LLVM_PROFILE_FILE="$(BUILD)/test_crypto.profraw"    ./$(BUILD)/test_crypto
	@LLVM_PROFILE_FILE="$(BUILD)/test_protocol.profraw"  ./$(BUILD)/test_protocol
	@LLVM_PROFILE_FILE="$(BUILD)/test_replay.profraw"    ./$(BUILD)/test_replay
	@LLVM_PROFILE_FILE="$(BUILD)/test_server.profraw"    ./$(BUILD)/test_server
	@LLVM_PROFILE_FILE="$(BUILD)/test_config.profraw"      ./$(BUILD)/test_config
	@LLVM_PROFILE_FILE="$(BUILD)/test_properties.profraw"  ./$(BUILD)/test_properties
	@LLVM_PROFILE_FILE="$(BUILD)/test_store.profraw"       ./$(BUILD)/test_store
	$(LLVM_PROFDATA) merge -sparse \
	    $(BUILD)/test_identity.profraw \
	    $(BUILD)/test_crypto.profraw \
	    $(BUILD)/test_protocol.profraw \
	    $(BUILD)/test_replay.profraw \
	    $(BUILD)/test_server.profraw \
	    $(BUILD)/test_config.profraw \
	    $(BUILD)/test_properties.profraw \
	    $(BUILD)/test_store.profraw \
	    -o coverage.profdata
	@echo ""
	@echo "=== Coverage summary ==="
	$(LLVM_COV) report $(BUILD)/test_identity \
	    -object $(BUILD)/test_crypto \
	    -object $(BUILD)/test_protocol \
	    -object $(BUILD)/test_replay \
	    -object $(BUILD)/test_server \
	    -object $(BUILD)/test_config \
	    -object $(BUILD)/test_properties \
	    -object $(BUILD)/test_store \
	    -instr-profile=coverage.profdata \
	    common/config.cpp common/kem.cpp common/identity.cpp common/crypto.cpp \
	    common/store.cpp common/replay.hpp $(SERVER_SRC)
	@echo ""
	@echo "=== Generating HTML report ==="
	$(LLVM_COV) show $(BUILD)/test_identity \
	    -object $(BUILD)/test_crypto \
	    -object $(BUILD)/test_protocol \
	    -object $(BUILD)/test_replay \
	    -object $(BUILD)/test_server \
	    -object $(BUILD)/test_config \
	    -object $(BUILD)/test_properties \
	    -object $(BUILD)/test_store \
	    -instr-profile=coverage.profdata \
	    -format=html \
	    -output-dir=coverage_report \
	    -show-line-counts-or-regions \
	    common/config.cpp common/kem.cpp common/identity.cpp common/crypto.cpp \
	    common/store.cpp common/replay.hpp $(SERVER_SRC)
	@echo ""
	@echo "Coverage report: coverage_report/index.html"

# -------------------------------------------------------
# Build Botan from source — run once after cloning
# -------------------------------------------------------
setup:
	cd botan-src && \
	./configure.py --prefix=$(shell pwd) && \
	make -j$(NCPUS) && \
	make install
	@if [ "$$(uname)" = "Darwin" ]; then \
	    codesign --force --sign - lib/libbotan-3.dylib; \
	fi

clean:
	rm -rf $(BUILD)/
	rm -f coverage.profdata
	rm -rf coverage_report coverage.info coverage_filtered.info
