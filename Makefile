CXX      = c++
CXXFLAGS = -std=c++20 -I./include/botan-3 -I. -Wall -pthread
LDFLAGS  = -L./lib -lbotan-3 -Wl,-rpath,$(shell pwd)/lib -lpthread

BUILD  = build
COMMON     = common/identity.cpp common/crypto.cpp
SERVER_SRC = server/server.cpp
TESTS      = $(BUILD)/test_identity $(BUILD)/test_crypto $(BUILD)/test_protocol \
             $(BUILD)/test_replay $(BUILD)/test_server

.PHONY: all setup test sanitize coverage format format-check tidy clean

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
FMT_SRCS = common/crypto.cpp common/crypto.hpp common/identity.cpp common/identity.hpp \
           common/protocol.hpp common/replay.hpp common/secure_memory.hpp common/tls_utils.hpp \
           server/server.hpp server/server.cpp server/main.cpp client/main.cpp \
           tests/test_runner.hpp tests/test_identity.cpp tests/test_crypto.cpp \
           tests/test_protocol.cpp tests/test_replay.cpp tests/test_server.cpp

CLANG_FORMAT ?= xcrun clang-format

format:
	$(CLANG_FORMAT) -i $(FMT_SRCS)

format-check:
	$(CLANG_FORMAT) --dry-run --Werror $(FMT_SRCS)

# -------------------------------------------------------
# clang-tidy — static analysis (requires llvm: brew install llvm)
# -------------------------------------------------------
CLANG_TIDY ?= clang-tidy
TIDY_SRCS   = common/identity.cpp common/crypto.cpp $(SERVER_SRC) client/main.cpp
TIDY_FLAGS  = -std=c++20 -I./include/botan-3 -I.

tidy:
	$(CLANG_TIDY) $(TIDY_SRCS) -- $(TIDY_FLAGS)

# -------------------------------------------------------
# Coverage — uses LLVM source-based coverage (Xcode built-in)
# -------------------------------------------------------
LLVM_COV      = xcrun llvm-cov
LLVM_PROFDATA = xcrun llvm-profdata
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
	$(LLVM_PROFDATA) merge -sparse \
	    $(BUILD)/test_identity.profraw \
	    $(BUILD)/test_crypto.profraw \
	    $(BUILD)/test_protocol.profraw \
	    $(BUILD)/test_replay.profraw \
	    $(BUILD)/test_server.profraw \
	    -o coverage.profdata
	@echo ""
	@echo "=== Coverage summary ==="
	$(LLVM_COV) report $(BUILD)/test_identity \
	    -object $(BUILD)/test_crypto \
	    -object $(BUILD)/test_protocol \
	    -object $(BUILD)/test_replay \
	    -object $(BUILD)/test_server \
	    -instr-profile=coverage.profdata \
	    common/identity.cpp common/crypto.cpp common/replay.hpp $(SERVER_SRC)
	@echo ""
	@echo "=== Generating HTML report ==="
	$(LLVM_COV) show $(BUILD)/test_identity \
	    -object $(BUILD)/test_crypto \
	    -object $(BUILD)/test_protocol \
	    -object $(BUILD)/test_replay \
	    -object $(BUILD)/test_server \
	    -instr-profile=coverage.profdata \
	    -format=html \
	    -output-dir=coverage_report \
	    -show-line-counts-or-regions \
	    common/identity.cpp common/crypto.cpp common/replay.hpp $(SERVER_SRC)
	@echo ""
	@echo "Coverage report: coverage_report/index.html"

# -------------------------------------------------------
# Build Botan from source — run once after cloning
# -------------------------------------------------------
setup:
	cd botan-src && \
	./configure.py --prefix=$(shell pwd) && \
	make -j$(shell sysctl -n hw.logicalcpu) && \
	make install && \
	cd .. && \
	codesign --force --sign - lib/libbotan-3.dylib

clean:
	rm -rf $(BUILD)/
	rm -f coverage.profdata
	rm -rf coverage_report coverage.info coverage_filtered.info
