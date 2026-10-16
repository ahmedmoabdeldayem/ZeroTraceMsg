CXX      = c++
CXXFLAGS = -std=c++20 -I./include/botan-3 -I. -Wall -pthread
LDFLAGS  = -L./lib -lbotan-3 -Wl,-rpath,$(shell pwd)/lib -lpthread

COMMON = common/identity.cpp common/crypto.cpp

TESTS = tests/test_identity tests/test_crypto tests/test_protocol

.PHONY: all setup test coverage clean

all: msg_server msg_client

msg_server: server/main.cpp $(COMMON)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDFLAGS)

msg_client: client/main.cpp $(COMMON)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDFLAGS)

# -------------------------------------------------------
# Tests — build and run all test binaries
# -------------------------------------------------------
tests/test_%: tests/test_%.cpp $(COMMON)
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
# Coverage — uses LLVM source-based coverage (Xcode built-in)
# No extra tools needed — llvm-cov and llvm-profdata ship with Xcode
# -------------------------------------------------------
LLVM_COV      = xcrun llvm-cov
LLVM_PROFDATA = xcrun llvm-profdata
COVFLAGS      = -fprofile-instr-generate -fcoverage-mapping -O0

coverage: CXXFLAGS += $(COVFLAGS)
coverage: LDFLAGS  += $(COVFLAGS)
coverage: clean $(TESTS)
	@echo "Running tests with coverage instrumentation..."
	@LLVM_PROFILE_FILE="tests/test_identity.profraw" ./tests/test_identity
	@LLVM_PROFILE_FILE="tests/test_crypto.profraw"   ./tests/test_crypto
	@LLVM_PROFILE_FILE="tests/test_protocol.profraw" ./tests/test_protocol
	$(LLVM_PROFDATA) merge -sparse tests/*.profraw -o coverage.profdata
	@echo ""
	@echo "=== Coverage summary ==="
	$(LLVM_COV) report tests/test_identity \
	    -instr-profile=coverage.profdata \
	    common/identity.cpp common/crypto.cpp
	@echo ""
	@echo "=== Generating HTML report ==="
	$(LLVM_COV) show tests/test_identity \
	    -instr-profile=coverage.profdata \
	    -format=html \
	    -output-dir=coverage_report \
	    -show-line-counts-or-regions \
	    common/identity.cpp common/crypto.cpp
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
	rm -f msg_server msg_client $(TESTS)
	rm -f *.gcda *.gcno common/*.gcda common/*.gcno tests/*.gcda tests/*.gcno
	rm -rf coverage_report coverage.info coverage_filtered.info
