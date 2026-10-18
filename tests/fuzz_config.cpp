// libFuzzer target: config INI parser
//
// Finds crashes, hangs, and assertion failures triggered by arbitrary
// user-supplied config file content.  The parser must never crash or
// invoke undefined behaviour on any byte sequence — it should only
// throw std::exception on invalid input.
//
// Build and run:
//   make fuzz-build
//   ./build/fuzz_config -max_total_time=3600 tests/corpus/config/

#include "../common/config.hpp"
#include <cstdint>
#include <cstdio>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    // Write the fuzz input to a temp file; Config::load() requires a path.
    const char* path = "/tmp/ztm_fuzz_config.conf";
    FILE* f = fopen(path, "wb");
    if (!f)
        return 0;
    fwrite(data, 1, size, f);
    fclose(f);

    try {
        Config::load(path);
    } catch (...) {
        // Throwing is fine — crashing is not.
    }
    return 0;
}
