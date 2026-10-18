// libFuzzer target: crypto blob decryption
//
// Finds crashes and UB triggered by arbitrary encrypted blobs received
// over the wire.  decrypt_message() must never crash on any input — it
// should only throw on authentication failure or malformed structure.
//
// The recipient identity is generated once and reused across iterations
// so the fuzzer spends time exploring blob parsing, not key generation.
//
// Build and run:
//   make fuzz-build
//   ./build/fuzz_crypto -max_total_time=3600 tests/corpus/crypto/

#include "../common/config.hpp"
#include "../common/crypto.hpp"
#include "../common/identity.hpp"
#include <botan/auto_rng.h>
#include <cstdint>
#include <vector>

// Persistent state — initialised once at process start.
static Botan::AutoSeeded_RNG g_rng;
static Config g_cfg;
static Identity g_recipient = generate_identity(g_rng, g_cfg);

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    std::vector<uint8_t> blob(data, data + size);
    try {
        decrypt_message(blob, g_recipient, g_rng, g_cfg);
    } catch (...) {
        // Throwing is fine — crashing is not.
    }
    return 0;
}
