#pragma once
#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_set>
#include <vector>

// Tracks message nonces seen this session. Detects replayed blobs — a blob
// presented twice has the same sealed nonce and is silently dropped by the caller.
class ReplayGuard
{
    std::unordered_set<std::string> seen_;
    mutable std::mutex mutex_;

  public:
    // Returns true if this nonce is new (accept the message).
    // Returns false if it was already seen (replay — drop the message).
    bool check_and_insert(const std::vector<uint8_t>& nonce)
    {
        std::string key(nonce.begin(), nonce.end());
        std::lock_guard<std::mutex> lock(mutex_);
        return seen_.insert(key).second;
    }
};
