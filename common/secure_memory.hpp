#pragma once
#include <botan/secmem.h>
#include <cstring>
#include <string>

// Passphrase and short sensitive strings.
// Backed by Botan's secure allocator: pages are mlock'd (not swappable)
// and zeroed automatically on deallocation.
using SecureString = Botan::secure_vector<char>;

inline SecureString make_secure(const char* s) { return SecureString(s, s + std::strlen(s)); }

inline SecureString make_secure(const std::string& s) { return SecureString(s.begin(), s.end()); }
