#pragma once
#include <iostream>
#include <string>

static int _pass = 0, _fail = 0;
static std::string _current_test;

#define TEST(name) do { _current_test = (name); } while(0)

#define ASSERT_TRUE(expr) do { \
    if(!(expr)) { \
        std::cerr << "  FAIL [" << _current_test << "] " << #expr \
                  << " (" << __FILE__ << ":" << __LINE__ << ")\n"; \
        _fail++; \
    } else { _pass++; } \
} while(0)

#define ASSERT_EQ(a, b)   ASSERT_TRUE((a) == (b))
#define ASSERT_NE(a, b)   ASSERT_TRUE((a) != (b))
#define ASSERT_GT(a, b)   ASSERT_TRUE((a) >  (b))

#define ASSERT_THROWS(expr) do { \
    bool _threw = false; \
    try { (void)(expr); } catch(...) { _threw = true; } \
    if(!_threw) { \
        std::cerr << "  FAIL [" << _current_test << "] expected exception: " << #expr \
                  << " (" << __FILE__ << ":" << __LINE__ << ")\n"; \
        _fail++; \
    } else { _pass++; } \
} while(0)

#define ASSERT_NO_THROW(expr) do { \
    bool _threw = false; \
    try { (void)(expr); } catch(const std::exception& e) { \
        std::cerr << "  FAIL [" << _current_test << "] unexpected exception: " \
                  << e.what() << " (" << __FILE__ << ":" << __LINE__ << ")\n"; \
        _threw = true; \
    } \
    if(!_threw) _pass++; else _fail++; \
} while(0)

#define SUITE_RESULTS() do { \
    std::cout << "\nResults: " << _pass << " passed, " << _fail << " failed\n"; \
    return _fail > 0 ? 1 : 0; \
} while(0)
