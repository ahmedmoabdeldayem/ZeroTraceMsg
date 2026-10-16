#pragma once
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

// -------------------------------------------------------
// Per-test result tracking
// -------------------------------------------------------
struct _TestCase {
    std::string name;
    bool passed;
    std::string failure_msg;
    double duration_s;
};

static std::string _suite_name;
static std::string _current_test;
static bool _current_passed = true;
static std::string _current_failure;
static std::vector<_TestCase> _cases;
static int _pass = 0, _fail = 0;
static std::chrono::steady_clock::time_point _test_start;

static std::string _xml_escape(const std::string& s)
{
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        switch (c) {
        case '<':
            out += "&lt;";
            break;
        case '>':
            out += "&gt;";
            break;
        case '&':
            out += "&amp;";
            break;
        case '"':
            out += "&quot;";
            break;
        case '\'':
            out += "&apos;";
            break;
        default:
            out += c;
            break;
        }
    }
    return out;
}

// Called by TEST() and SUITE_RESULTS() to close out the current test case.
static void _finalize_current()
{
    if (_current_test.empty())
        return;
    double dur =
        std::chrono::duration<double>(std::chrono::steady_clock::now() - _test_start).count();
    _cases.push_back({_current_test, _current_passed, _current_failure, dur});
    _current_test.clear();
    _current_passed = true;
    _current_failure.clear();
}

static void _write_junit_xml()
{
    if (_suite_name.empty())
        return;
    std::filesystem::create_directories("test-results");
    std::ofstream f("test-results/" + _suite_name + ".xml");
    if (!f)
        return;

    int fail_count = 0;
    double total_time = 0;
    for (auto& c : _cases) {
        if (!c.passed)
            fail_count++;
        total_time += c.duration_s;
    }

    f << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
    f << "<testsuite"
      << " name=\"" << _xml_escape(_suite_name) << "\""
      << " tests=\"" << _cases.size() << "\""
      << " failures=\"" << fail_count << "\""
      << " time=\"" << total_time << "\">\n";

    for (auto& c : _cases) {
        f << "  <testcase"
          << " name=\"" << _xml_escape(c.name) << "\""
          << " classname=\"" << _xml_escape(_suite_name) << "\""
          << " time=\"" << c.duration_s << "\"";
        if (c.passed) {
            f << "/>\n";
        } else {
            f << ">\n"
              << "    <failure message=\"" << _xml_escape(c.failure_msg) << "\""
              << " type=\"AssertionError\">" << _xml_escape(c.failure_msg) << "</failure>\n"
              << "  </testcase>\n";
        }
    }
    f << "</testsuite>\n";
}

// -------------------------------------------------------
// Public macros
// -------------------------------------------------------

// Call once at the start of main() to name this suite and enable XML output.
#define SUITE_INIT(name)                                                                           \
    do {                                                                                           \
        _suite_name = (name);                                                                      \
    } while (0)

// Begin a new named test case. Finalizes the previous one.
#define TEST(name)                                                                                 \
    do {                                                                                           \
        _finalize_current();                                                                       \
        _current_test = (name);                                                                    \
        _current_passed = true;                                                                    \
        _current_failure.clear();                                                                  \
        _test_start = std::chrono::steady_clock::now();                                            \
    } while (0)

#define ASSERT_TRUE(expr)                                                                          \
    do {                                                                                           \
        if (!(expr)) {                                                                             \
            std::string _msg = std::string("  FAIL [") + _current_test + "] " + #expr + " (" +     \
                               __FILE__ + ":" + std::to_string(__LINE__) + ")";                    \
            std::cerr << _msg << "\n";                                                             \
            if (_current_failure.empty())                                                          \
                _current_failure = _msg;                                                           \
            _current_passed = false;                                                               \
            _fail++;                                                                               \
        } else {                                                                                   \
            _pass++;                                                                               \
        }                                                                                          \
    } while (0)

#define ASSERT_EQ(a, b) ASSERT_TRUE((a) == (b))
#define ASSERT_NE(a, b) ASSERT_TRUE((a) != (b))
#define ASSERT_GT(a, b) ASSERT_TRUE((a) > (b))

#define ASSERT_THROWS(expr)                                                                        \
    do {                                                                                           \
        bool _threw = false;                                                                       \
        try {                                                                                      \
            (void)(expr);                                                                          \
        } catch (...) {                                                                            \
            _threw = true;                                                                         \
        }                                                                                          \
        if (!_threw) {                                                                             \
            std::string _msg = std::string("  FAIL [") + _current_test +                           \
                               "] expected exception: " + #expr + " (" + __FILE__ + ":" +          \
                               std::to_string(__LINE__) + ")";                                     \
            std::cerr << _msg << "\n";                                                             \
            if (_current_failure.empty())                                                          \
                _current_failure = _msg;                                                           \
            _current_passed = false;                                                               \
            _fail++;                                                                               \
        } else {                                                                                   \
            _pass++;                                                                               \
        }                                                                                          \
    } while (0)

#define ASSERT_NO_THROW(expr)                                                                      \
    do {                                                                                           \
        bool _threw = false;                                                                       \
        try {                                                                                      \
            (void)(expr);                                                                          \
        } catch (const std::exception& e) {                                                        \
            std::string _msg = std::string("  FAIL [") + _current_test +                           \
                               "] unexpected exception: " + e.what() + " (" + __FILE__ + ":" +     \
                               std::to_string(__LINE__) + ")";                                     \
            std::cerr << _msg << "\n";                                                             \
            if (_current_failure.empty())                                                          \
                _current_failure = _msg;                                                           \
            _threw = true;                                                                         \
            _current_passed = false;                                                               \
        }                                                                                          \
        if (!_threw)                                                                               \
            _pass++;                                                                               \
        else                                                                                       \
            _fail++;                                                                               \
    } while (0)

// Finalizes the last test case, writes JUnit XML, prints the summary line.
#define SUITE_RESULTS()                                                                            \
    do {                                                                                           \
        _finalize_current();                                                                       \
        _write_junit_xml();                                                                        \
        std::cout << "\nResults: " << _pass << " passed, " << _fail << " failed\n";                \
        return _fail > 0 ? 1 : 0;                                                                  \
    } while (0)
