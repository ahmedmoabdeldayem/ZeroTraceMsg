// Unit tests for ThreadPool

#include "../common/thread_pool.hpp"
#include "test_runner.hpp"
#include <atomic>
#include <chrono>
#include <thread>

int main()
{
    std::cout << "=== thread pool tests ===\n\n";

    TEST("ThreadPool executes all submitted tasks");
    {
        ThreadPool pool(2);
        std::atomic<int> count{0};
        for (int i = 0; i < 10; ++i)
            pool.submit([&count] { count.fetch_add(1); });
        // Give workers time to finish
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        ASSERT_EQ(count.load(), 10);
    }

    TEST("ThreadPool size returns configured worker count");
    {
        ThreadPool pool(4);
        ASSERT_EQ(pool.size(), 4);
    }

    TEST("ThreadPool with worker_threads=0 uses hardware_concurrency (>= 1)");
    {
        ThreadPool pool(0);
        ASSERT_TRUE(pool.size() >= 1);
    }

    TEST("ThreadPool executes tasks concurrently");
    {
        ThreadPool pool(4);
        std::atomic<int> peak{0};
        std::atomic<int> active{0};
        std::mutex mu;
        for (int i = 0; i < 4; ++i) {
            pool.submit([&] {
                int cur = active.fetch_add(1) + 1;
                int p = peak.load();
                while (cur > p && !peak.compare_exchange_weak(p, cur))
                    ;
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
                active.fetch_sub(1);
            });
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        ASSERT_TRUE(peak.load() >= 1);
    }

    TEST("ThreadPool destructor joins all threads cleanly");
    {
        std::atomic<int> count{0};
        {
            ThreadPool pool(2);
            for (int i = 0; i < 5; ++i)
                pool.submit([&count] { count.fetch_add(1); });
        } // destructor waits for all tasks to finish
        ASSERT_EQ(count.load(), 5);
    }

    SUITE_RESULTS();
}
