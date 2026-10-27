#pragma once
#include <condition_variable>
#include <functional>
#include <mutex>
#include <queue>
#include <thread>
#include <vector>

// Fixed-size thread pool with unbounded task queue.
// Connections are processed by one of the worker threads instead of
// a freshly-spawned detached thread per connection.
class ThreadPool
{
  public:
    explicit ThreadPool(int num_threads)
    {
        int n =
            (num_threads > 0) ? num_threads : static_cast<int>(std::thread::hardware_concurrency());
        if (n < 1)
            n = 1;
        workers_.reserve(static_cast<size_t>(n));
        for (int i = 0; i < n; ++i)
            workers_.emplace_back([this] { worker_loop(); });
    }

    ~ThreadPool()
    {
        {
            std::lock_guard<std::mutex> lk(mutex_);
            stop_ = true;
        }
        cv_.notify_all();
        for (auto& t : workers_)
            if (t.joinable())
                t.join();
    }

    // Queue a task for execution by the next available worker thread.
    void submit(std::function<void()> task)
    {
        {
            std::lock_guard<std::mutex> lk(mutex_);
            queue_.push(std::move(task));
        }
        cv_.notify_one();
    }

    int size() const { return static_cast<int>(workers_.size()); }

    ThreadPool(const ThreadPool&) = delete;
    ThreadPool& operator=(const ThreadPool&) = delete;

  private:
    void worker_loop()
    {
        while (true) {
            std::function<void()> task;
            {
                std::unique_lock<std::mutex> lk(mutex_);
                cv_.wait(lk, [this] { return stop_ || !queue_.empty(); });
                if (stop_ && queue_.empty())
                    return;
                task = std::move(queue_.front());
                queue_.pop();
            }
            task();
        }
    }

    std::vector<std::thread> workers_;
    std::queue<std::function<void()>> queue_;
    std::mutex mutex_;
    std::condition_variable cv_;
    bool stop_{false};
};
