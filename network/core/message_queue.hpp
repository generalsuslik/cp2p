//
// Created by generalsuslik on 28.02.25.
//

#ifndef MESSAGE_QUEUE_H
#define MESSAGE_QUEUE_H

#include <condition_variable>
#include <deque>
#include <mutex>

namespace cp2p {


    /**
     * @brief Thread-safe message queue
     *
     * @tparam T type of data to pass via queue (Message, std::string)
     */
    template <typename T>
    class MessageQueue final {
    public:
        MessageQueue() = default;

        MessageQueue(const MessageQueue&) = delete;
        MessageQueue& operator=(const MessageQueue&) = delete;

        ~MessageQueue() {
            deque_.clear();
        }

        const T& front() {
            std::unique_lock lock(mutex_);
            cond_.wait(lock, [this] { return !deque_.empty(); });

            return deque_.front();
        }

        const T& back() {
            std::unique_lock lock(mutex_);
            cond_.wait(lock, [this] { return !deque_.empty(); });

            return deque_.back();
        }

        void push_front(const T& item) {
            std::lock_guard lock(mutex_);
            deque_.emplace_front(std::move(item));
            cond_.notify_one();
        }

        void push_back(const T& item) {
            std::lock_guard lock(mutex_);
            deque_.emplace_back(std::move(item));
            cond_.notify_one();
        }

        bool empty() {
            std::lock_guard lock(mutex_);
            return deque_.empty();
        }

        std::size_t size() {
            std::lock_guard lock(mutex_);
            return deque_.size();
        }

        void clear() {
            std::lock_guard lock(mutex_);
            deque_.clear();
            cond_.notify_one();
        }

        T pop_front() {
            std::lock_guard lock(mutex_);
            auto item = std::move(deque_.front());
            deque_.pop_front();
            cond_.notify_one();
            return item;
        }

        T pop_back() {
            std::lock_guard lock(mutex_);
            auto item = std::move(deque_.back());
            deque_.pop_back();
            cond_.notify_one();
            return item;
        }

    protected:
        std::mutex mutex_;
        std::deque<T> deque_;
        std::condition_variable cond_;
    };


} // namespace cp2p


#endif //MESSAGE_QUEUE_H
