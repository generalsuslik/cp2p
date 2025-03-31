//
// Created by generalsuslik on 28.02.25.
//

#ifndef MESSAGE_QUEUE_H
#define MESSAGE_QUEUE_H

#include <deque>
#include <mutex>

namespace cp2p {


    template <typename T>
    class MessageQueue {
    public:
        MessageQueue() = default;

        MessageQueue(const MessageQueue&) = delete;

        virtual ~MessageQueue() {
            deque_.clear();
        }

        const T& front() {
            std::scoped_lock lock(mutex_);
            return deque_.front();
        }

        const T& back() {
            std::scoped_lock lock(mutex_);
            return deque_.back();
        }

        void push_front(const T& item) {
            std::scoped_lock lock(mutex_);
            deque_.emplace_front(std::move(item));
        }

        void push_back(const T& item) {
            std::scoped_lock lock(mutex_);
            deque_.emplace_back(std::move(item));
        }

        bool empty() {
            std::scoped_lock lock(mutex_);
            return deque_.empty();
        }

        std::size_t size() {
            std::scoped_lock lock(mutex_);
            return deque_.size();
        }

        void clear() {
            std::scoped_lock lock(mutex_);
            deque_.clear();
        }

        T pop_front() {
            std::scoped_lock lock(mutex_);
            auto item = std::move(deque_.front());
            deque_.pop_front();
            return item;
        }

        T pop_back() {
            std::scoped_lock lock(mutex_);
            auto item = std::move(deque_.back());
            deque_.pop_back();
            return item;
        }

    protected:
        std::mutex mutex_;
        std::deque<T> deque_;
    };


} // namespace cp2p


#endif //MESSAGE_QUEUE_H
