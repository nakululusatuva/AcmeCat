//
// Created by nova on 8/28/20.
//

#ifndef ACMECAT_THREADPOOL_H
#define ACMECAT_THREADPOOL_H

#include <iostream>
#include <mutex>
#include <thread>
#include <vector>
#include <queue>
#include <functional>
#include <atomic>
#include <condition_variable>

class ThreadPool
{
public:
	explicit ThreadPool(size_t size);
	~ThreadPool();
	void destroy();
	template <class Func, class... Args> inline void execute(Func&& task, Args&&... args)
	{
		std::lock_guard<std::mutex> lock(mutex);
		tasksQueue.emplace(std::bind(std::forward<Func>(task), maybe_wrap(std::forward<Args>(args))...));
		condition.notify_one();
	}
private:
	std::mutex mutex;
	std::condition_variable condition;
	bool shutdown = false;
	std::queue<std::function<void()>> tasksQueue;
	/* Forwarding of references with std::bind inside the variadic template.
	 * lvalues turn into reference wrappers, rvalues stay as rvalue references */
	template <class T> std::reference_wrapper<T> maybe_wrap(T& val) { return std::ref(val); }
	template <class T> T&& maybe_wrap(T&& val) { return std::forward<T>(val); }
};

#endif //ACMECAT_THREADPOOL_H
