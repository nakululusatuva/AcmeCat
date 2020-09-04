//
// Created by nova on 8/28/20.
//

#include "ThreadPool.h"

ThreadPool::ThreadPool(size_t size)
{
	for (size_t i = 0; i < size; ++i)
	{
		std::thread([this]
		{
			std::unique_lock<std::mutex> lock(this->mutex);
			while (true)
			{
				if (!tasksQueue.empty())
				{
					auto task = std::move(tasksQueue.front());
					tasksQueue.pop();
					lock.unlock();
					task();
					lock.lock();
				}
				else if (shutdown) break;
				else condition.wait(lock);
			}
		}).detach();
	}
}

ThreadPool::~ThreadPool()
{
	std::lock_guard<std::mutex> lock(mutex);
	shutdown = true;
	condition.notify_all();
}

void ThreadPool::destroy()
{
	std::lock_guard<std::mutex> lock(mutex);
	shutdown = true;
	condition.notify_all();
}
