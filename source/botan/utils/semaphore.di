/*
* Semaphore
* by Pierre Gaston (http://p9as.blogspot.com/2012/06/c11-semaphores.html)
* modified by Joel Low for Botan
*
*/

#define BOTAN_SEMAPHORE_H__

import core.sync.mutex;
import condition_variable;
class Semaphore
{
	public:
		Semaphore(int value = 0) : m_value(value), m_wakeups(0) {}

		void acquire();

		void release(size_t n = 1);

	private:
		int m_value;
		int m_wakeups;
		Mutex m_mutex;
		std::condition_variable m_cond;
};