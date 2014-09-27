/*
* SecureQueue
* (C) 1999-2007 Jack Lloyd
*	  2012 Markus Wanner
*
* Distributed under the terms of the botan license.
*/

import botan.data_src;
import botan.filter;
/**
* A queue that knows how to zeroize itself
*/
class SecureQueue : public Fanout_Filter, public DataSource
{
	public:
		string name() const { return "Queue"; }

		void write(in byte*, size_t);

		size_t read(byte[], size_t);
		size_t peek(byte[], size_t, size_t = 0) const;
		size_t get_bytes_read() const;

		bool end_of_data() const;

		bool empty() const;

		/**
		* @return number of bytes available in the queue
		*/
		size_t size() const;

		bool attachable() { return false; }

		/**
		* SecureQueue assignment
		* @param other the queue to copy
		*/
		SecureQueue& operator=(in SecureQueue other);

		/**
		* SecureQueue default constructor (creates empty queue)
		*/
		SecureQueue();

		/**
		* SecureQueue copy constructor
		* @param other the queue to copy
		*/
		SecureQueue(in SecureQueue other);

		~SecureQueue() { destroy(); }
	private:
		size_t bytes_read;
		void destroy();
		class SecureQueueNode* head;
		class SecureQueueNode* tail;
};