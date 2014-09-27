/*
* Output Buffer
* (C) 1999-2007 Jack Lloyd
*	  2012 Markus Wanner
*
* Distributed under the terms of the botan license.
*/

import botan.types;
import botan.pipe;
import deque;
/**
* Container of output buffers for Pipe
*/
class Output_Buffers
{
	public:
		size_t read(byte[], size_t, Pipe::message_id);
		size_t peek(byte[], size_t, size_t, Pipe::message_id) const;
		size_t get_bytes_read(Pipe::message_id) const;
		size_t remaining(Pipe::message_id) const;

		void add(class SecureQueue*);
		void retire();

		Pipe::message_id message_count() const;

		Output_Buffers();
		~this();
	private:
		class SecureQueue* get(Pipe::message_id) const;

		std::deque<SecureQueue*> buffers;
		Pipe::message_id offset;
};