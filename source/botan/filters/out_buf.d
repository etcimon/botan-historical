/*
* Output Buffer
* (C) 1999-2007 Jack Lloyd
*	  2012 Markus Wanner
*
* Distributed under the terms of the botan license.
*/
module botan.filters.out_buf;

import botan.utils.types;
import botan.filters.pipe;
import deque;
import botan.filters.secqueue;
/**
* Container of output buffers for Pipe
*/
class Output_Buffers
{
public:
	/*
	* Read data from a message
	*/
	size_t read(ubyte* output, size_t length,
	            Pipe.message_id msg)
	{
		SecureQueue* q = get(msg);
		if (q)
			return q.read(output, length);
		return 0;
	}

	/*
	* Peek at data in a message
	*/
	size_t peek(ubyte* output, size_t length,
	            size_t stream_offset,
	            Pipe.message_id msg) const
	{
		SecureQueue* q = get(msg);
		if (q)
			return q.peek(output, length, stream_offset);
		return 0;
	}

	/*
	* Return the total bytes of a message that have already been read.
	*/
	size_t get_bytes_read(Pipe.message_id msg) const
	{
		SecureQueue* q = get(msg);
		if (q)
			return q.get_bytes_read();
		return 0;
	}

	/*
	* Check available bytes in a message
	*/
	size_t remaining(Pipe.message_id msg) const
	{
		SecureQueue* q = get(msg);
		if (q)
			return q.length;
		return 0;
	}

	/*
	* Add a new output queue
	*/
	void add(SecureQueue* queue)
	{
		BOTAN_ASSERT(queue, "queue was provided");
		
		BOTAN_ASSERT(buffers.length < buffers.max_size(),
		             "Room was available in container");
		
		buffers.push_back(queue);
	}

	/*
	* Retire old output queues
	*/
	void retire()
	{
		for (size_t i = 0; i != buffers.length; ++i)
			if (buffers[i] && buffers[i].length == 0)
		{
			delete buffers[i];
			buffers[i] = null;
		}
		
		while(buffers.length && !buffers[0])
		{
			buffers.pop_front();
			offset = offset + Pipe.message_id(1);
		}
	}

	/*
	* Return the total number of messages
	*/
	Pipe.message_id message_count() const
	{
		return (offset + buffers.length);
	}

	this() { offset = 0; }
	~this()
	{
		for (size_t j = 0; j != buffers.length; ++j)
			delete buffers[j];
	}
private:
	/*
	* Get a particular output queue
	*/
	SecureQueue* get(Pipe.message_id msg) const
	{
		if (msg < offset)
			return null;
		
		BOTAN_ASSERT(msg < message_count(), "Message number is in range");
		
		return buffers[msg-offset];
	}

	std::deque<SecureQueue*> buffers;
	Pipe.message_id offset;
};
