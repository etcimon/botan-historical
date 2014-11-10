/*
* SecureQueue
* (C) 1999-2007 Jack Lloyd
*	  2012 Markus Wanner
*
* Distributed under the terms of the botan license.
*/
module botan.filters.secqueue;

import botan.filters.data_src;
import botan.filters.filter;

import std.algorithm;
/**
* A queue that knows how to zeroize itself
*/
final class SecureQueue : Fanout_Filter, DataSource
{
public:
	@property string name() const { return "Queue"; }

	/*
	* Add some bytes to the queue
	*/
	void write(in ubyte* input, size_t length)
	{
		if (!head)
			head = tail = new SecureQueueNode;
		while(length)
		{
			const size_t n = tail.write(input, length);
			input += n;
			length -= n;
			if (length)
			{
				tail.next = new SecureQueueNode;
				tail = tail.next;
			}
		}
	}

	/*
	* Read some bytes from the queue
	*/
	size_t read(ubyte* output, size_t length)
	{
		size_t got = 0;
		while(length && head)
		{
			const size_t n = head.read(output, length);
			output += n;
			got += n;
			length -= n;
			if (head.length == 0)
			{
				SecureQueueNode holder = head.next;
				delete head;
				head = holder;
			}
		}
		bytes_read += got;
		return got;
	}

	/*
	* Read data, but do not remove it from queue
	*/
	size_t peek(ubyte* output, size_t length, size_t offset = 0) const
	{
		SecureQueueNode current = head;
		
		while(offset && current)
		{
			if (offset >= current.length)
			{
				offset -= current.length;
				current = current.next;
			}
			else
				break;
		}
		
		size_t got = 0;
		while(length && current)
		{
			const size_t n = current.peek(output, length, offset);
			offset = 0;
			output += n;
			got += n;
			length -= n;
			current = current.next;
		}
		return got;
	}

	/**
	* Return how many bytes have been read so far.
	*/
	size_t get_bytes_read() const
	{
		return bytes_read;
	}

	/*
	* Test if the queue has any data in it
	*/
	bool end_of_data() const
	{
		return (size() == 0);
	}


	@property bool empty() const
	{
		return (size() == 0);
	}

	/**
	* @return number of bytes available in the queue
	*/
	size_t size() const
	{
		SecureQueueNode current = head;
		size_t count = 0;
		
		while(current)
		{
			count += current.length;
			current = current.next;
		}
		return count;
	}

	bool attachable() { return false; }

	/**
	* SecureQueue assignment
	* @param other the queue to copy
	*/
	SecureQueue opAssign(in SecureQueue input)
	{
		destroy();
		head = tail = new SecureQueueNode;
		SecureQueueNode temp = input.head;
		while(temp)
		{
			write(&temp.buffer[temp.start], temp.end - temp.start);
			temp = temp.next;
		}
		return this;
	}


	/**
	* SecureQueue default constructor (creates empty queue)
	*/
	this()
	{
		bytes_read = 0;
		set_next(null, 0);
		head = tail = new SecureQueueNode;
	}

	/**
	* SecureQueue copy constructor
	* @param other the queue to copy
	*/
	this(in SecureQueue input)
	{
		bytes_read = 0;
		set_next(null, 0);
		
		head = tail = new SecureQueueNode;
		SecureQueueNode temp = input.head;
		while(temp)
		{
			write(&temp.buffer[temp.start], temp.end - temp.start);
			temp = temp.next;
		}
	}

	~this() { destroy(); }
private:
	size_t bytes_read;

	/*
	* Destroy this SecureQueue
	*/
	void destroy()
	{
		SecureQueueNode temp = head;
		while(temp)
		{
			SecureQueueNode holder = temp.next;
			delete temp;
			temp = holder;
		}
		head = tail = null;
	}

	SecureQueueNode head;
	SecureQueueNode tail;
}

/**
* A node in a SecureQueue
*/
class SecureQueueNode
{
public:

	this() 
	{ 
		buffer = DEFAULT_BUFFERSIZE; 
		next = null; 
		start = end = 0; }
	
	~this() { 
		next = null; 
		start = end = 0; 
	}
	
	size_t write(in ubyte* input, size_t length)
	{
		size_t copied = std.algorithm.min(length, buffer.length - end);
		copy_mem(&buffer[end], input, copied);
		end += copied;
		return copied;
	}
	
	size_t read(ubyte* output, size_t length)
	{
		size_t copied = std.algorithm.min(length, end - start);
		copy_mem(output, &buffer[start], copied);
		start += copied;
		return copied;
	}
	
	size_t peek(ubyte* output, size_t length, size_t offset = 0)
	{
		const size_t left = end - start;
		if (offset >= left) return 0;
		size_t copied = std.algorithm.min(length, left - offset);
		copy_mem(output, &buffer[start + offset], copied);
		return copied;
	}
	
	size_t size() const { return (end - start); }
private:
	SecureQueueNode next;
	Secure_Vector!ubyte buffer;
	size_t start, end;
}