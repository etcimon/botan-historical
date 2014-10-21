/*
* Filter
* (C) 1999-2007 Jack Lloyd
* (C) 2013 Joel Low
*
* Distributed under the terms of the botan license.
*/
module botan.filters.filter;

import botan.alloc.secmem;
import vector;
import string;
import botan.filters.secqueue;
import botan.utils.exceptn;

/**
* This class represents general abstract filter objects.
*/
class Filter
{
public:
	/**
	* @return descriptive name for this filter
	*/
	abstract string name() const;

	/**
	* Write a portion of a message to this filter.
	* @param input the input as a ubyte array
	* @param length the length of the ubyte array input
	*/
	abstract void write(in ubyte* input, size_t length);

	/**
	* Start a new message. Must be closed by end_msg() before another
	* message can be started.
	*/
	abstract void start_msg() {}

	/**
	* Notify that the current message is finished; flush buffers and
	* do end-of-message processing (if any).
	*/
	abstract void end_msg() {}

	/**
	* Check whether this filter is an attachable filter.
	* @return true if this filter is attachable, false otherwise
	*/
	abstract bool attachable() { return true; }

	~this() {}
package:
	/**
	* @param input some input for the filter
	* @param length the length of in
	*/
	void send(in ubyte* input, size_t length)
	{
		if (!length)
			return;
		
		bool nothing_attached = true;
		for (size_t j = 0; j != total_ports(); ++j)
			if (next[j])
		{
			if (write_queue.length)
				next[j].write(&write_queue[0], write_queue.length);
			next[j].write(input, length);
			nothing_attached = false;
		}
		
		if (nothing_attached)
			write_queue += Pair(input, length);
		else
			write_queue.clear();
	}


	/**
	* @param input some input for the filter
	*/
	void send(ubyte input) { send(&input, 1); }

	/**
	* @param input some input for the filter
	*/
	void send(in SafeVector!ubyte input) { send(&input[0], input.length); }

	/**
	* @param input some input for the filter
	*/
	void send(in Vector!ubyte input) { send(&input[0], input.length); }

	/**
	* @param input some input for the filter
	* @param length the number of bytes of in to send
	*/
	void send(in SafeVector!ubyte input)
	{
		send(&input[0], length);
	}

	/**
	* @param input some input for the filter
	* @param length the number of bytes of in to send
	*/
	void send(in Vector!ubyte input)
	{
		send(&input[0], length);
	}

	/*
	* Filter Constructor
	*/
	this()
	{
		next.resize(1);
		port_num = 0;
		filter_owns = 0;
		owned = false;
	}

private:
	/**
	* Start a new message in this and all following filters. Only for
	* internal use, not intended for use in client applications.
	*/
	void new_msg()
	{
		start_msg();
		for (size_t j = 0; j != total_ports(); ++j)
			if (next[j])
				next[j].new_msg();
	}

	/**
	* End a new message in this and all following filters. Only for
	* internal use, not intended for use in client applications.
	*/
	void finish_msg()
	{
		end_msg();
		for (size_t j = 0; j != total_ports(); ++j)
			if (next[j])
				next[j].finish_msg();
	}

	/*
	* Return the total number of ports
	*/
	size_t total_ports() const
	{
		return next.length;
	}

	size_t current_port() const { return port_num; }

	/**
	* Set the active port
	* @param new_port the new value
	*/
	void set_port(size_t new_port)
	{
		if (new_port >= total_ports())
			throw new Invalid_Argument("Filter: Invalid port number");
		port_num = new_port;
	}

	size_t owns() const { return filter_owns; }

	/**
	* Attach another filter to this one
	* @param f filter to attach
	*/
	void attach(Filter new_filter)
	{
		if (new_filter)
		{
			Filter last = this;
			while(last.get_next())
				last = last.get_next();
			last.next[last.current_port()] = new_filter;
		}
	}

	/**
	* @param filters the filters to set
	* @param count number of items in filters
	*/
	void set_next(Filter* filters, size_t size)
	{
		next.clear();
		
		port_num = 0;
		filter_owns = 0;
		
		while(size && filters && (filters[size-1] == null))
			--size;
		
		if (filters && size)
			next.assign(filters, filters + size);
	}


	/*
	* Return the next Filter in the logical chain
	*/
	Filter get_next() const
	{
		if (port_num < next.length)
			return next[port_num];
		return null;
	}

	SafeVector!ubyte write_queue;
	Vector!Filter next;
	size_t port_num, filter_owns;

	// true if filter belongs to a pipe -. prohibit filter sharing!
	bool owned;
};

/**
* This is the abstract Fanout_Filter base class.
**/
class Fanout_Filter : Filter
{
package:
	/**
	* Increment the number of filters past us that we own
	*/
	void incr_owns() { ++filter_owns; }

	void set_port(size_t n) { set_port(n); }

	void set_next(Filter* f, size_t n) { set_next(f, n); }

	void attach(Filter f) { attach(f); }

/*private:
	using write_queue;
	using total_ports;
	using next;*/
};

/**
* The type of checking to be performed by decoders:
* NONE - no checks, IGNORE_WS - perform checks, but ignore
* whitespaces, FULL_CHECK - perform checks, also complain
* about white spaces.
*/
enum Decoder_Checking { NONE, IGNORE_WS, FULL_CHECK };
