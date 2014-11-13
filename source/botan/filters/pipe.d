/*
* Pipe
* (C) 1999-2007 Jack Lloyd
*	  2012 Markus Wanner
*
* Distributed under the terms of the botan license.
*/
module botan.filters.pipe;

import botan.filters.data_src;
import botan.filters.filter;
import botan.utils.exceptn;
import initializer_list;
// import iosfwd; // std.stdio?
static if (BOTAN_HAS_PIPE_UNIXFD_IO && false)
	import botan.fd_unix;

import botan.filters.out_buf;
import botan.filters.secqueue;
import botan.utils.parsing;


/**
* This class represents pipe objects.
* A set of filters can be placed into a pipe, and information flows
* through the pipe until it reaches the end, where the output is
* collected for retrieval.  If you're familiar with the Unix shell
* environment, this design will sound quite familiar.
*/
struct Pipe
{
public:

	/**
	* An opaque type that identifies a message in this Pipe
	*/
	typedef size_t message_id;

	/**
	* Exception if you use an invalid message as an argument to
	* read, remaining, etc
	*/
	class Invalid_Message_Number : Invalid_Argument
	{
		/**
		* @param where the error occured
		* @param msg the invalid message id that was used
		*/
		this(in string where, message_id msg) {
			super("Pipe::" ~ where ~ ": Invalid message number " ~
			      std.conv.to!string(msg));
		}
	}

	/**
	* A meta-id for whatever the last message is
	*/
	static const message_id LAST_MESSAGE = cast(message_id)(-2);

	/**
	* A meta-id for the default message (set with set_default_msg)
	*/
	static const message_id DEFAULT_MESSAGE = cast(message_id)(-1);

	/**
	* Write input to the pipe, i.e. to its first filter.
	* @param input the ubyte array to write
	* @param length the length of the ubyte array in
	*/
	void write(in ubyte* input, size_t length)
	{
		if (!m_inside_msg)
			throw new Invalid_State("Cannot write to a Pipe while it is not processing");
		m_pipe_to.write(input, length);
	}

	/**
	* Write input to the pipe, i.e. to its first filter.
	* @param input the Secure_Vector containing the data to write
	*/
	void write(in Secure_Vector!ubyte input)
	{ write(&input[0], input.length); }

	/**
	* Write input to the pipe, i.e. to its first filter.
	* @param input the std::vector containing the data to write
	*/
	void write(in Vector!ubyte input)
	{ write(&input[0], input.length); }

	/**
	* Write input to the pipe, i.e. to its first filter.
	* @param input the string containing the data to write
	*/
	void write(in string input)
	{
		write(cast(const ubyte*)(input.data()), input.length);
	}

	/**
	* Write input to the pipe, i.e. to its first filter.
	* @param input the ubyte array containing the data to write
	*/
	void write(in ubyte[] input)
	{
		write(cast(const ubyte*)(input.ptr), input.length);
	}

	/**
	* Write input to the pipe, i.e. to its first filter.
	* @param input the DataSource to read the data from
	*/
	void write(DataSource source)
	{
		Secure_Vector!ubyte buffer = Secure_Vector!ubyte(DEFAULT_BUFFERSIZE);
		while(!source.end_of_data())
		{
			size_t got = source.read(&buffer[0], buffer.length);
			write(&buffer[0], got);
		}
	}

	/**
	* Write input to the pipe, i.e. to its first filter.
	* @param input a single ubyte to be written
	*/
	void write(ubyte input)
	{
		write(&input, 1);
	}

	/**
	* Write input to the pipe, i.e. to its first filter.
	* @param input a ubyte array to be written
	*/
	void write(in ubyte[] input)
	{
		write(input.ptr, input.length);
	}

	/**
	* Perform start_msg(), write() and end_msg() sequentially.
	* @param input the ubyte array containing the data to write
	* @param length the length of the ubyte array to write
	*/
	void process_msg(in ubyte* input, size_t length)
	{
		start_msg();
		write(input, length);
		end_msg();
	}

	/**
	* Perform start_msg(), write() and end_msg() sequentially.
	* @param input the Secure_Vector containing the data to write
	*/
	void process_msg(in Secure_Vector!ubyte input)
	{
		process_msg(&input[0], input.length);
	}

	/**
	* Perform start_msg(), write() and end_msg() sequentially.
	* @param input the Secure_Vector containing the data to write
	*/
	void process_msg(in Vector!ubyte input)
	{
		process_msg(&input[0], input.length);
	}

	/**
	* Perform start_msg(), write() and end_msg() sequentially.
	* @param input the string containing the data to write
	*/
	void process_msg(in string input)
	{
		process_msg(cast(const ubyte*)(input.data()), input.length);
	}

	/**
	* Perform start_msg(), write() and end_msg() sequentially.
	* @param input the DataSource providing the data to write
	*/
	void process_msg(DataSource input)
	{
		start_msg();
		write(input);
		end_msg();
	}

	/**
	* Find out how many bytes are ready to read.
	* @param msg the number identifying the message
	* for which the information is desired
	* @return number of bytes that can still be read
	*/
	size_t remaining(message_id msg = DEFAULT_MESSAGE) const
	{
		return m_outputs.remaining(get_message_no("remaining", msg));
	}

	/**
	* Read the default message from the pipe. Moves the internal
	* offset so that every call to read will return a new portion of
	* the message.
	*
	* @param output the ubyte array to write the read bytes to
	* @param length the length of the ubyte array output
	* @return number of bytes actually read into output
	*/
	size_t read(ubyte* output, size_t length)
	{
		return read(output, length, DEFAULT_MESSAGE);
	}

	/**
	* Read a specified message from the pipe. Moves the internal
	* offset so that every call to read will return a new portion of
	* the message.
	* @param output the ubyte array to write the read bytes to
	* @param length the length of the ubyte array output
	* @param msg the number identifying the message to read from
	* @return number of bytes actually read into output
	*/
	size_t read(ubyte* output, size_t length, message_id msg)
	{
		return m_outputs.read(output, length, get_message_no("read", msg));
	}

	/**
	* Read a specified message from the pipe. Moves the internal
	* offset so that every call to read will return a new portion of
	* the message.
	* @param output the ubyte array to write the read bytes to
	* @param msg the number identifying the message to read from
	* @return number of bytes actually read into output
	*/
	size_t read(ref ubyte[] output, message_id msg = DEFAULT_MESSAGE)
	{
		return m_outputs.read(output.ptr, output.length, get_message_no("read", msg));
	}

	/**
	* Read a single ubyte from the pipe. Moves the internal offset so
	* that every call to read will return a new portion of the
	* message.
	*
	* @param output the ubyte to write the result to
	* @param msg the message to read from
	* @return number of bytes actually read into output
	*/
	size_t read(ref ubyte output, message_id msg = DEFAULT_MESSAGE)
	{
		return read(&output, 1, msg);
	}

	/**
	* Read the full contents of the pipe.
	* @param msg the number identifying the message to read from
	* @return Secure_Vector holding the contents of the pipe
	*/
	Secure_Vector!ubyte read_all(message_id msg = DEFAULT_MESSAGE)
	{
		msg = ((msg != DEFAULT_MESSAGE) ? msg : default_msg());
		Secure_Vector!ubyte buffer = Secure_Vector!ubyte(remaining(msg));
		size_t got = read(&buffer[0], buffer.length, msg);
		buffer.resize(got);
		return buffer;
	}


	/**
	* Read the full contents of the pipe.
	* @param msg the number identifying the message to read from
	* @return string holding the contents of the pipe
	*/
	string toString(message_id msg = DEFAULT_MESSAGE)
	{
		msg = ((msg != DEFAULT_MESSAGE) ? msg : default_msg());
		Secure_Vector!ubyte buffer = Secure_Vector!ubyte(DEFAULT_BUFFERSIZE);
		string str;
		str.reserve(remaining(msg));
		
		while(true)
		{
			size_t got = read(&buffer[0], buffer.length, msg);
			if (got == 0)
				break;
			str.append(cast(string)(buffer[0]), got);
		}
		
		return str;
	}

	/** Read from the default message but do not modify the internal
	* offset. Consecutive calls to peek() will return portions of
	* the message starting at the same position.
	* @param output the ubyte array to write the peeked message part to
	* @param length the length of the ubyte array output
	* @param offset the offset from the current position in message
	* @return number of bytes actually peeked and written into output
	*/
	size_t peek(ubyte* output, size_t length,
	            size_t offset, message_id msg = DEFAULT_MESSAGE) const
	{
		return m_outputs.peek(output, length, offset, get_message_no("peek", msg));
	}

	/** Read from the specified message but do not modify the
	* internal offset. Consecutive calls to peek() will return
	* portions of the message starting at the same position.
	* @param output the ubyte array to write the peeked message part to
	* @param length the length of the ubyte array output
	* @param offset the offset from the current position in message
	* @param msg the number identifying the message to peek from
	* @return number of bytes actually peeked and written into output
	*/
	size_t peek(ref ubyte[] output,
	            size_t offset, message_id msg = DEFAULT_MESSAGE) const
	{
		return peek(output.ptr, output.length, offset, DEFAULT_MESSAGE);
	}

	/** Read a single ubyte from the specified message but do not
	* modify the internal offset. Consecutive calls to peek() will
	* return portions of the message starting at the same position.
	* @param output the ubyte to write the peeked message ubyte to
	* @param offset the offset from the current position in message
	* @param msg the number identifying the message to peek from
	* @return number of bytes actually peeked and written into output
	*/
	size_t peek(ref ubyte output, size_t offset,
				message_id msg = DEFAULT_MESSAGE) const
	{
		return peek(&output, 1, offset, msg);
	}

	/**
	* Read one ubyte.
	* @param output the ubyte to read to
	* @return length in bytes that was actually read and put
	* into out
	*/
	size_t read_byte(ref ubyte output)
	{
		return read(output.ptr[0..1]);
	}
	
	
	/**
	* Peek at one ubyte.
	* @param output an output ubyte
	* @return length in bytes that was actually read and put
	* into out
	*/
	size_t peek_byte(ref ubyte output) const
	{
		return peek(output.ptr[0..1]);
	}
	
	
	/**
	* Discard the next N bytes of the data
	* @param N the number of bytes to discard
	* @return number of bytes actually discarded
	*/
	size_t discard_next(size_t n)
	{
		size_t discarded = 0;
		ubyte dummy;
		foreach (size_t j; 0 .. n)
			discarded += read_byte(dummy);
		return discarded;
	}

	/**
	* @return the number of bytes read from the default message.
	*/
	size_t get_bytes_read() const
	{
		return m_outputs.get_bytes_read(DEFAULT_MESSAGE);
	}

	/**
	* @return the number of bytes read from the specified message.
	*/
	size_t get_bytes_read(message_id msg = DEFAULT_MESSAGE) const
	{
		return m_outputs.get_bytes_read(msg);
	}

	/**
	* @return currently set default message
	*/
	size_t default_msg() const { return m_default_read; }

	/**
	* Set the default message
	* @param msg the number identifying the message which is going to
	* be the new default message
	*/
	void set_default_msg(message_id msg)
	{
		if (msg >= message_count())
			throw new Invalid_Argument("Pipe::set_default_msg: msg number is too high");
		m_default_read = msg;
	}

	/**
	* Get the number of messages the are in this pipe.
	* @return number of messages the are in this pipe
	*/
	message_id message_count() const
	{
		return m_outputs.message_count();
	}


	/**
	* Test whether this pipe has any data that can be read from.
	* @return true if there is more data to read, false otherwise
	*/
	bool end_of_data() const
	{
		return (remaining() == 0);
	}

	/**
	* Start a new message in the pipe. A potential other message in this pipe
	* must be closed with end_msg() before this function may be called.
	*/
	void start_msg()
	{
		if (m_inside_msg)
			throw new Invalid_State("Pipe::start_msg: Message was already started");
		if (m_pipe_to == null)
			m_pipe_to = new Null_Filter;
		find_endpoints(m_pipe_to);
		m_pipe_to.new_msg();
		m_inside_msg = true;
	}

	/**
	* End the current message.
	*/
	void end_msg()
	{
		if (!m_inside_msg)
			throw new Invalid_State("Pipe::end_msg: Message was already ended");
		m_pipe_to.finish_msg();
		clear_endpoints(m_pipe_to);
		if (cast(Null_Filter)(m_pipe_to))
		{
			delete m_pipe_to;
			m_pipe_to = null;
		}
		m_inside_msg = false;
		
		m_outputs.retire();
	}

	/**
	* Insert a new filter at the front of the pipe
	* @param filt the new filter to insert
	*/
	void prepend(Filter filter)
	{
		if (m_inside_msg)
			throw new Invalid_State("Cannot prepend to a Pipe while it is processing");
		if (!filter)
			return;
		if (cast(Secure_Queue)(filter))
			throw new Invalid_Argument("Pipe::prepend: Secure_Queue cannot be used");
		if (filter.owned)
			throw new Invalid_Argument("Filters cannot be shared among multiple Pipes");
		
		filter.owned = true;
		
		if (m_pipe_to) filter.attach(m_pipe_to);
		m_pipe_to = filter;
	}

	/**
	* Insert a new filter at the back of the pipe
	* @param filt the new filter to insert
	*/
	void append(Filter filter)
	{
		if (m_inside_msg)
			throw new Invalid_State("Cannot append to a Pipe while it is processing");
		if (!filter)
			return;
		if (cast(Secure_Queue)(filter))
			throw new Invalid_Argument("Pipe::append: Secure_Queue cannot be used");
		if (filter.owned)
			throw new Invalid_Argument("Filters cannot be shared among multiple Pipes");
		
		filter.owned = true;
		
		if (!m_pipe_to) m_pipe_to = filter;
		else		m_pipe_to.attach(filter);
	}


	/**
	* Remove the first filter at the front of the pipe.
	*/
	void pop()
	{
		if (m_inside_msg)
			throw new Invalid_State("Cannot pop off a Pipe while it is processing");
		
		if (!m_pipe_to)
			return;
		
		if (m_pipe_to.total_ports() > 1)
			throw new Invalid_State("Cannot pop off a Filter with multiple ports");
		
		Filter f = m_pipe_to;
		size_t owns = f.owns();
		m_pipe_to = m_pipe_to.next[0];
		delete f;
		
		while(owns--)
		{
			f = m_pipe_to;
			m_pipe_to = m_pipe_to.next[0];
			delete f;
		}
	}


	/**
	* Reset this pipe to an empty pipe.
	*/
	void reset()
	{
		destruct(m_pipe_to);
		m_pipe_to = null;
		m_inside_msg = false;
	}


	/**
	* Construct a Pipe of up to four filters. The filters are set up
	* in the same order as the arguments.
	*/
	this(Filter f1 = null, Filter f2 = null,
		  Filter f3 = null, Filter f4 = null)
	{
		init();
		append(f1);
		append(f2);
		append(f3);
		append(f4);
	}

	/**
	* Construct a Pipe from a list of filters
	* @param filters the set of filters to use
	*/
	this(Filter[] filters)
	{
		init();
		
		foreach (filter; filters)
			append(filter);
	}

	~this()
	{
		destruct(m_pipe_to);
		delete m_outputs;
	}
private:
	/*
	* Initialize the Pipe
	*/
	void init()
	{
		m_pipe_to = null;
		m_default_read = 0;
		m_inside_msg = false;
	}

	/*
	* Destroy the Pipe
	*/
	void destruct(Filter to_kill)
	{
		if (!to_kill || cast(Secure_Queue)(to_kill))
			return;
		for (size_t j = 0; j != to_kill.total_ports(); ++j)
			destruct(to_kill.next[j]);
		delete to_kill;
	}

	/*
	* Find the endpoints of the Pipe
	*/
	void find_endpoints(Filter f)
	{
		for (size_t j = 0; j != f.total_ports(); ++j)
			if (f.next[j] && !cast(Secure_Queue)(f.next[j]))
				find_endpoints(f.next[j]);
			else
		{
			Secure_Queue q = new Secure_Queue;
			f.next[j] = q;
			m_outputs.add(q);
		}
	}

	/*
	* Remove the SecureQueues attached to the Filter
	*/
	void clear_endpoints(Filter f)
	{
		if (!f) return;
		for (size_t j = 0; j != f.total_ports(); ++j)
		{
			if (f.next[j] && cast(Secure_Queue)(f.next[j]))
				f.next[j] = null;
			clear_endpoints(f.next[j]);
		}
	}

	/*
	* Look up the canonical ID for a queue
	*/
	message_id get_message_no(in string func_name,
	                          message_id msg) const
	{
		if (msg == DEFAULT_MESSAGE)
			msg = default_msg();
		else if (msg == LAST_MESSAGE)
			msg = message_count() - 1;
		
		if (msg >= message_count())
			throw new Invalid_Message_Number(func_name, msg);
		
		return msg;
	}

	Filter m_pipe_to;
	Output_Buffers m_outputs;
	message_id m_default_read;
	bool m_inside_msg;
}

/*
* A Filter that does nothing
*/
final class Null_Filter : Filter
{
public:
	void write(in ubyte* input, size_t length)
	{ send(input, length); }
	
	@property string name() const { return "Null"; }
}