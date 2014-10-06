/*
* Pipe
* (C) 1999-2007 Jack Lloyd
*	  2012 Markus Wanner
*
* Distributed under the terms of the botan license.
*/

import botan.data_src;
import botan.filter;
import botan.exceptn;
import initializer_list;
import iosfwd;
/**
* This class represents pipe objects.
* A set of filters can be placed into a pipe, and information flows
* through the pipe until it reaches the end, where the output is
* collected for retrieval.  If you're familiar with the Unix shell
* environment, this design will sound quite familiar.
*/
class Pipe : DataSource
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
	struct Invalid_Message_Number : Invalid_Argument
	{
		/**
		* @param where the error occured
		* @param msg the invalid message id that was used
		*/
		Invalid_Message_Number(in string where, message_id msg) :
			Invalid_Argument("Pipe::" ~ where ~ ": Invalid message number " ~
								  std.conv.to!string(msg))
		{}
	};

	/**
	* A meta-id for whatever the last message is
	*/
	static const message_id LAST_MESSAGE;

	/**
	* A meta-id for the default message (set with set_default_msg)
	*/
	static const message_id DEFAULT_MESSAGE;

	/**
	* Write input to the pipe, i.e. to its first filter.
	* @param in the ubyte array to write
	* @param length the length of the ubyte array in
	*/
	void write(in ubyte* input, size_t length);

	/**
	* Write input to the pipe, i.e. to its first filter.
	* @param in the secure_vector containing the data to write
	*/
	void write(in SafeVector!ubyte input)
	{ write(&input[0], input.size()); }

	/**
	* Write input to the pipe, i.e. to its first filter.
	* @param in the std::vector containing the data to write
	*/
	void write(in Vector!ubyte input)
	{ write(&input[0], input.size()); }

	/**
	* Write input to the pipe, i.e. to its first filter.
	* @param in the string containing the data to write
	*/
	void write(in string input);

	/**
	* Write input to the pipe, i.e. to its first filter.
	* @param in the DataSource to read the data from
	*/
	void write(DataSource input);

	/**
	* Write input to the pipe, i.e. to its first filter.
	* @param in a single ubyte to be written
	*/
	void write(ubyte input);

	/**
	* Perform start_msg(), write() and end_msg() sequentially.
	* @param in the ubyte array containing the data to write
	* @param length the length of the ubyte array to write
	*/
	void process_msg(in ubyte* input, size_t length);

	/**
	* Perform start_msg(), write() and end_msg() sequentially.
	* @param in the secure_vector containing the data to write
	*/
	void process_msg(in SafeVector!ubyte input);

	/**
	* Perform start_msg(), write() and end_msg() sequentially.
	* @param in the secure_vector containing the data to write
	*/
	void process_msg(in Vector!ubyte input);

	/**
	* Perform start_msg(), write() and end_msg() sequentially.
	* @param in the string containing the data to write
	*/
	void process_msg(in string input);

	/**
	* Perform start_msg(), write() and end_msg() sequentially.
	* @param in the DataSource providing the data to write
	*/
	void process_msg(DataSource input);

	/**
	* Find out how many bytes are ready to read.
	* @param msg the number identifying the message
	* for which the information is desired
	* @return number of bytes that can still be read
	*/
	size_t remaining(message_id msg = DEFAULT_MESSAGE) const;

	/**
	* Read the default message from the pipe. Moves the internal
	* offset so that every call to read will return a new portion of
	* the message.
	*
	* @param output the ubyte array to write the read bytes to
	* @param length the length of the ubyte array output
	* @return number of bytes actually read into output
	*/
	size_t read(ubyte* output, size_t length);

	/**
	* Read a specified message from the pipe. Moves the internal
	* offset so that every call to read will return a new portion of
	* the message.
	* @param output the ubyte array to write the read bytes to
	* @param length the length of the ubyte array output
	* @param msg the number identifying the message to read from
	* @return number of bytes actually read into output
	*/
	size_t read(ubyte* output, size_t length, message_id msg);

	/**
	* Read a single ubyte from the pipe. Moves the internal offset so
	* that every call to read will return a new portion of the
	* message.
	*
	* @param output the ubyte to write the result to
	* @param msg the message to read from
	* @return number of bytes actually read into output
	*/
	size_t read(ubyte& output, message_id msg = DEFAULT_MESSAGE);

	/**
	* Read the full contents of the pipe.
	* @param msg the number identifying the message to read from
	* @return secure_vector holding the contents of the pipe
	*/
	SafeVector!ubyte read_all(message_id msg = DEFAULT_MESSAGE);

	/**
	* Read the full contents of the pipe.
	* @param msg the number identifying the message to read from
	* @return string holding the contents of the pipe
	*/
	string read_all_as_string(message_id = DEFAULT_MESSAGE);

	/** Read from the default message but do not modify the internal
	* offset. Consecutive calls to peek() will return portions of
	* the message starting at the same position.
	* @param output the ubyte array to write the peeked message part to
	* @param length the length of the ubyte array output
	* @param offset the offset from the current position in message
	* @return number of bytes actually peeked and written into output
	*/
	size_t peek(ubyte* output, size_t length, size_t offset) const;

	/** Read from the specified message but do not modify the
	* internal offset. Consecutive calls to peek() will return
	* portions of the message starting at the same position.
	* @param output the ubyte array to write the peeked message part to
	* @param length the length of the ubyte array output
	* @param offset the offset from the current position in message
	* @param msg the number identifying the message to peek from
	* @return number of bytes actually peeked and written into output
	*/
	size_t peek(ubyte* output,
				size_t offset, message_id msg) const;

	/** Read a single ubyte from the specified message but do not
	* modify the internal offset. Consecutive calls to peek() will
	* return portions of the message starting at the same position.
	* @param output the ubyte to write the peeked message ubyte to
	* @param offset the offset from the current position in message
	* @param msg the number identifying the message to peek from
	* @return number of bytes actually peeked and written into output
	*/
	size_t peek(ref ubyte output, size_t offset,
				message_id msg = DEFAULT_MESSAGE) const;

	/**
	* @return the number of bytes read from the default message.
	*/
	size_t get_bytes_read() const;

	/**
	* @return the number of bytes read from the specified message.
	*/
	size_t get_bytes_read(message_id msg = DEFAULT_MESSAGE) const;

	/**
	* @return currently set default message
	*/
	size_t default_msg() const { return default_read; }

	/**
	* Set the default message
	* @param msg the number identifying the message which is going to
	* be the new default message
	*/
	void set_default_msg(message_id msg);

	/**
	* Get the number of messages the are in this pipe.
	* @return number of messages the are in this pipe
	*/
	message_id message_count() const;

	/**
	* Test whether this pipe has any data that can be read from.
	* @return true if there is more data to read, false otherwise
	*/
	bool end_of_data() const;

	/**
	* Start a new message in the pipe. A potential other message in this pipe
	* must be closed with end_msg() before this function may be called.
	*/
	void start_msg();

	/**
	* End the current message.
	*/
	void end_msg();

	/**
	* Insert a new filter at the front of the pipe
	* @param filt the new filter to insert
	*/
	void prepend(Filter* filt);

	/**
	* Insert a new filter at the back of the pipe
	* @param filt the new filter to insert
	*/
	void append(Filter* filt);

	/**
	* Remove the first filter at the front of the pipe.
	*/
	void pop();

	/**
	* Reset this pipe to an empty pipe.
	*/
	void reset();

	/**
	* Construct a Pipe of up to four filters. The filters are set up
	* in the same order as the arguments.
	*/
	Pipe(Filter* = null, Filter* = null,
		  Filter* = null, Filter* = null);

	/**
	* Construct a Pipe from a list of filters
	* @param filters the set of filters to use
	*/
	Pipe(std::initializer_list<Filter*> filters);

	Pipe(in Pipe);
	Pipe& operator=(in Pipe);

	~this();
private:
	void init();
	void destruct(Filter*);
	void find_endpoints(Filter*);
	void clear_endpoints(Filter*);

	message_id get_message_no(in string, message_id) const;

	Filter* pipe;
	class Output_Buffers* outputs;
	message_id default_read;
	bool inside_msg;
};

/**
* Stream output operator; dumps the results from pipe's default
* message to the output stream.
* @param out an output stream
* @param pipe the pipe
*/
std::ostream& operator<<(std::ostream& output, Pipe& pipe);

/**
* Stream input operator; dumps the remaining bytes of input
* to the (assumed open) pipe message.
* @param in the input stream
* @param pipe the pipe
*/
std::istream& operator>>(std::istream& input, Pipe& pipe);

}

#if defined(BOTAN_HAS_PIPE_UNIXFD_IO)
  import botan.fd_unix;
#endif

#endif
