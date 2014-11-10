/*
* DataSource
* (C) 1999-2007 Jack Lloyd
*	  2012 Markus Wanner
*
* Distributed under the terms of the botan license.
*/
module botan.filters.data_src;
import botan.alloc.zeroize;
import string;
import std.stdio;
import botan.utils.exceptn;
import std.algorithm;
/**
* This class represents an abstract data source object.
*/
class DataSource
{
public:
	/**
	* Read from the source. Moves the internal offset so that every
	* call to read will return a new portion of the source.
	*
	* @param output the ubyte array to write the result to
	* @param length the length of the ubyte array out
	* @return length in bytes that was actually read and put
	* into out
	*/
	abstract size_t read(ubyte* output);

	/**
	* Read from the source but do not modify the internal
	* offset. Consecutive calls to peek() will return portions of
	* the source starting at the same position.
	*
	* @param output the ubyte array to write the output to
	* @param length the length of the ubyte array out
	* @param peek_offset the offset into the stream to read at
	* @return length in bytes that was actually read and put
	* into out
	*/
	abstract size_t peek(ubyte* output,
							  size_t peek_offset) const;

	/**
	* Test whether the source still has data that can be read.
	* @return true if there is still data to read, false otherwise
	*/
	abstract bool end_of_data() const;
	/**
	* return the id of this data source
	* @return string representing the id of this data source
	*/
	abstract string id() const { return ""; }

	/**
	* Read one ubyte.
	* @param output the ubyte to read to
	* @return length in bytes that was actually read and put
	* into out
	*/
	final size_t read_byte(ref ubyte output)
	{
		return read(output.ptr[0..1]);
	}


	/**
	* Peek at one ubyte.
	* @param output an output ubyte
	* @return length in bytes that was actually read and put
	* into out
	*/
	final size_t peek_byte(ref ubyte output) const
	{
		return peek(output.ptr[0..1]);
	}


	/**
	* Discard the next N bytes of the data
	* @param N the number of bytes to discard
	* @return number of bytes actually discarded
	*/
	final size_t discard_next(size_t n)
	{
		size_t discarded = 0;
		ubyte dummy;
		for (size_t j = 0; j != n; ++j)
			discarded += read_byte(dummy);
		return discarded;
	}


	/**
	* @return number of bytes read so far.
	*/
	abstract size_t get_bytes_read() const;

	this() {}
	~this() {}

};

/**
* This class represents a Memory-Based DataSource
*/
final class DataSource_Memory : DataSource
{
public:
	size_t read(ubyte* output, size_t length)
	{
		size_t got = std.algorithm.min(source.length - offset, length);
		copy_mem(output, &source[offset], got);
		offset += got;
		return got;
	}

	/*
	* Peek into a memory buffer
	*/
	size_t peek(ubyte* output,
	            size_t peek_offset) const
	{
		size_t length = output.length;
		const size_t bytes_left = source.length - offset;
		if (peek_offset >= bytes_left) return 0;
		
		size_t got = std.algorithm.min(bytes_left - peek_offset, length);
		copy_mem(output, &source[offset + peek_offset], got);
		return got;
	}

	/*
	* Check if the memory buffer is empty
	*/
	bool end_of_data() const
	{
		return (offset == source.length);
	}


	/**
	* Construct a memory source that reads from a string
	* @param input the string to read from
	*/
	this(in string input) 
	{
		source = Secure_Vector!ubyte(cast(const ubyte*) input.ptr,
		                          cast(const ubyte*)(input.ptr) + input.length);
		offset = 0;
	}


	/**
	* Construct a memory source that reads from a ubyte array
	* @param input the ubyte array to read from
	* @param length the length of the ubyte array
	*/
	this(in ubyte* input, size_t length)
	{
		source = Secure_Vector!ubyte(input, input + length);
		offset = 0; 
	}

	/**
	* Construct a memory source that reads from a Secure_Vector
	* @param input the MemoryRegion to read from
	*/
	this(in Secure_Vector!ubyte input)
	{
		source = input;
		offset = 0;
	}

	/**
	* Construct a memory source that reads from a std::vector
	* @param input the MemoryRegion to read from
	*/
	this(in Vector!ubyte input) {
		source = Secure_Vector!ubyte(&input[0], &input[input.length]);
		offset = 0;
	}

	abstract size_t get_bytes_read() const { return offset; }
private:
	Secure_Vector!ubyte source;
	size_t offset;
};

/**
* This class represents a Stream-Based DataSource.
*/
final class DataSource_Stream : DataSource
{
public:
	/*
	* Read from a stream
	*/
	size_t read(ubyte* output, size_t length)
	{
		ubyte[] data;
		try data = source.rawRead(output[0..length]);
		catch (Exception e)
			throw new Stream_IO_Error("read: Source failure..." ~ e.toString());
		
		size_t got = data.length;
		total_read += got;
		return got;
	}

	/*
	* Peek into a stream
	*/
	size_t peek(ubyte* output, size_t length, size_t offset) const
	{
		size_t length = output.length;
		if (end_of_data())
			throw new Invalid_State("DataSource_Stream: Cannot peek when out of data");
		
		size_t got = 0;
		
		if (offset)
		{
			Secure_Vector!ubyte buf(offset);
			ubyte[] data;
			try data = source.rawRead(buf[0..length]);
			catch (Exception e)
				throw new Stream_IO_Error("peek: Source failure..." ~ e.toString());
			
			got = data.length;
		}
		
		if (got == offset)
		{
			ubyte[] data;
			try data = source.rawRead(output[0..length]);
			catch (Exception e)
				throw new Stream_IO_Error("peek: Source failure" ~ e.toString());
			got = data.length;
		}
		
		if (source.eof) {
			source.clearerr();
			source.rewind();
		}
		source.seek(total_read, SEEK_SET);
		
		return got;
	}

	/*
	* Check if the stream is empty or in error
	*/
	bool end_of_data() const
	{
		return (!source.eof && !source.error());
	}

	/*
	* Return a human-readable ID for this stream
	*/
	string id() const
	{
		return identifier;
	}

	/*
	* DataSource_Stream Constructor
	*/
	this(ref File input,
	                  in string name)
	{
		identifier = name;
		source = input;
		total_read = 0;
	}

	/**
	* Construct a Stream-Based DataSource from file
	* @param file the name of the file
	* @param use_binary whether to treat the file as binary or not
	*/
	this(in string path, bool use_binary = false)
	{
		
		identifier = path;
		source = File(path, use_binary ? "rb" : "r");
		total_read = 0;
		if (source.error())
		{
			throw new Stream_IO_Error("DataSource: Failure opening file " ~ path);
		}
	}

	/*
	* DataSource_Stream Destructor
	*/
	~this()
	{

	}

	size_t get_bytes_read() const { return total_read; }
private:
	const string identifier;

	File source;
	size_t total_read;
};