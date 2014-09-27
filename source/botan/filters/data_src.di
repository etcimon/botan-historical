/*
* DataSource
* (C) 1999-2007 Jack Lloyd
*	  2012 Markus Wanner
*
* Distributed under the terms of the botan license.
*/

import botan.secmem;
import string;
import iosfwd;
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
		* @param out the byte array to write the result to
		* @param length the length of the byte array out
		* @return length in bytes that was actually read and put
		* into out
		*/
		abstract size_t read(byte* output);

		/**
		* Read from the source but do not modify the internal
		* offset. Consecutive calls to peek() will return portions of
		* the source starting at the same position.
		*
		* @param out the byte array to write the output to
		* @param length the length of the byte array out
		* @param peek_offset the offset into the stream to read at
		* @return length in bytes that was actually read and put
		* into out
		*/
		abstract size_t peek(byte* output,
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
		* Read one byte.
		* @param out the byte to read to
		* @return length in bytes that was actually read and put
		* into out
		*/
		size_t read_byte(ref byte output);

		/**
		* Peek at one byte.
		* @param out an output byte
		* @return length in bytes that was actually read and put
		* into out
		*/
		size_t peek_byte(ref byte output) const;

		/**
		* Discard the next N bytes of the data
		* @param N the number of bytes to discard
		* @return number of bytes actually discarded
		*/
		size_t discard_next(size_t N);

		/**
		* @return number of bytes read so far.
		*/
		abstract size_t get_bytes_read() const;

		DataSource() {}
		abstract ~DataSource() {}
		DataSource& operator=(in DataSource);
		DataSource(in DataSource);
};

/**
* This class represents a Memory-Based DataSource
*/
class DataSource_Memory : public DataSource
{
	public:
		size_t read(byte[], size_t);
		size_t peek(byte[], size_t, size_t) const;
		bool end_of_data() const;

		/**
		* Construct a memory source that reads from a string
		* @param in the string to read from
		*/
		DataSource_Memory(in string input);

		/**
		* Construct a memory source that reads from a byte array
		* @param in the byte array to read from
		* @param length the length of the byte array
		*/
		DataSource_Memory(in byte* input, size_t length) :
			source(input, in + length), offset(0) {}

		/**
		* Construct a memory source that reads from a secure_vector
		* @param in the MemoryRegion to read from
		*/
		DataSource_Memory(in SafeVector!byte input) :
			source(input), offset(0) {}

		/**
		* Construct a memory source that reads from a std::vector
		* @param in the MemoryRegion to read from
		*/
		DataSource_Memory(in Vector!byte input) :
			source(&input[0], &input[in.size()]), offset(0) {}

		abstract size_t get_bytes_read() const { return offset; }
	private:
		SafeVector!byte source;
		size_t offset;
};

/**
* This class represents a Stream-Based DataSource.
*/
class DataSource_Stream : public DataSource
{
	public:
		size_t read(byte[], size_t);
		size_t peek(byte[], size_t, size_t) const;
		bool end_of_data() const;
		string id() const;

		DataSource_Stream(std::istream&,
								in string id = "<std::istream>");

		/**
		* Construct a Stream-Based DataSource from file
		* @param file the name of the file
		* @param use_binary whether to treat the file as binary or not
		*/
		DataSource_Stream(in string file, bool use_binary = false);

		DataSource_Stream(in DataSource_Stream);

		DataSource_Stream& operator=(in DataSource_Stream);

		~DataSource_Stream();

		abstract size_t get_bytes_read() const { return total_read; }
	private:
		const string identifier;

		std::istream* source_p;
		std::istream& source;
		size_t total_read;
};