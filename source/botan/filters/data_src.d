/*
* DataSource
* (C) 1999-2007 Jack Lloyd
*	  2005 Matthew Gregan
*
* Distributed under the terms of the Botan license
*/

import botan.data_src;
import botan.exceptn;
import fstream;
import algorithm;
/*
* Read a single ubyte from the DataSource
*/
size_t DataSource::read_byte(ref ubyte output)
{
	return read(output.ptr[0..1]);
}

/*
* Peek a single ubyte from the DataSource
*/
size_t DataSource::peek_byte(ref ubyte output) const
{
	return peek(output.ptr[0..1]);
}

/*
* Discard the next N bytes of the data
*/
size_t DataSource::discard_next(size_t n)
{
	size_t discarded = 0;
	ubyte dummy;
	for (size_t j = 0; j != n; ++j)
		discarded += read_byte(dummy);
	return discarded;
}

/*
* Read from a memory buffer
*/
size_t DataSource_Memory::read(ubyte* output)
{
	size_t length = output.length;
	size_t got = std.algorithm.min<size_t>(source.size() - offset, length);
	copy_mem(out, &source[offset], got);
	offset += got;
	return got;
}

/*
* Peek into a memory buffer
*/
size_t DataSource_Memory::peek(ubyte* output,
										 size_t peek_offset) const
{
	size_t length = output.length;
	const size_t bytes_left = source.size() - offset;
	if (peek_offset >= bytes_left) return 0;

	size_t got = std.algorithm.min(bytes_left - peek_offset, length);
	copy_mem(output, &source[offset + peek_offset], got);
	return got;
}

/*
* Check if the memory buffer is empty
*/
bool DataSource_Memory::end_of_data() const
{
	return (offset == source.size());
}

/*
* DataSource_Memory Constructor
*/
DataSource_Memory::DataSource_Memory(in string input) :
	source(cast(const ubyte*)(input.data()),
			 cast(const ubyte*)(input.data()) + input.length()),
	offset(0)
{
	offset = 0;
}

/*
* Read from a stream
*/
size_t DataSource_Stream::read(ubyte* output)
{
	size_t length = output.length;
	source.read(cast(char*)(output), length);
	if (source.bad())
		throw new Stream_IO_Error("DataSource_Stream::read: Source failure");

	size_t got = source.gcount();
	total_read += got;
	return got;
}

/*
* Peek into a stream
*/
size_t DataSource_Stream::peek(ubyte* output, size_t offset) const
{
	size_t length = output.length;
	if (end_of_data())
		throw new Invalid_State("DataSource_Stream: Cannot peek when out of data");

	size_t got = 0;

	if (offset)
	{
		SafeVector!ubyte buf(offset);
		source.read(cast(char*)(&buf[0]), buf.size());
		if (source.bad())
			throw new Stream_IO_Error("DataSource_Stream::peek: Source failure");
		got = source.gcount();
	}

	if (got == offset)
	{
		source.read(cast(char*)(output), length);
		if (source.bad())
			throw new Stream_IO_Error("DataSource_Stream::peek: Source failure");
		got = source.gcount();
	}

	if (source.eof())
		source.clear();
	source.seekg(total_read, std::ios::beg);

	return got;
}

/*
* Check if the stream is empty or in error
*/
bool DataSource_Stream::end_of_data() const
{
	return (!source.good());
}

/*
* Return a human-readable ID for this stream
*/
string DataSource_Stream::id() const
{
	return identifier;
}

/*
* DataSource_Stream Constructor
*/
DataSource_Stream::DataSource_Stream(in string path,
												 bool use_binary) :
	identifier(path),
	source_p(new std::ifstream(
					path.c_str(),
					use_binary ? std::ios::binary : std::ios::input)),
	source(*source_p),
	total_read(0)
{
	if (!source.good())
	{
		delete source_p;
		throw new Stream_IO_Error("DataSource: Failure opening file " ~ path);
	}
}

/*
* DataSource_Stream Constructor
*/
DataSource_Stream::DataSource_Stream(std::istream& input,
												 in string name) :
	identifier(name),
	source_p(null),
	source(input),
	total_read(0)
{
}

/*
* DataSource_Stream Destructor
*/
DataSource_Stream::~this()
{
	delete source_p;
}

}
