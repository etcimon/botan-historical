/*
* Pipe I/O
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/pipe.h>
#include <iostream>
/*
* Write data from a pipe into an ostream
*/
std::ostream& operator<<(std::ostream& stream, Pipe& pipe)
{
	SafeVector!byte buffer(DEFAULT_BUFFERSIZE);
	while(stream.good() && pipe.remaining())
	{
		size_t got = pipe.read(&buffer[0], buffer.size());
		stream.write(cast(string)(buffer[0]), got);
	}
	if(!stream.good())
		throw new Stream_IO_Error("Pipe output operator (iostream) has failed");
	return stream;
}

/*
* Read data from an istream into a pipe
*/
std::istream& operator>>(std::istream& stream, Pipe& pipe)
{
	SafeVector!byte buffer(DEFAULT_BUFFERSIZE);
	while(stream.good())
	{
		stream.read(cast(char*)(&buffer[0]), buffer.size());
		pipe.write(&buffer[0], stream.gcount());
	}
	if(stream.bad() || (stream.fail() && !stream.eof()))
		throw new Stream_IO_Error("Pipe input operator (iostream) has failed");
	return stream;
}

}
