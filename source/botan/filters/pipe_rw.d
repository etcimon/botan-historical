/*
* Pipe Reading/Writing
* (C) 1999-2007 Jack Lloyd
*	  2012 Markus Wanner
*
* Distributed under the terms of the Botan license
*/

#include <botan/pipe.h>
#include <botan/internal/out_buf.h>
#include <botan/secqueue.h>
/*
* Look up the canonical ID for a queue
*/
Pipe::message_id Pipe::get_message_no(in string func_name,
												  message_id msg) const
{
	if(msg == DEFAULT_MESSAGE)
		msg = default_msg();
	else if(msg == LAST_MESSAGE)
		msg = message_count() - 1;

	if(msg >= message_count())
		throw new Invalid_Message_Number(func_name, msg);

	return msg;
}

/*
* Write into a Pipe
*/
void Pipe::write(in byte* input, size_t length)
{
	if(!inside_msg)
		throw new Invalid_State("Cannot write to a Pipe while it is not processing");
	pipe->write(input, length);
}

/*
* Write a string into a Pipe
*/
void Pipe::write(in string str)
{
	write(cast(const byte*)(str.data()), str.size());
}

/*
* Write a single byte into a Pipe
*/
void Pipe::write(byte input)
{
	write(&input, 1);
}

/*
* Write the contents of a DataSource into a Pipe
*/
void Pipe::write(DataSource& source)
{
	SafeVector!byte buffer(DEFAULT_BUFFERSIZE);
	while(!source.end_of_data())
	{
		size_t got = source.read(&buffer[0], buffer.size());
		write(&buffer[0], got);
	}
}

/*
* Read some data from the pipe
*/
size_t Pipe::read(byte* output, size_t length, message_id msg)
{
	return outputs->read(output, length, get_message_no("read", msg));
}

/*
* Read some data from the pipe
*/
size_t Pipe::read(byte* output, size_t length)
{
	return read(output, length, DEFAULT_MESSAGE);
}

/*
* Read a single byte from the pipe
*/
size_t Pipe::read(ref byte output, message_id msg)
{
	return read(&output, 1, msg);
}

/*
* Return all data in the pipe
*/
SafeVector!byte Pipe::read_all(message_id msg)
{
	msg = ((msg != DEFAULT_MESSAGE) ? msg : default_msg());
	SafeVector!byte buffer(remaining(msg));
	size_t got = read(&buffer[0], buffer.size(), msg);
	buffer.resize(got);
	return buffer;
}

/*
* Return all data in the pipe as a string
*/
string Pipe::read_all_as_string(message_id msg)
{
	msg = ((msg != DEFAULT_MESSAGE) ? msg : default_msg());
	SafeVector!byte buffer(DEFAULT_BUFFERSIZE);
	string str;
	str.reserve(remaining(msg));

	while(true)
	{
		size_t got = read(&buffer[0], buffer.size(), msg);
		if(got == 0)
			break;
		str.append(cast(string)(buffer[0]), got);
	}

	return str;
}

/*
* Find out how many bytes are ready to read
*/
size_t Pipe::remaining(message_id msg) const
{
	return outputs->remaining(get_message_no("remaining", msg));
}

/*
* Peek at some data in the pipe
*/
size_t Pipe::peek(byte* output, size_t length,
						size_t offset, message_id msg) const
{
	return outputs->peek(output, length, offset, get_message_no("peek", msg));
}

/*
* Peek at some data in the pipe
*/
size_t Pipe::peek(byte* output, size_t length, size_t offset) const
{
	return peek(output, length, offset, DEFAULT_MESSAGE);
}

/*
* Peek at a byte in the pipe
*/
size_t Pipe::peek(ref byte output, size_t offset, message_id msg) const
{
	return peek(&output, 1, offset, msg);
}

size_t Pipe::get_bytes_read() const
{
	return outputs->get_bytes_read(DEFAULT_MESSAGE);
}

size_t Pipe::get_bytes_read(message_id msg) const
{
	return outputs->get_bytes_read(msg);
}

}
