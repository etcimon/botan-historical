/*
* Pipe I/O for Unix
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.filters.fd_unix;
import botan.filters.pipe;
import botan.utils.exceptn;
import core.sys.posix.unistd;

version(none):

/**
* Stream output operator; dumps the results from pipe's default
* message to the output stream.
* @param output file descriptor for an open output stream
* @param pipe the pipe
*/
int operator<<(int fd, Pipe& pipe)
{
	SafeVector!ubyte buffer(DEFAULT_BUFFERSIZE);
	while(pipe.remaining())
	{
		size_t got = pipe.read(&buffer[0], buffer.size());
		size_t position = 0;
		while(got)
		{
			ssize_t ret = write(fd, &buffer[position], got);
			if (ret == -1)
				throw new Stream_IO_Error("Pipe output operator (unixfd) has failed");
			position += ret;
			got -= ret;
		}
	}
	return fd;
}

/**
* File descriptor input operator; dumps the remaining bytes of input
* to the (assumed open) pipe message.
* @param input file descriptor for an open input stream
* @param pipe the pipe
*/
int opBinary(string op)(int fd, ref Pipe pipe)
{
	SafeVector!ubyte buffer(DEFAULT_BUFFERSIZE);
	while(true)
	{
		ssize_t ret = read(fd, &buffer[0], buffer.size());
		if (ret == 0) break;
		if (ret == -1)
			throw new Stream_IO_Error("Pipe input operator (unixfd) has failed");
		pipe.write(&buffer[0], ret);
	}
	return fd;
}
