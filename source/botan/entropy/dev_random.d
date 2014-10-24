/*
* /dev/random EntropySource
* (C) 1999-2009 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.entropy.dev_random;

version(Posix):
static if (BOTAN_HAS_ENTROPY_SRC_DEV_RANDOM):

import botan.entropy.entropy_src;
import botan.utils.types;
import string;
import core.sys.posix.sys.types;
import core.sys.posix.sys.select;
import core.sys.posix.sys.stat;
import core.sys.posix.unistd;
import core.sys.posix.fcntl;
import std.c.string;
import botan.utils.rounding;

/**
* Entropy source reading from kernel devices like /dev/random
*/
final class Device_EntropySource : EntropySource
{
public:
	@property string name() const { return "RNG Device Reader"; }

	/**
	* Gather entropy from a RNG device
	*/
	void poll(ref Entropy_Accumulator accum)
	{
		if (m_devices.empty)
			return;
		
		const size_t ENTROPY_BITS_PER_BYTE = 8;
		const size_t MS_WAIT_TIME = 32;
		const size_t READ_ATTEMPT = 32;
		
		int max_fd = m_devices[0];
		fd_set read_set;
		FD_ZERO(&read_set);
		for (size_t i = 0; i != m_devices.length; ++i)
		{
			FD_SET(m_devices[i], &read_set);
			max_fd = std.algorithm.max(m_devices[i], max_fd);
		}
		
		timeval timeout;
		
		timeout.tv_sec = (MS_WAIT_TIME / 1000);
		timeout.tv_usec = (MS_WAIT_TIME % 1000) * 1000;
		
		if (select(max_fd + 1, &read_set, null, null, &timeout) < 0)
			return;
		
		Secure_Vector!ubyte io_buffer = accum.get_io_buffer(READ_ATTEMPT);
		
		for (size_t i = 0; i != m_devices.length; ++i)
		{
			if (FD_ISSET(m_devices[i], &read_set))
			{
				const ssize_t got = read(m_devices[i], &io_buffer[0], io_buffer.length);
				if (got > 0)
					accum.add(&io_buffer[0], got, ENTROPY_BITS_PER_BYTE);
			}
		}
	}


	/**
	Device_EntropySource constructor
	Open a file descriptor to each (available) device in fsnames
	*/
	this(in Vector!string fsnames)
	{
		enum O_NONBLOCK = 0;
		enum O_NOCTTY = 0;
		
		const int flags = O_RDONLY | O_NONBLOCK | O_NOCTTY;
		
		foreach (fsname; fsnames)
		{
			fd_type fd = open(fsname.toStringz, flags);
			
			if (fd >= 0 && fd < FD_SETSIZE)
				m_devices.push_back(fd);
			else if (fd >= 0)
				close(fd);
		}
	}

	~this()
	{
		for (size_t i = 0; i != m_devices.length; ++i)
			close(m_devices[i]);
	}
private:
	typedef int fd_type;

	Vector!fd_type m_devices;
};