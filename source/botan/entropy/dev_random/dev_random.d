/*
* Reader of /dev/random and company
* (C) 1999-2009,2013 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

import botan.internal.dev_random;
import botan.internal.rounding;

import sys.types;
import sys.select;
import sys.stat;
import unistd.h;
import fcntl.h;
import string.h;
/**
Device_EntropySource constructor
Open a file descriptor to each (available) device in fsnames
*/
Device_EntropySource::Device_EntropySource(in Vector!( string ) fsnames)
{
  #define O_NONBLOCK 0
#endif

  #define O_NOCTTY 0
#endif

	const int flags = O_RDONLY | O_NONBLOCK | O_NOCTTY;

	foreach (fsname; fsnames)
	{
		fd_type fd = ::open(fsname.c_str(), flags);

		if (fd >= 0 && fd < FD_SETSIZE)
			m_devices.push_back(fd);
		else if (fd >= 0)
			::close(fd);
	}
}

/**
Device_EntropySource destructor: close all open devices
*/
Device_EntropySource::~Device_EntropySource()
{
	for (size_t i = 0; i != m_devices.size(); ++i)
		::close(m_devices[i]);
}

/**
* Gather entropy from a RNG device
*/
void Device_EntropySource::poll(Entropy_Accumulator& accum)
{
	if (m_devices.empty())
		return;

	const size_t ENTROPY_BITS_PER_BYTE = 8;
	const size_t MS_WAIT_TIME = 32;
	const size_t READ_ATTEMPT = 32;

	int max_fd = m_devices[0];
	fd_set read_set;
	FD_ZERO(&read_set);
	for (size_t i = 0; i != m_devices.size(); ++i)
	{
		FD_SET(m_devices[i], &read_set);
		max_fd = std::max(m_devices[i], max_fd);
	}

	struct ::timeval timeout;

	timeout.tv_sec = (MS_WAIT_TIME / 1000);
	timeout.tv_usec = (MS_WAIT_TIME % 1000) * 1000;

	if (::select(max_fd + 1, &read_set, null, null, &timeout) < 0)
		return;

	SafeVector!byte io_buffer = accum.get_io_buffer(READ_ATTEMPT);

	for (size_t i = 0; i != m_devices.size(); ++i)
	{
		if (FD_ISSET(m_devices[i], &read_set))
		{
			const ssize_t got = ::read(m_devices[i], &io_buffer[0], io_buffer.size());
			if (got > 0)
				accum.add(&io_buffer[0], got, ENTROPY_BITS_PER_BYTE);
		}
	}
}

}
