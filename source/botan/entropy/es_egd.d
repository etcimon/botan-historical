/*
* EGD EntropySource
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.entropy.es_egd;
import botan.entropy.entropy_src;
import string;
import vector;

import botan.utils.parsing;
import botan.utils.exceptn;
import cstring;
import stdexcept;

import core.sys.posix.sys.types;
import core.sys.posix.sys.stat;
import core.sys.posix.fcntl;
import core.sys.posix.unistd;

import core.sys.posix.sys.socket;
import core.sys.posix.sys.un;

import std.c.string;

enum PF_LOCAL = PF_UNIX;

/**
* EGD Entropy Source
*/
class EGD_EntropySource : EntropySource
{
public:
	string name() const { return "EGD/PRNGD"; }

	/**
	* Gather Entropy from EGD
	*/
	void poll(ref Entropy_Accumulator accum)
	{
		const size_t READ_ATTEMPT = 32;
		
		SafeVector!ubyte io_buffer = accum.get_io_buffer(READ_ATTEMPT);
		
		for (size_t i = 0; i != sockets.length; ++i)
		{
			size_t got = sockets[i].read(&io_buffer[0], io_buffer.length);
			
			if (got)
			{
				accum.add(&io_buffer[0], got, 6);
				break;
			}
		}
	}

	/**
	* EGD_EntropySource constructor
	*/
	this(in Vector!string paths)
	{
		for (size_t i = 0; i != paths.length; ++i)
			sockets.push_back(EGD_Socket(paths[i]));
	}
	~this()
	{
		for (size_t i = 0; i != sockets.length; ++i)
			sockets[i].close();
		sockets.clear();
	}
private:
	class EGD_Socket
	{
	public:
		this(in string path)
		{
			socket_path = path;
			m_fd = -1;
		}


		void close()
		{
			if (m_fd > 0)
			{
				close(m_fd);
				m_fd = -1;
			}
		}

		/**
		* Attempt to read entropy from EGD
		*/
		size_t read(ref ubyte[] outbuf)
		{
			size_t length = outbuf.length;
			if (length == 0)
				return 0;
			
			if (m_fd < 0)
			{
				m_fd = open_socket(socket_path);
				if (m_fd < 0)
					return 0;
			}
			
			try
			{
				// 1 == EGD command for non-blocking read
				ubyte[2] egd_read_command = {
					1, cast(ubyte)(std.algorithm.min(length, 255)) };
				
				if (write(m_fd, egd_read_command, 2) != 2)
					throw new Exception("Writing entropy read command to EGD failed");
				
				ubyte out_len = 0;
				if (read(m_fd, &out_len, 1) != 1)
					throw new Exception("Reading response length from EGD failed");
				
				if (out_len > egd_read_command[1])
					throw new Exception("Bogus length field received from EGD");
				
				ssize_t count = read(m_fd, outbuf, out_len);
				
				if (count != out_len)
					throw new Exception("Reading entropy result from EGD failed");
				
				return cast(size_t)(count);
			}
			catch(Exception e)
			{
				this.close();
				// Will attempt to reopen next poll
			}
			
			return 0;
		}

	private:
		/**
		* Attempt a connection to an EGD/PRNGD socket
		*/
		static int open_socket(in string path)
		{
			int fd = socket(PF_LOCAL, SOCK_STREAM, 0);
			
			if (fd >= 0)
			{
				sockaddr_un addr;
				memset(&addr, 0, sizeof(addr));
				addr.sun_family = PF_LOCAL;
				
				if (sizeof(addr.sun_path) < path.length() + 1)
					throw new Invalid_Argument("EGD socket path is too long");
				
				strncpy(addr.sun_path, path.toStringz, sizeof(addr.sun_path));
				
				int len = sizeof(addr.sun_family) + strlen(addr.sun_path) + 1;
				
				if (connect(fd, cast(sockaddr*)(&addr), len) < 0)
				{
					close(fd);
					fd = -1;
				}
			}
			
			return fd;
		}

		string socket_path;
		int m_fd; // cached fd
	};

	Vector!( EGD_Socket ) sockets;
};