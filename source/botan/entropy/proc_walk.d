/*
* File Tree Walking EntropySource
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.entropy.proc_walk;

import botan.entropy.entropy_src;
import botan.alloc.secmem;
import cstring;
import deque;

enum _POSIX_C_SOURCE = 199309;

import core.sys.posix.sys.types;
import core.sys.posix.sys.stat;
import core.sys.posix.fcntl;
import core.sys.posix.unistd;
import core.sys.posix.dirent;

package:

class Directory_Walker : File_Descriptor_Source
{
public:
	this(in string root) 
	{
		m_cur_dir = Pair!(DIR*, string)(null, "");
		if (DIR* root_dir = opendir(root.toStringz))
			m_cur_dir = Pair(root_dir, root);
	}
	
	~this()
	{
		if (m_cur_dir.first)
			closedir(m_cur_dir.first);
	}
	
	int next_fd();
private:
	void add_directory(in string dirname)
	{
		m_dirlist.push_back(dirname);
	}
	
	Pair!(dirent*, string) get_next_dirent()
	{
		while(m_cur_dir.first)
		{
			if (dirent* dir = readdir(m_cur_dir.first))
				return Pair(dir, m_cur_dir.second);
			
			closedir(m_cur_dir.first);
			m_cur_dir = Pair!(DIR*, string)(null, "");
			
			while(!m_dirlist.empty() && !m_cur_dir.first)
			{
				const string next_dir_name = m_dirlist[0];
				m_dirlist.pop_front();
				
				if (DIR* next_dir = opendir(next_dir_name.toStringz))
					m_cur_dir = Pair(next_dir, next_dir_name);
			}
		}
		
		return Pair!(dirent*, string)(null, ""); // nothing left
	}
	
	Pair!(DIR*, string) m_cur_dir;
	std::deque<string> m_dirlist;
};


class File_Descriptor_Source
{
public:
	int next_fd()
	{
		while(true)
		{
			Pair!(dirent*, string) entry = get_next_dirent();
			
			if (!entry.first)
				break; // no more dirs
			
			const string filename = entry.first.d_name;
			
			if (filename == "." || filename == "..")
				continue;
			
			const string full_path = entry.second + '/' + filename;
			
			stat stat_buf;
			if (lstat(full_path.toStringz, &stat_buf) == -1)
				continue;
			
			if (S_ISDIR(stat_buf.st_mode))
			{
				add_directory(full_path);
			}
			else if (S_ISREG(stat_buf.st_mode) && (stat_buf.st_mode & S_IROTH))
			{
				int fd = open(full_path.toStringz, O_RDONLY | O_NOCTTY);
				
				if (fd > 0)
					return fd;
			}
		}
		
		return -1;
	}

	~this() {}
};

/**
* File Tree Walking Entropy Source
*/
class ProcWalking_EntropySource : EntropySource
{
public:
	string name() const { return "Proc Walker"; }

	void poll(ref Entropy_Accumulator accum)
	{
		const size_t MAX_FILES_READ_PER_POLL = 2048;
		const double ENTROPY_ESTIMATE = 1.0 / (8*1024);
		
		if (!m_dir)
			m_dir.reset(new Directory_Walker(m_path));
		
		SafeVector!ubyte io_buffer = accum.get_io_buffer(4096);
		
		for (size_t i = 0; i != MAX_FILES_READ_PER_POLL; ++i)
		{
			int fd = m_dir.next_fd();
			
			// If we've exhaused this walk of the directory, halt the poll
			if (fd == -1)
			{
				m_dir.reset();
				break;
			}
			
			ssize_t got = read(fd, io_buffer[]);
			close(fd);
			
			if (got > 0)
				accum.add(&io_buffer[0], got, ENTROPY_ESTIMATE);
			
			if (accum.polling_goal_achieved())
				break;
		}
	}

	this(in string root_dir)
	{
		m_path = root_dir;
		m_dir = null;
	}

private:
	const string m_path;
	Unique!File_Descriptor_Source m_dir;
};