/*
* File Tree Walking EntropySource
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.entropy.proc_walk;

import botan.constants;
static if (BOTAN_HAS_ENTROPY_SRC_PROC_WALKER):

import botan.entropy.entropy_src;
import botan.utils.memory.zeroize;
import botan.utils.types;
import core.stdc.string;

import core.sys.posix.sys.types;
import core.sys.posix.sys.stat;
import core.sys.posix.fcntl;
import core.sys.posix.unistd;
import core.sys.posix.dirent;


final class DirectoryWalker : FileDescriptorSource
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
    
    int nextFd();
private:
    void addDirectory(in string dirname)
    {
        m_dirlist.pushBack(dirname);
    }
    
    Pair!(dirent*, string) getNextDirent()
    {
        while (m_cur_dir.first)
        {
            if (dirent* dir = readdir(m_cur_dir.first))
                return Pair(dir, m_cur_dir.second);
            
            closedir(m_cur_dir.first);
            m_cur_dir = Pair!(DIR*, string)(null, "");
            
            while (!m_dirlist.empty && !m_cur_dir.first)
            {
                const string next_dir_name = m_dirlist[0];
                m_dirlist.popFront();
                
                if (DIR* next_dir = opendir(next_dir_name.toStringz))
                    m_cur_dir = Pair(next_dir, next_dir_name);
            }
        }
        
        return Pair!(dirent*, string)(null, ""); // nothing left
    }
    
    Pair!(DIR*, string) m_cur_dir;
    Deque!string m_dirlist;
}


class FileDescriptorSource
{
public:
    int nextFd()
    {
        while (true)
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
}

/**
* File Tree Walking Entropy Source
*/
final class ProcWalkingEntropySource : EntropySource
{
public:
    @property string name() const { return "Proc Walker"; }

    void poll(ref EntropyAccumulator accum)
    {
        __gshared immutable size_t MAX_FILES_READ_PER_POLL = 2048;
        const double ENTROPY_ESTIMATE = 1.0 / (8*1024);
        
        if (!m_dir)
            m_dir = new DirectoryWalker(m_path);
        
        SecureVector!ubyte io_buffer = accum.getIoBuffer(4096);
        
        foreach (size_t i; 0 .. MAX_FILES_READ_PER_POLL)
        {
            int fd = m_dir.nextFd();
            
            // If we've exhaused this walk of the directory, halt the poll
            if (fd == -1)
            {
                m_dir.clear();
                break;
            }
            
            ssize_t got = read(fd, io_buffer[]);
            close(fd);
            
            if (got > 0)
                accum.add(io_buffer.ptr, got, ENTROPY_ESTIMATE);
            
            if (accum.pollingGoalAchieved())
                break;
        }
    }

    this(in string root_dir)
    {
        m_path = root_dir;
        m_dir.clear();
    }

private:
    const string m_path;
    Unique!FileDescriptorSource m_dir;
}