/*
* Unix EntropySource
* (C) 1999-2009,2013 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.entropy.unix_procs;

import botan.constants;
static if (BOTAN_HAS_ENTROPY_SRC_UNIX_PROCESS_RUNNER):

import botan.entropy.entropy_src;
import botan.utils.types;
import botan.utils.parsing;
import std.algorithm;
import core.sys.posix.sys.types;
import core.sys.posix.sys.stat;
import core.sys.posix.unistd;
import core.sys.posix.sys.socket;
import core.sys.posix.sys.wait;
import core.sys.posix.sys.resource;
import core.sys.posix.signal;
import std.c.stdlib;

/**
* Entropy source for generic Unix. Runs various programs trying to
* gather data hard for a remote attacker to guess. Probably not too
* effective against local attackers as they can sample from the same
* distribution.
*/
final class Unix_EntropySource : EntropySource
{
public:
    @property string name() const { return "Unix Process Runner"; }

    void poll(ref Entropy_Accumulator accum)
    {
        // refuse to run as root (maybe instead setuid to nobody before exec?)
        // fixme: this should also check for setgid
        if (getuid() == 0 || geteuid() == 0)
            return;
        
        if (m_sources.empty)
        {
            auto sources = get_default_sources();
            
            foreach (src; sources)
            {
                const string path = find_full_path_if_exists(m_trusted_paths, src[0]);
                if (path != "")
                {
                    src[0] = path;
                    m_sources.push_back(src);
                }
            }
        }
        
        if (m_sources.empty)
            return; // still empty, really nothing to try
        
        __gshared immutable size_t MS_WAIT_TIME = 32;
        __gshared immutable double ENTROPY_ESTIMATE = 1.0 / 1024;
        
        Secure_Vector!ubyte io_buffer = accum.get_io_buffer(4*1024); // page
        
        while (!accum.polling_goal_achieved())
        {
            while (m_procs.length < m_concurrent)
                m_procs.emplace_back(Unix_Process(next_source()));
            
            fd_set read_set;
            FD_ZERO(&read_set);
            
            Vector!( int ) fds;
            
            foreach (ref proc; m_procs)
            {
                int fd = proc.fd();
                if (fd > 0)
                {
                    fds.push_back(fd);
                    FD_SET(fd, &read_set);
                }
            }
            
            if (fds.empty)
                break;
            
            const int max_fd = *std.algorithm.max_element(fds.ptr, fds.end());
            
            timeval timeout;
            timeout.tv_sec = (MS_WAIT_TIME / 1000);
            timeout.tv_usec = (MS_WAIT_TIME % 1000) * 1000;
            
            if (select(max_fd + 1, &read_set, null, null, &timeout) < 0)
                return; // or continue?
            
            foreach (ref proc; m_procs)
            {
                int fd = proc.fd();
                
                if (FD_ISSET(fd, &read_set))
                {
                    const ssize_t got = read(fd, io_buffer.ptr, io_buffer.length);
                    if (got > 0)
                        accum.add(io_buffer.ptr, got, ENTROPY_ESTIMATE);
                    else
                        proc.spawn(next_source());
                }
            }
        }
    }


    /**
    * @param trusted_paths is a list of directories that are assumed
    *          to contain only 'safe' binaries. If an attacker can write
    *          an executable to one of these directories then we will
    *          run arbitrary code.
    */
    this(in Vector!string trusted_path, size_t proc_cnt = 0)
    {
        m_trusted_paths = trusted_path;
        m_concurrent = concurrent_processes(proc_cnt);
    }
private:
    /**
    * Default Commands for Entropy Gathering
    */
    static Vector!(string[]) get_default_sources()
    {
        Vector!(string[]) srcs;
        
        srcs.push_back([ "netstat", "-in" ]);
        srcs.push_back([ "pfstat" ]);
        srcs.push_back([ "vmstat", "-s" ]);
        srcs.push_back([ "vmstat" ]);
        
        srcs.push_back([ "arp", "-a", "-n" ]);
        srcs.push_back([ "ifconfig", "-a" ]);
        srcs.push_back([ "iostat" ]);
        srcs.push_back([ "ipcs", "-a" ]);
        srcs.push_back([ "mpstat" ]);
        srcs.push_back([ "netstat", "-an" ]);
        srcs.push_back([ "netstat", "-s" ]);
        srcs.push_back([ "nfsstat" ]);
        srcs.push_back([ "portstat" ]);
        srcs.push_back([ "procinfo", "-a" ]);
        srcs.push_back([ "pstat", "-T" ]);
        srcs.push_back([ "pstat", "-s" ]);
        srcs.push_back([ "uname", "-a" ]);
        srcs.push_back([ "uptime" ]);
        
        srcs.push_back([ "listarea" ]);
        srcs.push_back([ "listdev" ]);
        srcs.push_back([ "ps", "-A" ]);
        srcs.push_back([ "sysinfo" ]);
        
        srcs.push_back([ "finger" ]);
        srcs.push_back([ "mailstats" ]);
        srcs.push_back([ "rpcinfo", "-p", "localhost" ]);
        srcs.push_back([ "who" ]);
        
        srcs.push_back([ "df", "-l" ]);
        srcs.push_back([ "dmesg" ]);
        srcs.push_back([ "last", "-5" ]);
        srcs.push_back([ "ls", "-alni", "/proc" ]);
        srcs.push_back([ "ls", "-alni", "/tmp" ]);
        srcs.push_back([ "pstat", "-f" ]);
        
        srcs.push_back([ "ps", "-elf" ]);
        srcs.push_back([ "ps", "aux" ]);
        
        srcs.push_back([ "lsof", "-n" ]);
        srcs.push_back([ "sar", "-A" ]);
        
        return srcs;
    }

    struct Unix_Process
    {
    public:
        int fd() const { return m_fd; }

        void spawn(in string[] args)
        {
            shutdown();
            
            int[2] pipe;
            if (pipe(pipe) != 0)
                return;
            
            pid_t pid = fork();
            
            if (pid == -1)
            {
                close(pipe[0]);
                close(pipe[1]);
            }
            else if (pid > 0) // in parent
            {
                m_pid = pid;
                m_fd = pipe[0];
                close(pipe[1]);
            }
            else // in child
            {
                if (dup2(pipe[1], STDOUT_FILENO) == -1)
                    exit(127);
                if (close(pipe[0]) != 0 || close(pipe[1]) != 0)
                    exit(127);
                if (close(STDERR_FILENO) != 0)
                    exit(127);
                
                do_exec(args);
                exit(127);
            }
        }

        void shutdown()
        {
            if (m_pid == -1)
                return;
            
            close(m_fd);
            m_fd = -1;
            
            pid_t reaped = waitpid(m_pid, null, WNOHANG);
            
            if (reaped == 0)
            {
                /*
                * Child is still alive - send it SIGTERM, sleep for a bit and
                * try to reap again, if still alive send SIGKILL
                */
                kill(m_pid, SIGTERM);
                
                timeval tv;
                tv.tv_sec = 0;
                tv.tv_usec = 1000;
                select(0, null, null, null, &tv);
                
                reaped = waitpid(m_pid, null, WNOHANG);
                
                if (reaped == 0)
                {
                    kill(m_pid, SIGKILL);
                    do
                        reaped = waitpid(m_pid, null, 0);
                    while (reaped == -1);
                }
            }
            
            m_pid = -1;
        }

        this(in string[] args) { spawn(args); }

        ~this() { shutdown(); }

        this(ref Unix_Process other)
        {
            std.algorithm.swap(m_fd, other.m_fd);
            std.algorithm.swap(m_pid, other.m_pid);
        }
    private:
        int m_fd = -1;
        pid_t m_pid = -1;
    }

    string[] next_source()
    {
        const src = m_sources[m_sources_idx];
        m_sources_idx = (m_sources_idx + 1) % m_sources.length;
        return src;
    }


    const Vector!string m_trusted_paths;
    const size_t m_concurrent;

    Vector!(string[]) m_sources;
    size_t m_sources_idx = 0;

    Vector!Unix_Process m_procs;
}

final class UnixProcessInfo_EntropySource : EntropySource
{
public:
    @property string name() const { return "Unix Process Info"; }

    void poll(ref Entropy_Accumulator accum)
    {
        accum.add(getpid(),  0.0);
        accum.add(getppid(), 0.0);
        accum.add(getuid(),  0.0);
        accum.add(getgid(),  0.0);
        accum.add(getsid(0),  0.0);
        accum.add(getpgrp(), 0.0);
        
        rusage usage;
        getrusage(RUSAGE_SELF, &usage);
        accum.add(usage, 0.0);
        
        getrusage(RUSAGE_CHILDREN, &usage);
        accum.add(usage, 0.0);
    }

}

private:

string find_full_path_if_exists(in Vector!string trusted_path, in string proc)
{
    foreach (dir; trusted_path)
    {
        const string full_path = dir ~ "/" ~ proc;
        if (access(full_path.toStringz, X_OK) == 0)
            return full_path;
    }
    
    return "";
}

size_t concurrent_processes(size_t user_request)
{
    __gshared immutable size_t DEFAULT_CONCURRENT = 2;
    __gshared immutable size_t MAX_CONCURRENT = 8;
    
    if (user_request > 0 && user_request < MAX_CONCURRENT)
        return user_request;
    
    const long online_cpus = sysconf(_SC_NPROCESSORS_ONLN);
    
    if (online_cpus > 0)
        return cast(size_t)(online_cpus); // maybe fewer?
    
    return DEFAULT_CONCURRENT;
}

void do_exec(in string[] args)
{
    // cleaner way to do this?
    string arg0 = (args.length > 0) ? args[0].toStringz : null;
    string arg1 = (args.length > 1) ? args[1].toStringz : null;
    string arg2 = (args.length > 2) ? args[2].toStringz : null;
    string arg3 = (args.length > 3) ? args[3].toStringz : null;
    string arg4 = (args.length > 4) ? args[4].toStringz : null;
    
    execl(arg0, arg0, arg1, arg2, arg3, arg4, NULL);
}
