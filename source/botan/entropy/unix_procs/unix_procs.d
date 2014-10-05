 /*
* Gather entropy by running various system commands in the hopes that
* some of the output cannot be guessed by a remote attacker.
*
* (C) 1999-2009,2013 Jack Lloyd
*	  2012 Markus Wanner
*
* Distributed under the terms of the Botan license
*/

import botan.internal.unix_procs;
import botan.parsing;
import algorithm;

import sys.time;
import sys.stat;
import sys.wait;
import sys.resource;
import unistd.h;
import signal.h;
import stdlib.h;
namespace {

string find_full_path_if_exists(in Vector!string trusted_path,
												 in string proc)
{
	foreach (dir; trusted_path)
	{
		const string full_path = dir ~ "/" ~ proc;
		if (::access(full_path.c_str(), X_OK) == 0)
			return full_path;
	}

	return "";
}

size_t concurrent_processes(size_t user_request)
{
	const size_t DEFAULT_CONCURRENT = 2;
	const size_t MAX_CONCURRENT = 8;

	if (user_request > 0 && user_request < MAX_CONCURRENT)
		return user_request;

	const long online_cpus = ::sysconf(_SC_NPROCESSORS_ONLN);

	if (online_cpus > 0)
		return cast(size_t)(online_cpus); // maybe fewer?

	return DEFAULT_CONCURRENT;
}

}

/**
* Unix_EntropySource Constructor
*/
Unix_EntropySource::Unix_EntropySource(in Vector!string trusted_path,
													size_t proc_cnt) :
	m_trusted_paths(trusted_path),
	m_concurrent(concurrent_processes(proc_cnt))
{
}

void UnixProcessInfo_EntropySource::poll(Entropy_Accumulator& accum)
{
	accum.add(::getpid(),  0.0);
	accum.add(::getppid(), 0.0);
	accum.add(::getuid(),  0.0);
	accum.add(::getgid(),  0.0);
	accum.add(::getsid(0),  0.0);
	accum.add(::getpgrp(), 0.0);

	struct ::rusage usage;
	::getrusage(RUSAGE_SELF, &usage);
	accum.add(usage, 0.0);

	::getrusage(RUSAGE_CHILDREN, &usage);
	accum.add(usage, 0.0);
}

namespace {

void do_exec(in Vector!string args)
{
	// cleaner way to do this?
	string arg0 = (args.size() > 0) ? args[0].c_str() : null;
	string arg1 = (args.size() > 1) ? args[1].c_str() : null;
	string arg2 = (args.size() > 2) ? args[2].c_str() : null;
	string arg3 = (args.size() > 3) ? args[3].c_str() : null;
	string arg4 = (args.size() > 4) ? args[4].c_str() : null;

	::execl(arg0, arg0, arg1, arg2, arg3, arg4, NULL);
}

}

void Unix_EntropySource::Unix_Process::spawn(in Vector!string args)
{
	shutdown();

	int pipe[2];
	if (::pipe(pipe) != 0)
		return;

	pid_t pid = ::fork();

	if (pid == -1)
	{
		::close(pipe[0]);
		::close(pipe[1]);
	}
	else if (pid > 0) // in parent
	{
		m_pid = pid;
		m_fd = pipe[0];
		::close(pipe[1]);
	}
	else // in child
	{
		if (::dup2(pipe[1], STDOUT_FILENO) == -1)
			::exit(127);
		if (::close(pipe[0]) != 0 || ::close(pipe[1]) != 0)
			::exit(127);
		if (close(STDERR_FILENO) != 0)
			::exit(127);

		do_exec(args);
		::exit(127);
	}
}

void Unix_EntropySource::Unix_Process::shutdown()
{
	if (m_pid == -1)
		return;

	::close(m_fd);
	m_fd = -1;

	pid_t reaped = waitpid(m_pid, null, WNOHANG);

	if (reaped == 0)
	{
		/*
		* Child is still alive - send it SIGTERM, sleep for a bit and
		* try to reap again, if still alive send SIGKILL
		*/
		kill(m_pid, SIGTERM);

		struct ::timeval tv;
		tv.tv_sec = 0;
		tv.tv_usec = 1000;
		select(0, null, null, null, &tv);

		reaped = ::waitpid(m_pid, null, WNOHANG);

		if (reaped == 0)
		{
			::kill(m_pid, SIGKILL);
			do
				reaped = ::waitpid(m_pid, null, 0);
			while(reaped == -1);
		}
	}

	m_pid = -1;
}

const Vector!string& Unix_EntropySource::next_source()
{
	const auto& src = m_sources.at(m_sources_idx);
	m_sources_idx = (m_sources_idx + 1) % m_sources.size();
	return src;
}

void Unix_EntropySource::poll(Entropy_Accumulator& accum)
{
	// refuse to run as root (maybe instead setuid to nobody before exec?)
	// fixme: this should also check for setgid
	if (::getuid() == 0 || ::geteuid() == 0)
		return;

	if (m_sources.empty())
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

	if (m_sources.empty())
		return; // still empty, really nothing to try

	const size_t MS_WAIT_TIME = 32;
	const double ENTROPY_ESTIMATE = 1.0 / 1024;

	SafeVector!ubyte io_buffer = accum.get_io_buffer(4*1024); // page

	while(!accum.polling_goal_achieved())
	{
		while(m_procs.size() < m_concurrent)
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

		if (fds.empty())
			break;

		const int max_fd = *std.algorithm.max_element(fds.begin(), fds.end());

		struct ::timeval timeout;
		timeout.tv_sec = (MS_WAIT_TIME / 1000);
		timeout.tv_usec = (MS_WAIT_TIME % 1000) * 1000;

		if (::select(max_fd + 1, &read_set, null, null, &timeout) < 0)
			return; // or continue?

		foreach (ref proc; m_procs)
		{
			int fd = proc.fd();

			if (FD_ISSET(fd, &read_set))
			{
				const ssize_t got = ::read(fd, &io_buffer[0], io_buffer.size());
				if (got > 0)
					accum.add(&io_buffer[0], got, ENTROPY_ESTIMATE);
				else
					proc.spawn(next_source());
			}
		}
	}
}

}
