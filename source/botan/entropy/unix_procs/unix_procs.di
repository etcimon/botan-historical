/*
* Unix EntropySource
* (C) 1999-2009,2013 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.entropy_src;
import vector;
import sys.types;
/**
* Entropy source for generic Unix. Runs various programs trying to
* gather data hard for a remote attacker to guess. Probably not too
* effective against local attackers as they can sample from the same
* distribution.
*/
class Unix_EntropySource : public EntropySource
{
	public:
		string name() const { return "Unix Process Runner"; }

		void poll(Entropy_Accumulator& accum) override;

		/**
		* @param trusted_paths is a list of directories that are assumed
		*		  to contain only 'safe' binaries. If an attacker can write
		*		  an executable to one of these directories then we will
		*		  run arbitrary code.
		*/
		Unix_EntropySource(in Vector!( string ) trusted_paths,
								 size_t concurrent_processes = 0);
	private:
		static Vector!( std::vector<string )> get_default_sources();

		class Unix_Process
		{
			public:
				int fd() const { return m_fd; }

				void spawn(in Vector!( string ) args);
				void shutdown();

				Unix_Process() {}

				Unix_Process(in Vector!( string ) args) { spawn(args); }

				~Unix_Process() { shutdown(); }

				Unix_Process(Unix_Process&& other)
				{
					std::swap(m_fd, other.m_fd);
					std::swap(m_pid, other.m_pid);
				}

				Unix_Process(in Unix_Process);
				Unix_Process& operator=(in Unix_Process);
			private:
				int m_fd = -1;
				pid_t m_pid = -1;
		};

		const Vector!( string )& next_source();

		const Vector!( string ) m_trusted_paths;
		const size_t m_concurrent;

		Vector!( std::vector<string )> m_sources;
		size_t m_sources_idx = 0;

		Vector!( Unix_Process ) m_procs;
};

class UnixProcessInfo_EntropySource : public EntropySource
{
	public:
		string name() const { return "Unix Process Info"; }

		void poll(Entropy_Accumulator& accum);
};