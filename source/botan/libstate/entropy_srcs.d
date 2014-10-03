/*
* Global PRNG
* (C) 2008-2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

import botan.libstate;

#if defined(BOTAN_HAS_ENTROPY_SRC_HIGH_RESOLUTION_TIMER)
  import botan.internal.hres_timer;
#endif

#if defined(BOTAN_HAS_ENTROPY_SRC_RDRAND)
  import botan.internal.rdrand;
#endif

#if defined(BOTAN_HAS_ENTROPY_SRC_DEV_RANDOM)
  import botan.internal.dev_random;
#endif

#if defined(BOTAN_HAS_ENTROPY_SRC_EGD)
  import botan.internal.es_egd;
#endif

#if defined(BOTAN_HAS_ENTROPY_SRC_UNIX_PROCESS_RUNNER)
  import botan.internal.unix_procs;
#endif

#if defined(BOTAN_HAS_ENTROPY_SRC_BEOS)
  import botan.internal.es_beos;
#endif

#if defined(BOTAN_HAS_ENTROPY_SRC_CAPI)
  import botan.internal.es_capi;
#endif

#if defined(BOTAN_HAS_ENTROPY_SRC_WIN32)
  import botan.internal.es_win32;
#endif

#if defined(BOTAN_HAS_ENTROPY_SRC_PROC_WALKER)
  import botan.internal.proc_walk;
#endif
Vector!( Unique!EntropySource ) Library_State::entropy_sources()
{
	Vector!( Unique!EntropySource ) sources;

#if defined(BOTAN_HAS_ENTROPY_SRC_HIGH_RESOLUTION_TIMER)
	sources.push_back(Unique!EntropySource(new High_Resolution_Timestamp));
#endif

#if defined(BOTAN_HAS_ENTROPY_SRC_RDRAND)
	sources.push_back(Unique!EntropySource(new Intel_Rdrand));
#endif

#if defined(BOTAN_HAS_ENTROPY_SRC_UNIX_PROCESS_RUNNER)
	sources.push_back(Unique!EntropySource(new UnixProcessInfo_EntropySource));
#endif

#if defined(BOTAN_HAS_ENTROPY_SRC_DEV_RANDOM)
	sources.push_back(Unique!EntropySource(new Device_EntropySource(
	{ "/dev/random", "/dev/srandom", "/dev/urandom" }
	)));
#endif

#if defined(BOTAN_HAS_ENTROPY_SRC_CAPI)
	sources.push_back(Unique!EntropySource(new Win32_CAPI_EntropySource));
#endif

#if defined(BOTAN_HAS_ENTROPY_SRC_PROC_WALKER)
	sources.push_back(Unique!EntropySource(
		new ProcWalking_EntropySource("/proc")));
#endif

#if defined(BOTAN_HAS_ENTROPY_SRC_WIN32)
	sources.push_back(Unique!EntropySource(new Win32_EntropySource));
#endif

#if defined(BOTAN_HAS_ENTROPY_SRC_BEOS)
	sources.push_back(Unique!EntropySource(new BeOS_EntropySource));
#endif

#if defined(BOTAN_HAS_ENTROPY_SRC_UNIX_PROCESS_RUNNER)
	sources.push_back(Unique!EntropySource(
		new Unix_EntropySource(
		{ "/bin", "/sbin", "/usr/bin", "/usr/sbin" }
		)));
#endif

#if defined(BOTAN_HAS_ENTROPY_SRC_EGD)
	sources.push_back(Unique!EntropySource(
		new EGD_EntropySource({ "/var/run/egd-pool", "/dev/egd-pool" })
		));
#endif

	return sources;
}

void Library_State::poll_available_sources(class Entropy_Accumulator& accum)
{
	m_entropy_src_mutex.lock(); scope(exit) m_entropy_src_mutex.unlock();

	if (m_sources.empty())
		throw new Exception("No entropy sources enabled at build time, poll failed");

	size_t poll_attempt = 0;

	while(!accum.polling_goal_achieved() && poll_attempt < 16)
	{
		const size_t src_idx = poll_attempt % m_sources.size();
		m_sources[src_idx].poll(accum);
		++poll_attempt;
	}
}

}

