/*
* Library Internal/Global State
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.libstate.libstate;

import botan.libstate.global_state;
import botan.algo_factory;
import botan.rng;
import botan.charset;
import botan.engine.engine;
import botan.utils.cpuid;
import botan.asn1.oid_lookup.oids;
import botan.internal.core_engine;
import botan.internal.stl_util;
import std.algorithm;
import core.sync.mutex;
import string;
import vector;
import map;

version(BOTAN_HAS_SELFTESTS)
	import botan.selftest;

// Engines
version(BOTAN_HAS_ENGINE_ASSEMBLER)
	import botan.internal.asm_engine;
version(BOTAN_HAS_ENGINE_AES_ISA)
	import botan.internal.aes_isa_engine;
version(BOTAN_HAS_ENGINE_SIMD)
	import botan.engine.simd_engine.simd_engine;
version(BOTAN_HAS_ENGINE_GNU_MP)
	import botan.internal.gnump_engine;
version(BOTAN_HAS_ENGINE_OPENSSL)
	import botan.internal.openssl_engine;
// Entropy sources
version(BOTAN_HAS_ENTROPY_SRC_HIGH_RESOLUTION_TIMER)
	import botan.internal.hres_timer;
version(BOTAN_HAS_ENTROPY_SRC_RDRAND)
	import botan.internal.rdrand;
version(BOTAN_HAS_ENTROPY_SRC_DEV_RANDOM)
	import botan.internal.dev_random;
version(BOTAN_HAS_ENTROPY_SRC_EGD)
	import botan.internal.es_egd;
version(BOTAN_HAS_ENTROPY_SRC_UNIX_PROCESS_RUNNER)
	import botan.internal.unix_procs;
version(BOTAN_HAS_ENTROPY_SRC_BEOS)
	import botan.internal.es_beos;
version(BOTAN_HAS_ENTROPY_SRC_CAPI)
	import botan.internal.es_capi;
version(BOTAN_HAS_ENTROPY_SRC_WIN32)
	import botan.internal.es_win32;
version(BOTAN_HAS_ENTROPY_SRC_PROC_WALKER)
	import botan.internal.proc_walk;

/**
* Global Library State
*/
class Library_State
{
public:
	this() {}

	void initialize()
	{
		if (m_algorithm_factory.release())
			throw new Invalid_State("Library_State has already been initialized");
		
		SCAN_Name.set_default_aliases();
		oids.set_defaults();
		
		m_algorithm_factory = new Algorithm_Factory();
		
		version(BOTAN_HAS_ENGINE_GNU_MP)
			algorithm_factory().add_engine(new GMP_Engine);
		
		
		version(BOTAN_HAS_ENGINE_OPENSSL)
			algorithm_factory().add_engine(new OpenSSL_Engine);
		
		
		version(BOTAN_HAS_ENGINE_AES_ISA)
			algorithm_factory().add_engine(new AES_ISA_Engine);
		
		
		version(BOTAN_HAS_ENGINE_SIMD)
			algorithm_factory().add_engine(new SIMD_Engine);
		
		
		version(BOTAN_HAS_ENGINE_ASSEMBLER)
			algorithm_factory().add_engine(new Assembler_Engine);
		
		
		algorithm_factory().add_engine(new Core_Engine);
		
		m_sources = entropy_sources();
		
		m_global_prng.reset(new Serialized_RNG());
		
		version(BOTAN_HAS_SELFTESTS)
			confirm_startup_self_tests(algorithm_factory());

	}

	/**
	* Return a reference to the Algorithm_Factory
	* @return global Algorithm_Factory
	*/
	Algorithm_Factory algorithm_factory() const
	{
		if (!m_algorithm_factory)
			throw new Invalid_State("Uninitialized in algorithm_factory");
		return m_algorithm_factory;
	}

	/**
	* Return a reference to the global PRNG
	* @return global RandomNumberGenerator
	*/
	RandomNumberGenerator global_rng()
	{
		return *m_global_prng;
	}

	void poll_available_sources(Entropy_Accumulator accum)
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
	


private:
	static Vector!( Unique!EntropySource ) entropy_sources()
	{
		Vector!( Unique!EntropySource ) sources;
		
		version(BOTAN_HAS_ENTROPY_SRC_HIGH_RESOLUTION_TIMER)
			sources.push_back(Unique!EntropySource(new High_Resolution_Timestamp));
		
		
		version(BOTAN_HAS_ENTROPY_SRC_RDRAND)
			sources.push_back(Unique!EntropySource(new Intel_Rdrand));
		
		
		version(BOTAN_HAS_ENTROPY_SRC_UNIX_PROCESS_RUNNER)
			sources.push_back(Unique!EntropySource(new UnixProcessInfo_EntropySource));
		
		
		version(BOTAN_HAS_ENTROPY_SRC_DEV_RANDOM)
			sources.push_back(Unique!EntropySource(new Device_EntropySource(
				[ "/dev/random", "/dev/srandom", "/dev/urandom" ]
			)));
		
		
		version(BOTAN_HAS_ENTROPY_SRC_CAPI)
			sources.push_back(Unique!EntropySource(new Win32_CAPI_EntropySource));
		
		
		version(BOTAN_HAS_ENTROPY_SRC_PROC_WALKER)
			sources.push_back(Unique!EntropySource(new ProcWalking_EntropySource("/proc")));
		
		
		version(BOTAN_HAS_ENTROPY_SRC_WIN32)
			sources.push_back(Unique!EntropySource(new Win32_EntropySource));

		
		version(BOTAN_HAS_ENTROPY_SRC_BEOS)
			sources.push_back(Unique!EntropySource(new BeOS_EntropySource));
		

		version(BOTAN_HAS_ENTROPY_SRC_UNIX_PROCESS_RUNNER)
			sources.push_back(Unique!EntropySource(
				new Unix_EntropySource(	[ "/bin", "/sbin", "/usr/bin", "/usr/sbin" ] )
			));
		
		
		version(BOTAN_HAS_ENTROPY_SRC_EGD)
			sources.push_back(Unique!EntropySource(
				new EGD_EntropySource( [ "/var/run/egd-pool", "/dev/egd-pool" ] )
				));
		
		
		return sources;
	}


	Unique!Serialized_RNG m_global_prng;

	Mutex m_entropy_src_mutex;
	Vector!( Unique!EntropySource ) m_sources;

	Algorithm_Factory m_algorithm_factory;
};