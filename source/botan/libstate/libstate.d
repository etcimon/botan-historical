/*
* Library Internal/Global State
* (C) 1999-2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

import botan.libstate;
import botan.charset;
import botan.engine;
import botan.cpuid;
import botan.oids;
import botan.internal.core_engine;
import botan.internal.stl_util;
import algorithm;

#if defined(BOTAN_HAS_SELFTESTS)
  import botan.selftest;
#endif

#if defined(BOTAN_HAS_ENGINE_ASSEMBLER)
  import botan.internal.asm_engine;
#endif

#if defined(BOTAN_HAS_ENGINE_AES_ISA)
  import botan.internal.aes_isa_engine;
#endif

#if defined(BOTAN_HAS_ENGINE_SIMD)
  import botan.internal.simd_engine;
#endif

#if defined(BOTAN_HAS_ENGINE_GNU_MP)
  import botan.internal.gnump_engine;
#endif

#if defined(BOTAN_HAS_ENGINE_OPENSSL)
  import botan.internal.openssl_engine;
#endif
/*
* Return a reference to the Algorithm_Factory
*/
Algorithm_Factory& Library_State::algorithm_factory() const
{
	if (!m_algorithm_factory)
		throw new Invalid_State("Uninitialized in Library_State::algorithm_factory");
	return *m_algorithm_factory;
}

/*
* Return a reference to the global PRNG
*/
RandomNumberGenerator& Library_State::global_rng()
{
	return *m_global_prng;
}

void Library_State::initialize()
{
	if (m_algorithm_factory.get())
		throw new Invalid_State("Library_State has already been initialized");

	CPUID::initialize();

	SCAN_Name::set_default_aliases();
	OIDS::set_defaults();

	m_algorithm_factory.reset(new Algorithm_Factory());

#if defined(BOTAN_HAS_ENGINE_GNU_MP)
	algorithm_factory().add_engine(new GMP_Engine);
#endif

#if defined(BOTAN_HAS_ENGINE_OPENSSL)
	algorithm_factory().add_engine(new OpenSSL_Engine);
#endif

#if defined(BOTAN_HAS_ENGINE_AES_ISA)
	algorithm_factory().add_engine(new AES_ISA_Engine);
#endif

#if defined(BOTAN_HAS_ENGINE_SIMD)
	algorithm_factory().add_engine(new SIMD_Engine);
#endif

#if defined(BOTAN_HAS_ENGINE_ASSEMBLER)
	algorithm_factory().add_engine(new Assembler_Engine);
#endif

	algorithm_factory().add_engine(new Core_Engine);

	m_sources = entropy_sources();

	m_global_prng.reset(new Serialized_RNG());

#if defined(BOTAN_HAS_SELFTESTS)
	confirm_startup_self_tests(algorithm_factory());
#endif
}

}
