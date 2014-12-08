/*
* Library Internal/Global State
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.libstate.libstate;

public import botan.utils.types;
public import botan.algo_factory.algo_factory;
public import botan.libstate.lookup;
import botan.libstate.global_state;
import botan.rng.rng;
import botan.utils.charset;
import botan.engine.engine;
import botan.utils.cpuid;
import botan.asn1.oids;
import botan.engine.core_engine;
import botan.utils.containers.multimap;
import std.algorithm;
import core.sync.mutex;
import std.typecons;
import botan.entropy.entropy_src;
import botan.utils.containers.hashmap;

import botan.constants;
static if (BOTAN_HAS_SELFTESTS)
    import botan.selftest.selftest;
// Engines
static if (BOTAN_HAS_ENGINE_ASSEMBLER)
    import botan.engine.asm_engine;
static if (BOTAN_HAS_ENGINE_AES_ISA)
    import botan.engine.aes_isa_engine;
static if (BOTAN_HAS_ENGINE_SIMD)
    import botan.engine.simd_engine.simd_engine;
static if (BOTAN_HAS_ENGINE_GNU_MP)
    import botan.engine.gnump_engine;
static if (BOTAN_HAS_ENGINE_OPENSSL)
    import botan.engine.openssl_engine;
// Entropy sources
static if (BOTAN_HAS_ENTROPY_SRC_HIGH_RESOLUTION_TIMER)
    import botan.entropy.hres_timer;
static if (BOTAN_HAS_ENTROPY_SRC_RDRAND)
    import botan.entropy.rdrand;
static if (BOTAN_HAS_ENTROPY_SRC_DEV_RANDOM)
    import botan.entropy.dev_random;
static if (BOTAN_HAS_ENTROPY_SRC_EGD)
    import botan.entropy.es_egd;
static if (BOTAN_HAS_ENTROPY_SRC_UNIX_PROCESS_RUNNER)
    import botan.entropy.unix_procs;
static if (BOTAN_HAS_ENTROPY_SRC_BEOS)
    import botan.entropy.es_beos;
static if (BOTAN_HAS_ENTROPY_SRC_CAPI)
    import botan.entropy.es_capi;
static if (BOTAN_HAS_ENTROPY_SRC_WIN32)
    import botan.entropy.es_win32;
static if (BOTAN_HAS_ENTROPY_SRC_PROC_WALKER)
    import botan.entropy.proc_walk;


alias LibraryState = FreeListRef!LibraryStateImpl;

/**
* Global Library State
*/
class LibraryStateImpl
{
public:
    shared this()
    {
        m_entropy_src_mutex = new Mutex;
        m_global_prng = new shared SerializedRNG();
    }

    void initialize()
    {
        if (m_initialized)
            return false;

        SCANToken.setDefaultAliases();
        OIDS.setDefaults();

        m_algorithm_factory = AlgorithmFactory.init;
        
        static if (BOTAN_HAS_ENGINE_GNU_MP)
            algorithmFactory().addEngine(new GMPEngine);
        
        
        static if (BOTAN_HAS_ENGINE_OPENSSL)
            algorithmFactory().addEngine(new OpenSSLEngine);
        
        
        static if (BOTAN_HAS_ENGINE_AES_ISA)
            algorithmFactory().addEngine(new AESISAEngine);
        
        
        static if (BOTAN_HAS_ENGINE_SIMD)
            algorithmFactory().addEngine(new SIMDEngine);
        
        
        static if (BOTAN_HAS_ENGINE_ASSEMBLER)
            algorithmFactory().addEngine(new AssemblerEngine);
        
        
        algorithmFactory().addEngine(new CoreEngine);

        synchronized(m_entropy_src_mutex)
            if (!m_sources)
                m_sources = entropySources();

        static if (BOTAN_HAS_SELFTESTS)
            confirmStartupSelfTests(algorithmFactory());

        m_initialized = true;

    }

    /**
    * Return a reference to the AlgorithmFactory
    * @return global AlgorithmFactory
    */
    AlgorithmFactory algorithmFactory() const
    {
        if (!m_algorithm_factory)
            throw new InvalidState("Uninitialized in algorithmFactory");
        return m_algorithm_factory;
    }

    /**
    * Return a reference to the global PRNG
    * @return global RandomNumberGenerator
    */
    RandomNumberGenerator globalRng()
    {
        return m_global_prng;
    }

    void pollAvailableSources(ref EntropyAccumulator accum)
    {
        synchronized(m_entropy_src_mutex){
            if (m_sources.empty)
                throw new Exception("No entropy sources enabled at build time, poll failed");
            
            size_t poll_attempt = 0;
            
            while (!accum.pollingGoalAchieved() && poll_attempt < 16)
            {
                const size_t src_idx = poll_attempt % m_sources.length;
                m_sources[src_idx].poll(accum);
                ++poll_attempt;
            }
        }
    }

    ~this() { }
private:
    static Vector!( EntropySource ) entropySources()
    {
        Vector!( EntropySource ) sources;
        
        static if (BOTAN_HAS_ENTROPY_SRC_HIGH_RESOLUTION_TIMER)
            sources.pushBack(new HighResolutionTimestamp);
                
        static if (BOTAN_HAS_ENTROPY_SRC_RDRAND)
            sources.pushBack(new IntelRdrand);
                
        static if (BOTAN_HAS_ENTROPY_SRC_UNIX_PROCESS_RUNNER)
            sources.pushBack(new UnixProcessInfoEntropySource);
                
        static if (BOTAN_HAS_ENTROPY_SRC_DEV_RANDOM)
            sources.pushBack(new DeviceEntropySource(
                [ "/dev/random", "/dev/srandom", "/dev/urandom" ]
            ));
                
        static if (BOTAN_HAS_ENTROPY_SRC_CAPI)
            sources.pushBack(EntropySource(new Win32CAPIEntropySource));
                
        static if (BOTAN_HAS_ENTROPY_SRC_PROC_WALKER)
            sources.pushBack(new ProcWalkingEntropySource("/proc"));
                
        static if (BOTAN_HAS_ENTROPY_SRC_WIN32)
            sources.pushBack(new Win32EntropySource);
                
        static if (BOTAN_HAS_ENTROPY_SRC_BEOS)
            sources.pushBack(new BeOSEntropySource);

        static if (BOTAN_HAS_ENTROPY_SRC_UNIX_PROCESS_RUNNER)
            sources.pushBack(
                new UnixEntropySource(    [ "/bin", "/sbin", "/usr/bin", "/usr/sbin" ] )
            );
                
        static if (BOTAN_HAS_ENTROPY_SRC_EGD)
            sources.pushBack(
                new EGDEntropySource( [ "/var/run/egd-pool", "/dev/egd-pool" ] )
                );
                
        return sources;
    }

    shared SerializedRNG m_global_prng;
    __gshared Mutex m_entropy_src_mutex;
    __gshared Vector!( EntropySource ) m_sources;

    AlgorithmFactory m_algorithm_factory;
    bool m_initialized;
}