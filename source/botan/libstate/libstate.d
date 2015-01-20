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
public import botan.libstate.global_state;
import botan.rng.rng;
import botan.utils.charset;
import botan.engine.engine;
import botan.utils.cpuid;
import botan.asn1.oids;
import botan.engine.core_engine;
import botan.utils.containers.multimap;
import std.algorithm;
import core.sync.mutex;
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



/**
* Global Library State
*/
final class LibraryState
{
public:
    this()
    {
        m_entropy_src_mutex = new Mutex;
    }

    void initialize()
    {
        logTrace("LibraryState.initialize()");
        if (m_initialized)
            return;

        SCANToken.setDefaultAliases();
        static if (BOTAN_HAS_PUBLIC_KEY_CRYPTO) 
			OIDS.setDefaults();

        m_algorithm_factory = Unique!AlgorithmFactory(new AlgorithmFactory);
        
        static if (BOTAN_HAS_ENGINE_GNU_MP) {
            logTrace("Loading GNU MP Engine");
            algorithmFactory().addEngine(new GMPEngine);
        }
        
        static if (BOTAN_HAS_ENGINE_OPENSSL) {
            logTrace("Loading OpenSSL Engine");
            algorithmFactory().addEngine(new OpenSSLEngine);
        }
        
        static if (BOTAN_HAS_ENGINE_AES_ISA) {             
            logTrace("Loading AES ISA Engine");
            algorithmFactory().addEngine(new AESISAEngine);        
        }
        
        static if (BOTAN_HAS_ENGINE_SIMD) {
            logTrace("Loading SIMD Engine");
            algorithmFactory().addEngine(new SIMDEngine);
        }
        
        static if (BOTAN_HAS_ENGINE_ASSEMBLER) {
            logTrace("Loading Assembler Engine");
            algorithmFactory().addEngine(new AssemblerEngine);
        
        }
        
        algorithmFactory().addEngine(new CoreEngine);

        synchronized(m_entropy_src_mutex)
            if (m_sources.length == 0)
                m_sources = entropySources();

        logTrace("new SerializedRNG()");

        m_global_prng = new SerializedRNG();
        logTrace("Done serialized RNG");
        static if (BOTAN_HAS_SELFTESTS) {        
            logTrace("Startup Self-Tests");
            confirmStartupSelfTests(algorithmFactory());
        }
        logTrace("Done Self Tests");
        m_initialized = true;

    }

    /**
    * Return a reference to the AlgorithmFactory
    * @return global AlgorithmFactory
    */
    AlgorithmFactory algorithmFactory()
    {
        if (!m_algorithm_factory)
            throw new InvalidState("Uninitialized in algorithmFactory");
        return *m_algorithm_factory;
    }

    /**
    * Return a reference to the global PRNG
    * @return global RandomNumberGenerator
    */
    RandomNumberGenerator globalRng()
    {
        return cast(RandomNumberGenerator)m_global_prng;
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
                
        static if (BOTAN_HAS_ENTROPY_SRC_UNIX_PROCESS_RUNNER) version(Posix)
            sources.pushBack(new UnixProcessInfoEntropySource);
                
        static if (BOTAN_HAS_ENTROPY_SRC_DEV_RANDOM) version(Posix)
            sources.pushBack(new DeviceEntropySource(
                Vector!string([ "/dev/random", "/dev/srandom", "/dev/urandom" ])
            ));
                
        static if (BOTAN_HAS_ENTROPY_SRC_CAPI) version(Windows)
            sources.pushBack(EntropySource(new Win32CAPIEntropySource));
                
        static if (BOTAN_HAS_ENTROPY_SRC_PROC_WALKER)
            sources.pushBack(new ProcWalkingEntropySource("/proc"));
                
        static if (BOTAN_HAS_ENTROPY_SRC_WIN32) version(Windows)
            sources.pushBack(new Win32EntropySource);
                
        static if (BOTAN_HAS_ENTROPY_SRC_BEOS)
            sources.pushBack(new BeOSEntropySource);

        static if (BOTAN_HAS_ENTROPY_SRC_UNIX_PROCESS_RUNNER)
            sources.pushBack(
                new UnixEntropySource(   Vector!string( [ "/bin", "/sbin", "/usr/bin", "/usr/sbin" ] ) )
            );
                
        static if (BOTAN_HAS_ENTROPY_SRC_EGD)
            sources.pushBack(
                new EGDEntropySource( Vector!string( [ "/var/run/egd-pool", "/dev/egd-pool" ] ) )
                );
                
        return sources;
    }

    __gshared SerializedRNG m_global_prng;
    __gshared Mutex m_entropy_src_mutex;
    __gshared Vector!( EntropySource ) m_sources;

    Unique!AlgorithmFactory m_algorithm_factory;
    bool m_initialized;
}