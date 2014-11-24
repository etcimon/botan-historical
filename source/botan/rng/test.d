module botan.rng.test;

import botan.constants;
static if (BOTAN_TEST):
import botan.libstate.libstate;
import botan.codec.hex;
import botan.rng.rng;
import core.atomic;

class Fixed_Output_RNG : RandomNumberGenerator
{
public:
    bool is_seeded() const { return !buf.empty; }
    
    ubyte random()
    {
        if (!is_seeded())
            throw new Exception("Out of bytes");
        
        ubyte output = m_buf.front();
        m_buf.pop_front();
        return output;
    }
    
    void reseed(size_t) {}
    
    void randomize(ubyte* output, size_t len)
    {
        for(size_t j = 0; j != len; j++)
            output[j] = random();
    }
    
    void add_entropy(in ubyte* b, size_t s)
    {
        m_buf.insert(b[0 .. s]);
    }
    
    @property string name() const { return "Fixed_Output_RNG"; }
    
    void clear() {}
    
    this(in Vector!ubyte input)
    {
        m_buf.insert(input.ptr[0 .. input.length]);
    }
    
    this(string in_str)
    {
        Vector!ubyte input = hex_decode(in_str);
        m_buf.insert(input.ptr[0 .. input.length]);
    }
    
    this() {}
protected:
    size_t remaining() const { return m_buf.length; }
private:
    Vector!ubyte m_buf;
};

RandomNumberGenerator get_rng(string algo_str, string ikm_hex)
{
    class AllOnce_RNG : Fixed_Output_RNG
    {
    public:
        this(in Vector!ubyte input) {
            super(input);
        }
        
        Secure_Vector!ubyte random_vec(size_t)
        {
            Secure_Vector!ubyte vec = Secure_Vector!ubyte(this.remaining());
            this.randomize(&vec[0], vec.length);
            return vec;
        }
    }
    
    const auto ikm = hex_decode(ikm_hex);
    
    Algorithm_Factory af = global_state().algorithm_factory();
    
    const auto algo_name = parse_algorithm_name(algo_str);
    
    const string rng_name = algo_name[0];
    
    static if (BOTAN_HAS_HMAC_DRBG) {
        if (rng_name == "HMAC_DRBG")
            return new HMAC_DRBG(af.make_mac("HMAC(" ~ algo_name[1] ~ ")"), new AllOnce_RNG(ikm));
    }
    
    static if (BOTAN_HAS_X931_RNG) {
        if (rng_name == "X9.31-RNG")
            return new ANSI_X931_RNG(af.make_block_cipher(algo_name[1]), new Fixed_Output_RNG(ikm));
    }
    
    return null;
}


__gshared size_t total_tests;
static if (BOTAN_HAS_X931_RNG)
size_t x931_test(string algo,
                 string ikm,
                 string output,
                 size_t L)
{
    atomicOp!"+="(total_tests, 1);
    Unique!RandomNumberGenerator rng = get_rng(algo, ikm);
    
    if (!rng)
        throw new Exception("Unknown RNG " ~ algo);
    
    const string got = hex_encode(rng.random_vec(L));
    
    if (got != output)
    {
        writeln("X9.31 " ~ got ~ " != " ~ output);
        return 1;
    }
    
    return 0;
}

static if (BOTAN_HAS_HMAC_DRBG)
size_t hmac_drbg_test(string[string] m)
{
    atomicOp!"+="(total_tests, 1);
    const string algo = m["RNG"];
    const string ikm = m["EntropyInput"];
    
    Unique!RandomNumberGenerator rng = get_rng(algo, ikm);

    if (!rng)
        throw new Exception("Unknown RNG " ~ algo);
    
    rng.reseed(0); // force initialization
    
    // now reseed
    const auto reseed_input = hex_decode(m["EntropyInputReseed"]);
    rng.add_entropy(&reseed_input[0], reseed_input.length);
    
    const string output = m["Out"];
    
    const size_t out_len = output.length / 2;
    
    rng.random_vec(out_len); // gen 1st block (discarded)
    
    const string got = hex_encode(rng.random_vec(out_len));
    
    if (got != output)
    {
        writeln(algo ~ " " ~ got ~ " != " ~ output);
        return 1;
    }
    
    return 0;
}

unittest
{
    File hmac_drbg_vec = File("test_data/hmac_drbg.vec", "r");
    File x931_vec = File("test_data/x931.vec", "r");
    
    size_t fails = 0;
    
    fails += run_tests_bb(hmac_drbg_vec, "RNG", "Out", true, hmac_drbg_test);
    
    fails += run_tests_bb(x931_vec, "RNG", "Out", true,
                          (string[string] m) {
                                return x931_test(m["RNG"], m["IKM"], m["Out"], to!uint(m["L"]));
                            });


    test_report("rng", total_tests, fails);
}
