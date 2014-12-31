module botan.rng.test;

import botan.constants;
static if (BOTAN_TEST):
import botan.libstate.libstate;
import botan.codec.hex;
import botan.rng.rng;
import core.atomic;

class FixedOutputRNG : RandomNumberGenerator
{
public:
    override bool isSeeded() const { return !buf.empty; }
    
    ubyte random()
    {
        if (!isSeeded())
            throw new Exception("Out of bytes");
        
        ubyte output = m_buf.front();
        m_buf.popFront();
        return output;
    }
    
    override void reseed(size_t) {}
    
    override void randomize(ubyte* output, size_t len)
    {
        for(size_t j = 0; j != len; j++)
            output[j] = random();
    }
    
    override void addEntropy(const(ubyte)* b, size_t s)
    {
        m_buf.insert(b[0 .. s]);
    }
    
    override @property string name() const { return "Fixed_Output_RNG"; }
    
    override void clear() {}
    
    this(in Vector!ubyte input)
    {
        m_buf.insert(input.ptr[0 .. input.length]);
    }
    
    this(string in_str)
    {
        Vector!ubyte input = hexDecode(in_str);
        m_buf.insert(input.ptr[0 .. input.length]);
    }
    
    this() {}
protected:
    size_t remaining() const { return m_buf.length; }
private:
    Vector!ubyte m_buf;
}

RandomNumberGenerator getRng(string algo_str, string ikm_hex)
{
    class AllOnceRNG : Fixed_Output_RNG
    {
    public:
        this(in Vector!ubyte input) {
            super(input);
        }
        
        SecureVector!ubyte randomVec(size_t)
        {
            SecureVector!ubyte vec = SecureVector!ubyte(this.remaining());
            this.randomize(&vec[0], vec.length);
            return vec;
        }
    }
    
    const auto ikm = hexDecode(ikm_hex);
    
    AlgorithmFactory af = globalState().algorithmFactory();
    
    const auto algo_name = parseAlgorithmName(algo_str);
    
    const string rng_name = algo_name[0];
    
    static if (BOTAN_HAS_HMAC_DRBG) {
        if (rng_name == "HMAC_DRBG")
            return new HMAC_DRBG(af.makeMac("HMAC(" ~ algo_name[1] ~ ")"), new AllOnceRNG(ikm));
    }
    
    static if (BOTAN_HAS_X931_RNG) {
        if (rng_name == "X9.31-RNG")
            return new ANSIX931RNG(af.makeBlockCipher(algo_name[1]), new FixedOutputRNG(ikm));
    }
    
    return null;
}


__gshared size_t total_tests;
static if (BOTAN_HAS_X931_RNG)
size_t x931Test(string algo,
                 string ikm,
                 string output,
                 size_t L)
{
    atomicOp!"+="(total_tests, 1);
    Unique!RandomNumberGenerator rng = getRng(algo, ikm);
    
    if (!rng)
        throw new Exception("Unknown RNG " ~ algo);
    
    const string got = hexEncode(rng.randomVec(L));
    
    if (got != output)
    {
        writeln("X9.31 " ~ got ~ " != " ~ output);
        return 1;
    }
    
    return 0;
}

static if (BOTAN_HAS_HMAC_DRBG)
size_t hmacDrbgTest(string[string] m)
{
    atomicOp!"+="(total_tests, 1);
    const string algo = m["RNG"];
    const string ikm = m["EntropyInput"];
    
    Unique!RandomNumberGenerator rng = getRng(algo, ikm);

    if (!rng)
        throw new Exception("Unknown RNG " ~ algo);
    
    rng.reseed(0); // force initialization
    
    // now reseed
    const auto reseed_input = hexDecode(m["EntropyInputReseed"]);
    rng.addEntropy(&reseed_input[0], reseed_input.length);
    
    const string output = m["Out"];
    
    const size_t out_len = output.length / 2;
    
    rng.randomVec(out_len); // gen 1st block (discarded)
    
    const string got = hexEncode(rng.randomVec(out_len));
    
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
    
    fails += runTestsBb(hmac_drbg_vec, "RNG", "Out", true, hmacDrbgTest);
    
    fails += runTestsBb(x931_vec, "RNG", "Out", true,
                          (string[string] m) {
                                return x931Test(m["RNG"], m["IKM"], m["Out"], to!uint(m["L"]));
                            });


    testReport("rng", total_tests, fails);
}
