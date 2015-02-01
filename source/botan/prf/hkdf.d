/*
* HKDF
* (C) 2013 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.prf.hkdf;

import botan.constants;
static if (BOTAN_HAS_HKDF):

import botan.mac.mac;
import botan.hash.hash;
import botan.utils.types;
import botan.utils.mem_ops;

/**
* HKDF, see @rfc 5869 for details
*/
final class HKDF
{
public:
    this(MessageAuthenticationCode extractor,
          MessageAuthenticationCode prf) 
    {
        m_extractor = extractor;
        m_prf = prf;
    }

    this(MessageAuthenticationCode prf)
    {
        m_extractor = prf;
        m_prf = m_extractor.clone(); 
    }

    void startExtract(const(ubyte)* salt, size_t salt_len)
    {
        m_extractor.setKey(salt, salt_len);
    }

    void extract(const(ubyte)* input, size_t input_len)
    {
        m_extractor.update(input, input_len);
    }

    void finishExtract()
    {
        m_prf.setKey(m_extractor.finished());
    }


    /**
    * Only call after extract
    * @param output_len = must be less than 256*hashlen
    */
    void expand(ubyte* output, size_t output_len,
                const(ubyte)* info, size_t info_len)
    {
        if (output_len > m_prf.outputLength * 255)
            throw new InvalidArgument("HKDF requested output too large");
        
        ubyte counter = 1;
        
        SecureVector!ubyte T;
        
        while (output_len)
        {
            m_prf.update(T);
            m_prf.update(info, info_len);
            m_prf.update(counter++);
            T = m_prf.finished();
            
            const size_t to_write = std.algorithm.min(T.length, output_len);
            copyMem(output, T.ptr, to_write);
            output += to_write;
            output_len -= to_write;
        }
    }


    @property string name() const
    {
        return "HKDF(" ~ m_prf.name ~ ")";
    }

    void clear()
    {
        m_extractor.clear();
        m_prf.clear();
    }
private:
    Unique!MessageAuthenticationCode m_extractor;
    Unique!MessageAuthenticationCode m_prf;
}


static if (BOTAN_TEST):

import botan.test;
import botan.codec.hex;
import botan.libstate.libstate;
import memutils.hashmap;

private shared size_t total_tests;

SecureVector!ubyte hkdf()(string hkdf_algo,
                          auto const ref SecureVector!ubyte ikm,
						  auto const ref SecureVector!ubyte salt,
						  auto const ref SecureVector!ubyte info,
                          size_t L)
{
    AlgorithmFactory af = globalState().algorithmFactory();
    
    const string algo = hkdf_algo[5 .. hkdf_algo.length-6+5];
    
    const MessageAuthenticationCode mac_proto = af.prototypeMac("HMAC(" ~ algo ~ ")");
    
    if (!mac_proto)
        throw new InvalidArgument("Bad HKDF hash '" ~ algo ~ "'");
    
    HKDF hkdf = scoped!HKDF(mac_proto.clone(), mac_proto.clone());
    
    hkdf.startExtract(&salt[0], salt.length);
    hkdf.extract(&ikm[0], ikm.length);
    hkdf.finishExtract();
    
    SecureVector!ubyte key = SecureVector!ubyte(L);
    hkdf.expand(&key[0], key.length, &info[0], info.length);
    return key;
}

size_t hkdfTest(string algo, string ikm, string salt, string info, string okm, size_t L)
{
    import core.atomic;
    atomicOp!"+="(total_tests, 1);
    const string got = hexEncode(hkdf(algo, 
                                      hexDecodeLocked(ikm), 
                                      hexDecodeLocked(salt), 
                                      hexDecodeLocked(info),
                                      L));
    
    if (got != okm)
    {
        logTrace("HKDF got " ~ got ~ " expected " ~ okm);
        return 1;
    }
    
    return 0;
}

unittest
{
    logDebug("Testing hkdf.d ...");
    File vec = File("../test_data/hkdf.vec", "r");
    
    size_t fails = runTestsBb(vec, "HKDF", "OKM", true,
                                (ref HashMap!(string, string) m)
                                {
        return hkdfTest(m["HKDF"], m["IKM"], m["salt"], m["info"], m["OKM"], to!uint(m["L"]));
    });
    
    testReport("hkdf", total_tests, fails);
}
