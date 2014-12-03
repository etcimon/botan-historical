/*
* Interface for AEAD modes
* (C) 2013 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.modes.aead.aead;
import botan.modes.cipher_mode;
import botan.block.block_cipher;
import botan.libstate.libstate;

static if (BOTAN_HAS_AEAD_CCM) import botan.modes.aead.ccm;
static if (BOTAN_HAS_AEAD_EAX) import botan.modes.aead.eax;
static if (BOTAN_HAS_AEAD_GCM) import botan.modes.aead.gcm;
static if (BOTAN_HAS_AEAD_SIV) import botan.modes.aead.siv;
static if (BOTAN_HAS_AEAD_OCB) import botan.modes.aead.ocb;

/**
* Interface for AEAD (Authenticated Encryption with Associated Data)
* modes. These modes provide both encryption and message
* authentication, and can authenticate additional per-message data
* which is not included in the ciphertext (for instance a sequence
* number).
*/
class AEADMode : Cipher_Mode
{
public:
    final override bool authenticated() const { return true; }

    /**
    * Set associated data that is not included in the ciphertext but
    * that should be authenticated. Must be called after setKey
    * and before finish.
    *
    * Unless reset by another call, the associated data is kept
    * between messages. Thus, if the AD does not change, calling
    * once (after setKey) is the optimum.
    *
    * @param ad = the associated data
    * @param ad_len = length of add in bytes
    */
    abstract void setAssociatedData(in ubyte* ad, size_t ad_len);

    final void setAssociatedDataVec(Alloc)(in Vector!( ubyte, Alloc ) ad)
    {
        setAssociatedData(ad.ptr, ad.length);
    }

    /**
    * Default AEAD nonce size (a commonly supported value among AEAD
    * modes, and large enough that random collisions are unlikely).
    */
    final override size_t defaultNonceLength() const { return 12; }

    /**
    * Return the size of the authentication tag used (in bytes)
    */
    abstract size_t tagSize() const;
}

/**
* Get an AEAD mode by name (eg "AES-128/GCM" or "Serpent/EAX")
*/
AEADMode getAead(in string algo_spec, CipherDir direction)
{
    AlgorithmFactory af = globalState().algorithmFactory();
    
    const Vector!string algo_parts = splitter(algo_spec, '/');
    if (algo_parts.empty)
        throw new InvalidAlgorithmName(algo_spec);
    
    if (algo_parts.length < 2)
        return null;
    
    const string cipher_name = algo_parts[0];
    const BlockCipher cipher = af.prototypeBlockCipher(cipher_name);
    if (!cipher)
        return null;
    
    const Vector!string mode_info = parse_algorithm_name(algo_parts[1]);
    
    if (mode_info.empty)
        return null;
    
    const string mode_name = mode_info[0];
    
    const size_t tag_size = (mode_info.length > 1) ? to!uint(mode_info[1]) : cipher.block_size;
    
    static if (BOTAN_HAS_AEAD_CCM) {
        if (mode_name == "CCM-8")
        {
            if (direction == ENCRYPTION)
                return new CCMEncryption(cipher.clone(), 8, 3);
            else
                return new CCMDecryption(cipher.clone(), 8, 3);
        }
        
        if (mode_name == "CCM" || mode_name == "CCM-8")
        {
            const size_t L = (mode_info.length > 2) ? to!uint(mode_info[2]) : 3;
            
            if (direction == ENCRYPTION)
                return new CCMEncryption(cipher.clone(), tag_size, L);
            else
                return new CCMDecryption(cipher.clone(), tag_size, L);
        }
    }
    
    static if (BOTAN_HAS_AEAD_EAX) {
        if (mode_name == "EAX")
        {
            if (direction == ENCRYPTION)
                return new EAXEncryption(cipher.clone(), tag_size);
            else
                return new EAXDecryption(cipher.clone(), tag_size);
        }
    }
    
    static if (BOTAN_HAS_AEAD_SIV) {
        if (mode_name == "SIV")
        {
            assert(tag_size == 16, "Valid tag size for SIV");
            if (direction == ENCRYPTION)
                return new SIVEncryption(cipher.clone());
            else
                return new SIVDecryption(cipher.clone());
        }
    }
    
    static if (BOTAN_HAS_AEAD_GCM) {
        if (mode_name == "GCM")
        {
            if (direction == ENCRYPTION)
                return new GCMEncryption(cipher.clone(), tag_size);
            else
                return new GCMDecryption(cipher.clone(), tag_size);
        }
    }

    static if (BOTAN_HAS_AEAD_OCB) {
        if (mode_name == "OCB")
        {
            if (direction == ENCRYPTION)
                return new OCBEncryption(cipher.clone(), tag_size);
            else
                return new OCBDecryption(cipher.clone(), tag_size);
        }
    }
    
    return null;
}

static if (BOTAN_TEST):

import botan.test;
import botan.codec.hex;
import core.atomic;
size_t total_tests;

size_t aeadTest(string algo, string input, string expected, string nonce_hex, string ad_hex, string key_hex)
{
    atomicOp!"+="(total_tests, 5);
    const auto nonce = hexDecodeLocked(nonce_hex);
    const auto ad = hexDecodeLocked(ad_hex);
    const auto key = hexDecodeLocked(key_hex);
    
    Unique!Cipher_Mode enc = get_aead(algo, ENCRYPTION);
    Unique!Cipher_Mode dec = get_aead(algo, DECRYPTION);
    
    if (!enc || !dec)
        throw new Exception("Unknown AEAD " ~ algo);
    
    enc.setKey(key);
    dec.setKey(key);
    
    if (auto aead_enc = cast(AEADMode)(*enc))
        aead_enc.setAssociatedDataVec(ad);
    if (auto aead_dec = cast(AEADMode)(*dec))
        aead_dec.setAssociatedDataVec(ad);
    
    size_t fail = 0;
    
    const auto pt = hexDecodeLocked(input);
    const auto expected_ct = hexDecodeLocked(expected);
    
    auto vec = pt;
    enc.startVec(nonce);
    // should first update if possible
    enc.finish(vec);
    
    if (vec != expected_ct)
    {
        writeln(algo ~ " got ct " ~ hexEncode(vec) ~ " expected " ~ expected);
        writeln(algo ~ " \n");
        ++fail;
    }
    
    vec = expected_ct;
    
    dec.startVec(nonce);
    dec.finish(vec);
    
    if (vec != pt)
    {
        writeln(algo ~ " got pt " ~ hexEncode(vec) ~ " expected " ~ input);
        ++fail;
    }
    
    if (enc.authenticated())
    {
        vec = expected_ct;
        vec[0] ^= 1;
        dec.startVec(nonce);
        try
        {
            dec.finish(vec);
            writeln(algo ~ " accepted message with modified message");
            ++fail;
        }
        catch (Throwable) {}
        
        if (nonce.length)
        {
            auto bad_nonce = nonce;
            bad_nonce[0] ^= 1;
            vec = expected_ct;
            
            dec.startVec(bad_nonce);
            
            try
            {
                dec.finish(vec);
                writeln(algo ~ " accepted message with modified nonce");
                ++fail;
            }
            catch (Throwable) {}
        }
        
        if (auto aead_dec = cast(AEADMode)(*dec))
        {
            auto bad_ad = ad;
            
            if (ad.length)
                bad_ad[0] ^= 1;
            else
                bad_ad.pushBack(0);
            
            aead_dec.setAssociatedDataVec(bad_ad);
            
            vec = expected_ct;
            dec.startVec(nonce);
            
            try
            {
                dec.finish(vec);
                writeln(algo ~ " accepted message with modified AD");
                ++fail;
            }
            catch (Throwable) {}
        }
    }
    
    return fail;
}

unittest
{
    auto test = (string input)
    {
        File vec = File(input, "r");
        
        return runTestsBb(vec, "AEAD", "Out", true,
                            (string[string] m)
                            {
            return aeadTest(m["AEAD"], m["In"], m["Out"],
            m["Nonce"], m["AD"], m["Key"]);
        });
    };
    
    size_t fails = runTestsInDir("test_data/aead", test);

    testReport("aead", total_tests, fails);
}
