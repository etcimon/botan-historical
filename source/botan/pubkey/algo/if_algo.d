/*
* IF Scheme
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.pubkey.algo.if_algo;

import botan.constants;
static if (BOTAN_HAS_PUBLIC_KEY_CRYPTO):

public import botan.pubkey.pubkey;
import botan.math.bigint.bigint;
import botan.pubkey.x509_key;
import botan.pubkey.pkcs8;
import botan.math.numbertheory.numthry;
import botan.pubkey.workfactor;
import botan.asn1.der_enc;
import botan.asn1.ber_dec;

/**
* This class represents public keys
* of integer factorization based (IF) public key schemes.
*/
class IFSchemePublicKey : PublicKey
{
public:

    this(in AlgorithmIdentifier, in SecureVector!ubyte key_bits, 
         in string algo_name,
         bool delegate(RandomNumberGenerator, bool) const check_key = null)
    {
        m_check_key = check_key;
        BERDecoder(key_bits)
                .startCons(ASN1Tag.SEQUENCE)
                .decode(m_n)
                .decode(m_e)
                .verifyEnd()
                .endCons();
        m_algo_name = algo_name;
    }

    this(BigInt n, BigInt e, in string algo_name, 
         bool delegate(RandomNumberGenerator, bool) const check_key = null)
    {
        m_check_key = check_key;
        m_algo_name = algo_name;
        m_n = n;
        m_e = e; 
    }

    /// Used for object casting to the right type in the factory.
    final override @property string algoName() const {
        return m_algo_name;
    }

    /*
    * Check IF Scheme Public Parameters
    */
    override bool checkKey(RandomNumberGenerator rng, bool strong) const
    {
        if (m_check_key) {
            auto tmp = m_check_key;
            (cast(IFSchemePublicKey)this).m_check_key = null;
            scope(exit) (cast(IFSchemePublicKey)this).m_check_key = tmp;
            return m_check_key(rng, strong);
        }

        if (m_n < 35 || m_n.isEven() || m_e < 2)
            return false;
        return true;
    }


    final AlgorithmIdentifier algorithmIdentifier() const
    {
        return AlgorithmIdentifier(getOid(), AlgorithmIdentifierImpl.USE_NULL_PARAM);
    }

    final Vector!ubyte x509SubjectPublicKey() const
    {
        return DEREncoder()
                .startCons(ASN1Tag.SEQUENCE)
                .encode(m_n)
                .encode(m_e)
                .endCons()
                .getContentsUnlocked();
    }

    /**
    * @return public modulus
    */
    final const(BigInt) getN() const { return m_n; }

    /**
    * @return public exponent
    */
    final const(BigInt) getE() const { return m_e; }

    final size_t maxInputBits() const { return (m_n.bits() - 1); }

    final override size_t messagePartSize() const {
        return 0;
    }

    final override size_t messageParts() const {
        return 1;
    }

    override final size_t estimatedStrength() const
    {
        return dlWorkFactor(m_n.bits());
    }

protected:
    BigInt m_n, m_e;
    const string m_algo_name;

    bool delegate(RandomNumberGenerator, bool) const m_check_key;
}

/**
* This class represents public keys
* of integer factorization based (IF) public key schemes.
*/
final class IFSchemePrivateKey : IFSchemePublicKey, PrivateKey
{
public:
    this(RandomNumberGenerator rng, in AlgorithmIdentifier aid, in SecureVector!ubyte key_bits,
         in string algo_name, bool delegate(RandomNumberGenerator, bool) const check_key = null)
    {
        BigInt n, e;
        BERDecoder(key_bits)
                .startCons(ASN1Tag.SEQUENCE)
                .decodeAndCheck!size_t(0, "Unknown PKCS #1 key format version")
                .decode(n)
                .decode(e)
                .decode(m_d)
                .decode(m_p)
                .decode(m_q)
                .decode(m_d1)
                .decode(m_d2)
                .decode(m_c)
                .endCons();
        
        super(n, e, algo_name, check_key);

        loadCheck(rng);
    }

    this(RandomNumberGenerator rng,
         BigInt prime1,
         BigInt prime2,
         BigInt exp,
         BigInt d_exp,
         BigInt mod, 
         in string algo_name,
         bool delegate(RandomNumberGenerator, bool) const check_key = null)
    {
        BigInt e = exp;
        m_p = prime1;
        m_q = prime2;
        BigInt n = mod.isNonzero() ? mod : m_p * m_q;
        super(n, e, algo_name, check_key);

        m_d = d_exp;
        
        if (m_d == 0)
        {
            BigInt inv_for_d = lcm(m_p - 1, m_q - 1);
            if (m_e.isEven())
                inv_for_d >>= 1;
            
            m_d = inverseMod(m_e, inv_for_d);
        }
        
        m_d1 = m_d % (m_p - 1);
        m_d2 = m_d % (m_q - 1);
        m_c = inverseMod(m_q, m_p);

        loadCheck(rng);

    }

    override AlgorithmIdentifier pkcs8AlgorithmIdentifier() const { return super.algorithmIdentifier(); }

    /*
    * Check IF Scheme Private Parameters
    */
    override bool checkKey(RandomNumberGenerator rng, bool strong) const
    {
        if (m_check_key) {
            auto tmp = m_check_key;
            (cast(IFSchemePrivateKey)this).m_check_key = null;
            scope(exit) (cast(IFSchemePrivateKey)this).m_check_key = tmp;
            return m_check_key(rng, strong);
        }

        if (m_n < 35 || m_n.isEven() || m_e < 2 || m_d < 2 || m_p < 3 || m_q < 3 || m_p*m_q != m_n)
            return false;
        
        if (m_d1 != m_d % (m_p - 1) || m_d2 != m_d % (m_q - 1) || m_c != inverseMod(m_q, m_p))
            return false;
        
        const size_t prob = (strong) ? 56 : 12;
        
        if (!isPrime(m_p, rng, prob) || !isPrime(m_q, rng, prob))
            return false;
        return true;
    }

    /**
    * Get the first prime p.
    * @return prime p
    */
    const(BigInt) getP() const { return m_p; }

    /**
    * Get the second prime q.
    * @return prime q
    */
    const(BigInt) getQ() const { return m_q; }

    /**
    * Get d with exp * d = 1 mod (p - 1, q - 1).
    * @return d
    */
    const(BigInt) getD() const { return m_d; }

    const(BigInt) getC() const { return m_c; }
    const(BigInt) getD1() const { return m_d1; }
    const(BigInt) getD2() const { return m_d2; }

    SecureVector!ubyte pkcs8PrivateKey() const
    {
        return DEREncoder()
                .startCons(ASN1Tag.SEQUENCE)
                .encode(cast(size_t)(0))
                .encode(m_n)
                .encode(m_e)
                .encode(m_d)
                .encode(m_p)
                .encode(m_q)
                .encode(m_d1)
                .encode(m_d2)
                .encode(m_c)
                .endCons()
                .getContents();
    }

protected:
    BigInt m_d, m_p, m_q, m_d1, m_d2, m_c;
}