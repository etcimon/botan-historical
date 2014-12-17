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

    this(in AlgorithmIdentifier, in SecureVector!ubyte key_bits, bool delegate(RandomNumberGenerator, bool) const check_key = null)
    {
        m_check_key = check_key;
        BERDecoder(key_bits)
                .startCons(ASN1Tag.SEQUENCE)
                .decode(m_n)
                .decode(m_e)
                .verifyEnd()
                .endCons();
    }

    this(in BigInt n, in BigInt e, bool delegate(RandomNumberGenerator, bool) const check_key = null)
    {
        m_check_key = check_key;
        m_n = n;
        m_e = e; 
    }

    /*
    * Check IF Scheme Public Parameters
    */
    override bool checkKey(RandomNumberGenerator rng, bool b) const
    {
        if (m_check_key) {
            auto tmp = m_check_key;
            m_check_key = null;
            scope(exit) m_check_key = tmp;
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
    final BigInt getN() const { return m_n; }

    /**
    * @return public exponent
    */
    final BigInt getE() const { return m_e; }

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

package:

    BigInt m_n, m_e;

    bool delegate(RandomNumberGenerator, bool) const m_check_key;
}

/**
* This class represents public keys
* of integer factorization based (IF) public key schemes.
*/
final class IFSchemePrivateKey : IFSchemePublicKey, PrivateKey
{
public:
    this(RandomNumberGenerator rng, in AlgorithmIdentifier, in SecureVector!ubyte key_bits,
         bool delegate(RandomNumberGenerator, bool) const check_key = null)
    {
        m_check_key = check_key;
        BERDecoder(key_bits)
                .startCons(ASN1Tag.SEQUENCE)
                .decodeAndCheck!size_t(0, "Unknown PKCS #1 key format version")
                .decode(m_n)
                .decode(m_e)
                .decode(m_d)
                .decode(m_p)
                .decode(m_q)
                .decode(m_d1)
                .decode(m_d2)
                .decode(m_c)
                .endCons();
        
        loadCheck(rng);
    }

    this(RandomNumberGenerator rng,
         in BigInt prime1,
         in BigInt prime2,
         in BigInt exp,
         in BigInt d_exp,
         in BigInt mod, 
         bool delegate(RandomNumberGenerator, bool) const check_key = null)
    {
        m_check_key = check_key;
        m_p = prime1;
        m_q = prime2;
        e = exp;
        m_d = d_exp;
        n = mod.isNonzero() ? mod : m_p * m_q;
        
        if (m_d == 0)
        {
            BigInt inv_for_d = lcm(m_p - 1, m_q - 1);
            if (e.isEven())
                inv_for_d >>= 1;
            
            m_d = inverseMod(e, inv_for_d);
        }
        
        m_d1 = m_d % (m_p - 1);
        m_d2 = m_d % (m_q - 1);
        m_c = inverseMod(m_q, m_p);

        loadCheck(rng);

    }

    /*
    * Check IF Scheme Private Parameters
    */
    override bool checkKey(RandomNumberGenerator rng, bool strong) const
    {
        if (m_check_key) {
            auto tmp = m_check_key;
            m_check_key = null;
            scope(exit) m_check_key = tmp;
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
    BigInt getP() const { return m_p; }

    /**
    * Get the second prime q.
    * @return prime q
    */
    BigInt getQ() const { return m_q; }

    /**
    * Get d with exp * d = 1 mod (p - 1, q - 1).
    * @return d
    */
    BigInt getD() const { return m_d; }

    BigInt getC() const { return m_c; }
    BigInt getD1() const { return m_d1; }
    BigInt getD2() const { return m_d2; }

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

package:
    this(bool delegate(RandomNumberGenerator, bool) const check_key = null)
    {
        m_check_key = check_key;
    }
    BigInt m_d, m_p, m_q, m_d1, m_d2, m_c;
}