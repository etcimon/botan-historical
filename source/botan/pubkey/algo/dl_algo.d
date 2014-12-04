/*
* DL Scheme
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.pubkey.algo.dl_algo;

import botan.pubkey.algo.dl_group;
import botan.pubkey.x509_key;
import botan.pubkey.pkcs8;
import botan.math.numbertheory.numthry;
import botan.pubkey.workfactor;
import botan.asn1.der_enc;
import botan.asn1.ber_dec;

/**
* This class represents discrete logarithm (DL) public keys.
*/
class DLSchemePublicKey : PublicKey
{
public:
    bool checkKey(RandomNumberGenerator rng, bool strong) const
    {
        if (m_y < 2 || m_y >= groupP())
            return false;
        if (!m_group.verifyGroup(rng, strong))
            return false;
        return true;
    }

    AlgorithmIdentifier algorithmIdentifier() const
    {
        return AlgorithmIdentifier(getOid(), m_group.DER_encode(groupFormat()));
    }

    Vector!ubyte x509SubjectPublicKey() const
    {
        return DEREncoder().encode(m_y).getContentsUnlocked();
    }

    /**
    * Get the DL domain parameters of this key.
    * @return DL domain parameters of this key
    */
    ref DLGroup getDomain() const { return m_group; }

    /**
    * Get the public value m_y with m_y = g^m_x mod p where m_x is the secret key.
    */
    BigInt getY() const { return m_y; }

    /**
    * Get the prime p of the underlying DL m_group.
    * @return prime p
    */
    BigInt groupP() const { return m_group.getP(); }

    /**
    * Get the prime q of the underlying DL m_group.
    * @return prime q
    */
    BigInt groupQ() const { return m_group.getQ(); }

    /**
    * Get the generator g of the underlying DL m_group.
    * @return generator g
    */
    BigInt groupG() const { return m_group.getG(); }

    /**
    * Get the underlying groups encoding format.
    * @return encoding format
    */
    abstract DLGroup.Format groupFormat() const;

    override size_t estimatedStrength() const
    {
        return dlWorkFactor(m_group.getP().bits());
    }

    this(in AlgorithmIdentifier alg_id,
         in SecureVector!ubyte key_bits,
         DLGroup.Format format)
    {
        m_group.BER_decode(alg_id.parameters, format);
        
        BERDecoder(key_bits).decode(m_y);
    }

protected:
    this() {}

    /**
    * The DL public key
    */
    BigInt m_y;

    /**
    * The DL m_group
    */
    DLGroup m_group;
}

/**
* This class represents discrete logarithm (DL) private keys.
*/
class DLSchemePrivateKey : DLSchemePublicKey, PrivateKey
{
public:

    bool checkKey(RandomNumberGenerator rng,
                  bool strong) const
    {
        const BigInt p = groupP();
        const BigInt g = groupG();
        
        if (m_y < 2 || m_y >= p || m_x < 2 || m_x >= p)
            return false;
        if (!m_group.verifyGroup(rng, strong))
            return false;
        
        if (!strong)
            return true;
        
        if (m_y != powerMod(g, m_x, p))
            return false;
        
        return true;
    }

    /**
    * Get the secret key m_x.
    * @return secret key
    */
    BigInt getX() const { return m_x; }

    SecureVector!ubyte pkcs8PrivateKey() const
    {
        return DEREncoder().encode(m_x).getContents();
    }

    this(in AlgorithmIdentifier alg_id,
         in SecureVector!ubyte key_bits,
         DLGroup.Format format)
    {
        m_group.BER_decode(alg_id.parameters, format);
        
        BERDecoder(key_bits).decode(m_x);
    }

protected:
    this() {}

    /**
    * The DL private key
    */
    BigInt m_x;
}