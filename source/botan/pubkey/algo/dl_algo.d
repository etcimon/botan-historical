/*
* DL Scheme
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.pubkey.algo.dl_algo;

public import botan.pubkey.algo.dl_group;
import botan.pubkey.x509_key;
import botan.pubkey.pkcs8;
import botan.math.numbertheory.numthry;
import botan.pubkey.workfactor;
import botan.rng.rng;
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
		if (m_check_key) {
			auto tmp = m_check_key;
			m_check_key = null;
			scope(exit) m_check_key = tmp;
			return m_check_key(rng, strong);
		}
        if (m_y < 2 || m_y >= groupP())
            return false;
        if (!m_group.verifyGroup(rng, strong))
            return false;
        return true;
    }

	final override size_t messageParts() const {
		return m_msg_parts;
	}

	final override size_t maxInputBits() const {
		return m_max_input_bits;
	}

	final size_t messagePartSize() const { 
		if (m_msg_part_size) return m_msg_part_size(); 
		return groupQ().bytes(); 
	}

    final AlgorithmIdentifier algorithmIdentifier() const
    {
        return AlgorithmIdentifier(getOid(), m_group.DER_encode(m_format));
    }

    final Vector!ubyte x509SubjectPublicKey() const
    {
        return DEREncoder().encode(m_y).getContentsUnlocked();
    }

    /**
    * Get the DL domain parameters of this key.
    * @return DL domain parameters of this key
    */
    final ref DLGroup getDomain() const { return m_group; }

    /**
    * Get the public value m_y with m_y = g^m_x mod p where m_x is the secret key.
    */
    final BigInt getY() const { return m_y; }

    /**
    * Get the prime p of the underlying DL m_group.
    * @return prime p
    */
    final BigInt groupP() const { return m_group.getP(); }

    /**
    * Get the prime q of the underlying DL m_group.
    * @return prime q
    */
    final BigInt groupQ() const { return m_group.getQ(); }

    /**
    * Get the generator g of the underlying DL m_group.
    * @return generator g
    */
    final BigInt groupG() const { return m_group.getG(); }

    override final size_t estimatedStrength() const
    {
        return dlWorkFactor(m_group.getP().bits());
    }

	this(in AlgorithmIdentifier alg_id, 
	     in SecureVector!ubyte key_bits, 
	     in DLGroup.Format format,
	     in string algo_name,
	     in short msg_parts = 0,
	     in bool delegate(RandomNumberGenerator, bool) const check_key = null,
	     in size_t delegate() const max_input_bits = null,
	     in size_t delegate() const msg_part_size = null)
	{
		m_format = format;
		m_algo_name = algo_name;
		m_msg_parts = msg_parts;
		m_max_input_bits = max_input_bits;
		m_msg_part_size = msg_part_size;
		m_check_key = check_key;
		m_group.BER_decode(alg_id.parameters, format);
		
		BERDecoder(key_bits).decode(m_y);
	}

	this(DLGroup grp, BigInt y1,
	     in DLGroup.Format format,
	     in string algo_name,
	     in short msg_parts = 0,
	     in bool delegate(RandomNumberGenerator, bool) const check_key = null,
	     in size_t delegate() const max_input_bits = null,
	     in size_t delegate() const msg_part_size = null)
	{
		m_format = format;
		m_algo_name = algo_name;
		m_msg_parts = msg_parts;
		m_max_input_bits = max_input_bits;
		m_msg_part_size = msg_part_size;
		m_check_key = check_key;
		m_group = grp;
		m_y = y1;
	}

package:
    /**
    * The DL public key
    */
    BigInt m_y;

    /**
    * The DL group
    */
    DLGroup m_group;

	const DLGroup.Format m_format;
	const string m_algo_name;
	const short m_msg_parts;
	const size_t delegate() const m_max_input_bits;
	const size_t delegate() const m_msg_part_size;
	bool delegate(RandomNumberGenerator, bool) const m_check_key;
}

/**
* This class represents discrete logarithm (DL) private keys.
*/
final class DLSchemePrivateKey : DLSchemePublicKey, PrivateKey
{
public:

	override bool checkKey(RandomNumberGenerator rng, bool strong) const
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
	     DLGroup.Format format,
	     in string algo_name,
	     in short msg_parts = 0,
	     in bool delegate(RandomNumberGenerator, bool) const check_key = null,
	     in size_t delegate() const max_input_bits = null,
	     in size_t delegate() const msg_part_size = null)
    {
		m_format = format;
		m_algo_name = algo_name;
		m_msg_parts = msg_parts;
		m_max_input_bits = max_input_bits;
		m_msg_part_size = msg_part_size;
		m_check_key = check_key;
        m_group.BER_decode(alg_id.parameters, format);
        
        BERDecoder(key_bits).decode(m_x);
    }

	this(DLGroup grp, BigInt y1, BigInt x_arg,
	     in DLGroup.Format format,
	     in string algo_name,
	     in short msg_parts = 0,
	     in bool delegate(RandomNumberGenerator, bool) const check_key = null,
	     in size_t delegate() const max_input_bits = null,
	     in size_t delegate() const msg_part_size = null)
	{
		m_format = format;
		m_algo_name = algo_name;
		m_msg_parts = msg_parts;
		m_max_input_bits = max_input_bits;
		m_msg_part_size = msg_part_size;
		m_check_key = check_key;
		m_group = grp;
		m_y = y1;
		m_x = x_arg;
	}

package:
    /**
    * The DL private key
    */
    BigInt m_x;
}