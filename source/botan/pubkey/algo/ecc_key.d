/*
* ECDSA
* (C) 2007 Falko Strenzke, FlexSecure GmbH
*             Manuel Hartl, FlexSecure GmbH
* (C) 2008-2010 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.pubkey.algo.ecc_key;

import botan.constants;
static if (BOTAN_HAS_PUBLIC_KEY_CRYPTO && (BOTAN_HAS_ECDH || BOTAN_HAS_ECDSA || BOTAN_HAS_GOST_34_10_2001)):

public import botan.pubkey.pubkey;
public import botan.math.ec_gfp.ec_group;
public import botan.math.numbertheory.numthry;
public import botan.math.ec_gfp.curve_gfp;
public import botan.math.ec_gfp.point_gfp;
public import botan.pubkey.pk_keys;
public import botan.pubkey.x509_key;
import botan.rng.rng;
import botan.pubkey.pkcs8;
import botan.asn1.der_enc;
import botan.asn1.ber_dec;
import memutils.vector;
import botan.utils.mem_ops;
import botan.utils.exceptn;

/**
* This class represents abstract ECC public keys. When encoding a key
* via an encoder that can be accessed via the corresponding member
* functions, the key will decide upon its internally stored encoding
* information whether to encode itself with or without domain
* parameters, or using the domain parameter oid. Furthermore, a public
* key without domain parameters can be decoded. In that case, it
* cannot be used for verification until its domain parameters are set
* by calling the corresponding member function.
*/
class ECPublicKey : PublicKey
{
public:
    this(const ref ECGroup dom_par, 
		 const ref PointGFp pub_point, 
         in string algo_name, 
         in bool msg_compat, 
         in short msg_parts = 1) 
    {
        m_check_key = null;
        m_algorithm_identifier = null;
        m_subject_public_key = null;
        m_msg_compat = msg_compat;
        m_algo_name = algo_name;
        m_msg_parts = msg_parts;
        m_domain_params = dom_par.dup;
        m_public_key = pub_point.dup;
        m_domain_encoding = EC_DOMPAR_ENC_EXPLICIT;
        if (domain().getCurve() != publicPoint().getCurve())
            throw new InvalidArgument("ECPublicKey: curve mismatch in constructor");
    }

    this(in AlgorithmIdentifier alg_id, 
         const ref SecureVector!ubyte key_bits, 
         in string algo_name, in bool msg_compat, in short msg_parts = 1) 
    {
        m_check_key = null;
        m_algorithm_identifier = null;
        m_subject_public_key = null;
        m_msg_compat = msg_compat;
        m_algo_name = algo_name;
        m_msg_parts = msg_parts;
        m_domain_params = ECGroup(alg_id.parameters);
        m_domain_encoding = EC_DOMPAR_ENC_EXPLICIT;
        
        m_public_key = OS2ECP(key_bits, domain().getCurve());
    }

    final void setCB(in bool delegate(RandomNumberGenerator, bool) const check_key = null,
                     in Vector!ubyte delegate() const subject_public_key = null,
                     in AlgorithmIdentifier delegate() const algorithm_identifier = null) {
        m_check_key = check_key;
        m_algorithm_identifier = algorithm_identifier;
        m_subject_public_key = subject_public_key;
    }

    /// Used for object casting to the right type in the factory.
    final override @property string algoName() const {
        return m_algo_name;
    }

    /**
    * Get the public point of this key.
    * @throw new InvalidState is thrown if the
    * domain parameters of this point are not set
    * @result the public point of this key
    */
    final ref const(PointGFp) publicPoint() const { return m_public_key; }

    final override size_t maxInputBits() const { return domain().getOrder().bits(); }

    final override size_t messagePartSize() const { if (!m_msg_compat) return 0; return domain().getOrder().bytes(); }

    final override size_t messageParts() const { return m_msg_parts; }

    final override AlgorithmIdentifier algorithmIdentifier() const
    {
        if (m_algorithm_identifier)
            return m_algorithm_identifier();
        return AlgorithmIdentifier(getOid(), DER_domain());
    }

    final override Vector!ubyte x509SubjectPublicKey() const
    {
        if (m_subject_public_key)
            return m_subject_public_key();
        return unlock(EC2OSP(publicPoint(), PointGFp.COMPRESSED));
    }

    final override bool checkKey(RandomNumberGenerator rng, bool b) const
    {
        if (m_check_key) {
            return m_check_key(rng, b);
        }
        return publicPoint().onTheCurve();
    }

    /**
    * Get the domain parameters of this key.
    * @throw new InvalidState is thrown if the
    * domain parameters of this point are not set
    * @result the domain parameters of this key
    */
    final ref const(ECGroup) domain() const { return m_domain_params; }

    /**
    * Set the domain parameter encoding to be used when encoding this key.
    * @param enc = the encoding to use
    */
    final void setParameterEncoding(ECGroupEncoding form)
    {
        if (form != EC_DOMPAR_ENC_EXPLICIT && form != EC_DOMPAR_ENC_IMPLICITCA && form != EC_DOMPAR_ENC_OID)
            throw new InvalidArgument("Invalid encoding form for EC-key object specified");
        
        if ((form == EC_DOMPAR_ENC_OID) && (m_domain_params.getOid() == ""))
            throw new InvalidArgument("Invalid encoding form OID specified for "
                                       ~ "EC-key object whose corresponding domain "
                                       ~ "parameters are without oid");
        
        m_domain_encoding = form;
    }

    /**
    * Return the DER encoding of this keys domain in whatever format
    * is preset for this particular key
    */
    Vector!ubyte DER_domain() const { return domain().DER_encode(domainFormat()); }

    /**
    * Get the domain parameter encoding to be used when encoding this key.
    * @result the encoding to use
    */
    ECGroupEncoding domainFormat() const { return m_domain_encoding; }

    override size_t estimatedStrength() const
    {
        return domain().getCurve().getP().bits() / 2;
    }

    /**
    * @return public point value
    */
    Vector!ubyte publicValue() const
    { return unlock(EC2OSP(publicPoint(), PointGFp.UNCOMPRESSED)); }
protected:

    ECGroup m_domain_params;
    PointGFp m_public_key;
    ECGroupEncoding m_domain_encoding;

    const string m_algo_name;
    const bool m_msg_compat;
    const short m_msg_parts;

    bool delegate(RandomNumberGenerator, bool) const m_check_key;
    Vector!ubyte delegate() const m_subject_public_key;
    AlgorithmIdentifier delegate() const m_algorithm_identifier;
}

/**
* This abstract class represents ECC private keys
*/
final class ECPrivateKey : ECPublicKey, PrivateKey, PKKeyAgreementKey
{
public:
    /**
    * ECPrivateKey constructor
    */
    this(RandomNumberGenerator rng, const ref ECGroup ec_group, const ref BigInt private_key, 
         in string algo_name, in bool msg_compat, in short msg_parts = 1) 
    {        
		if (private_key == 0) {
			auto bi = BigInt(1);
			m_private_key = BigInt.randomInteger(rng, bi, ec_group.getOrder());
		}
        else
            m_private_key = private_key.dup;

        PointGFp public_key = ec_group.getBasePoint() * m_private_key;
        
        assert(public_key.onTheCurve(), "Generated public key point was on the curve");

		logDebug("private key: ", m_private_key.toString());
        super(ec_group, public_key, algo_name, msg_compat, msg_parts);
    }

    this(in AlgorithmIdentifier alg_id, const ref SecureVector!ubyte key_bits, 
         in string algo_name, in bool msg_compat, in short msg_parts = 1) 
    {
        PointGFp public_key;
        OID key_parameters;
        SecureVector!ubyte public_key_bits;
        
        BERDecoder(key_bits)
                .startCons(ASN1Tag.SEQUENCE)
                .decodeAndCheck!size_t(1, "Unknown version code for ECC key")
                .decodeOctetStringBigint(m_private_key)
                .decodeOptional(key_parameters, (cast(ASN1Tag) 0), ASN1Tag.PRIVATE)
                .decodeOptionalString(public_key_bits, ASN1Tag.BIT_STRING, 1, ASN1Tag.PRIVATE)
                .endCons();
        
        if (!key_parameters.empty && key_parameters != alg_id.oid)
            throw new DecodingError("ECPrivateKey - inner and outer OIDs did not match");
        
        if (public_key_bits.empty)
        {
            public_key = domain().getBasePoint() * m_private_key;
            
            assert(public_key.onTheCurve(), "Public point derived from loaded key was on the curve");
        }
        else
        {
            public_key = OS2ECP(public_key_bits, ECGroup(alg_id.parameters).getCurve());
            // OS2ECP verifies that the point is on the curve
        }

		ECGroup ec = ECGroup(alg_id.parameters);
        super(ec, public_key, algo_name, msg_compat, msg_parts);
    }

    SecureVector!ubyte pkcs8PrivateKey() const
    {
        return DEREncoder()
                .startCons(ASN1Tag.SEQUENCE)
                .encode(cast(size_t)(1))
                .encode(BigInt.encode1363(m_private_key, m_private_key.bytes()),
                        ASN1Tag.OCTET_STRING)
                .endCons()
                .getContents();
    }

    override AlgorithmIdentifier pkcs8AlgorithmIdentifier() const { return super.algorithmIdentifier(); }

    /**
    * Get the private key value of this key object.
    * @result the private key value of this key object
    */
    ref const(BigInt) privateValue() const
    {
        if (m_private_key == 0)
            throw new InvalidState("ECPrivateKey.private_value - uninitialized");
        
        return m_private_key;
    }

    override Vector!ubyte publicValue() const { return super.publicValue(); }

private:

    BigInt m_private_key;
}