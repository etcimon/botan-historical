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
static if (BOTAN_HAS_ECDH || BOTAN_HAS_ECDSA || BOTAN_HAS_GOST_34_10_2001):

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
import botan.utils.memory.zeroize;
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
    this(in ECGroup dom_par, in PointGFp pub_point) 
    {
        m_domain_params = dom_par;
        m_public_key = pub_point;
        m_domain_encoding = EC_DOMPAR_ENC_EXPLICIT;
        if (domain().getCurve() != public_point().getCurve())
            throw new InvalidArgument("ECPublicKey: curve mismatch in constructor");
    }

    this(in AlgorithmIdentifier alg_id, in SecureVector!ubyte key_bits)
    {
        m_domain_params = ECGroup(alg_id.parameters);
        m_domain_encoding = EC_DOMPAR_ENC_EXPLICIT;
        
        m_public_key = OS2ECP(key_bits, domain().getCurve());
    }

    /**
    * Get the public point of this key.
    * @throw new Invalid_State is thrown if the
    * domain parameters of this point are not set
    * @result the public point of this key
    */
    ref PointGFp publicPoint() const { return m_public_key; }

    AlgorithmIdentifier algorithmIdentifier() const
    {
        return AlgorithmIdentifier(get_oid(), DER_domain());
    }

    Vector!ubyte x509SubjectPublicKey() const
    {
        return unlock(EC2OSP(public_point(), PointGFp.COMPRESSED));
    }

    bool checkKey(RandomNumberGenerator, bool) const
    {
        return public_point().onTheCurve();
    }

    /**
    * Get the domain parameters of this key.
    * @throw new Invalid_State is thrown if the
    * domain parameters of this point are not set
    * @result the domain parameters of this key
    */
    ECGroup domain() const { return m_domain_params; }

    /**
    * Set the domain parameter encoding to be used when encoding this key.
    * @param enc = the encoding to use
    */
    void setParameterEncoding(ECGroupEncoding form)
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
    Vector!ubyte dERDomain() const
    { return domain().dEREncode(domain_format()); }

    /**
    * Get the domain parameter encoding to be used when encoding this key.
    * @result the encoding to use
    */
    ECGroupEncoding domainFormat() const
    { return m_domain_encoding; }

    override size_t estimatedStrength() const
    {
        return domain().getCurve().getP().bits() / 2;
    }


protected:
    this() 
    {        m_public_key = pub_point;
        
        m_domain_encoding = EC_DOMPAR_ENC_EXPLICIT;
    }

    ECGroup m_domain_params;
    PointGFp m_public_key;
    EC_Group_Encoding m_domain_encoding;
}

/**
* This abstract class represents ECC private keys
*/
final class ECPrivateKey : ECPublicKey,
                            PrivateKey
{
public:
    /**
    * ECPrivateKey constructor
    */
    this(RandomNumberGenerator rng, in ECGroup ec_group, in BigInt private_key)
    {
        m_domain_params = ec_group;
        m_domain_encoding = EC_DOMPAR_ENC_EXPLICIT;
        
        if (private_key == 0)
            m_private_key = BigInt.randomInteger(rng, 1, domain().getOrder());
        else
            m_private_key = private_key;
        
        m_public_key = domain().getBasePoint() * m_private_key;
        
        assert(m_public_key.onTheCurve(), "Generated public key point was on the curve");
    }

    this(in AlgorithmIdentifier alg_id, in SecureVector!ubyte key_bits)
    {
        m_domain_params = ECGroup(alg_id.parameters);
        m_domain_encoding = EC_DOMPAR_ENC_EXPLICIT;
        
        OID key_parameters;
        SecureVector!ubyte public_key_bits;
        
        BERDecoder(key_bits)
                .startCons(ASN1Tag.SEQUENCE)
                .decode_and_check!size_t(1, "Unknown version code for ECC key")
                .decodeOctetStringBigint(m_private_key)
                .decodeOptional(key_parameters, ASN1Tag(0), ASN1Tag.PRIVATE)
                .decodeOptionalString(public_key_bits, ASN1Tag.BIT_STRING, 1, ASN1Tag.PRIVATE)
                .endCons();
        
        if (!key_parameters.empty && key_parameters != alg_id.oid)
            throw new DecodingError("ECPrivateKey - inner and outer OIDs did not match");
        
        if (public_key_bits.empty)
        {
            m_public_key = domain().getBasePoint() * m_private_key;
            
            assert(m_public_key.onTheCurve(), "Public point derived from loaded key was on the curve");
        }
        else
        {
            public_key = OS2ECP(public_key_bits, domain().getCurve());
            // OS2ECP verifies that the point is on the curve
        }
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

    /**
    * Get the private key value of this key object.
    * @result the private key value of this key object
    */
    BigInt privateValue() const
    {
        if (m_private_key == 0)
            throw new InvalidState("ECPrivateKey::private_value - uninitialized");
        
        return m_private_key;
    }
protected:
    this() {}

    BigInt m_private_key;
}