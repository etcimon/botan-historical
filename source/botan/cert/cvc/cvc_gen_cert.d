/*
* EAC11 general CVC
* (C) 2008 Falko Strenzke
*      2008-2010 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.cert.cvc.cvc_gen_cert;

import botan.constants;
static if (BOTAN_HAS_CVC_CERTIFICATES):

import botan.cert.cvc.eac_obj;
import botan.cert.cvc.eac_asn_obj;
import botan.pubkey.algo.ecdsa;
import botan.pubkey.pubkey;
import botan.utils.types;

/**
*  This class represents TR03110 (EAC) v1.1 generalized CV Certificates
*/
class EAC11genCVC(Derived) : EAC11obj!Derived // CRTP continuation from EAC11obj
{
public:

    /**
    * Get this certificates public key.
    * @result this certificates public key
    */
    final PublicKey subjectPublicKey() const
    {
        return new ECDSAPublicKey(m_pk);
    }

    /**
    * Find out whether this object is self signed.
    * @result true if this object is self signed
    */
    final bool isSelfSigned() const
    {
        return self_signed;
    }


    /**
    * Get the CHR of the certificate.
    * @result the CHR of the certificate
    */
    final ASN1Chr getChr() const {
        return m_chr;
    }

    /**
    * Put the DER encoded version of this object into a pipe. PEM
    * is not supported.
    * @param output = the pipe to push the DER encoded version into
    * @param encoding = the encoding to use. Must be DER.
    */
    final void encode(Pipe output, X509Encoding encoding) const
    {
        Vector!ubyte concat_sig = EAC11obj!Derived.m_sig.get_concatenation();
        Vector!ubyte der = DEREncoder()
                .startCons(ASN1Tag(33), ASN1Tag.APPLICATION)
                .startCons(ASN1Tag(78), ASN1Tag.APPLICATION)
                .rawBytes(EAC11obj!Derived.tbs_bits)
                .endCons()
                .encode(concat_sig, ASN1Tag.OCTET_STRING, ASN1Tag(55), ASN1Tag.APPLICATION)
                .endCons()
                .getContentsUnlocked();
        
        if (encoding == PEM)
            throw new InvalidArgument("EAC11GenCVC::encode() cannot PEM encode an EAC object");
        else
            output.write(der);
    }

    /**
    * Get the to-be-signed (TBS) data of this object.
    * @result the TBS data of this object
    */
    final Vector!ubyte tbsData() const
    {
        return buildCertBody(m_tbs_bits);
    }


    /**
    * Build the DER encoded certifcate body of an object
    * @param tbs = the data to be signed
    * @result the correctly encoded body of the object
    */
    static Vector!ubyte buildCertBody(in Vector!ubyte tbs)
    {
        return DEREncoder()
                .startCons(ASN1Tag(78), ASN1Tag.APPLICATION)
                .rawBytes(tbs)
                .endCons().getContentsUnlocked();
    }

    /**
    * Create a signed generalized CVC object.
    * @param signer = the signer used to sign this object
    * @param tbs_bits = the body the generalized CVC object to be signed
    * @param rng = a random number generator
    * @result the DER encoded signed generalized CVC object
    */
    static Vector!ubyte makeSigned(PKSigner signer,
                                    in Vector!ubyte tbs_bits,
                                    RandomNumberGenerator rng)
    {
        const auto concat_sig = signer.signMessage(tbs_bits, rng);
        
        return DEREncoder()
                .startCons(ASN1Tag(33), ASN1Tag.APPLICATION)
                .rawBytes(tbs_bits)
                .encode(concat_sig, ASN1Tag.OCTET_STRING, ASN1Tag(55), ASN1Tag.APPLICATION)
                .endCons()
                .getContentsUnlocked();
    }

    this() { m_pk = 0; }

    ~this()
    { delete m_pk; }

protected:
    ECDSAPublicKey m_pk;
    ASN1Chr m_chr;
    bool self_signed;

    static void decodeInfo(DataSource source,
                            Vector!ubyte res_tbs_bits,
                            ECDSASignature res_sig)
    {
        Vector!ubyte concat_sig;
        BERDecoder(source)
                .startCons(ASN1Tag(33))
                .startCons(ASN1Tag(78))
                .rawBytes(res_tbs_bits)
                .endCons()
                .decode(concat_sig, ASN1Tag.OCTET_STRING, ASN1Tag(55), ASN1Tag.APPLICATION)
                .endCons();
        res_sig = decodeConcatenation(concat_sig);
    }

}