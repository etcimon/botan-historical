/*
* EAC11 CVC
* (C) 2008 Falko Strenzke
*      2008 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.cert.cvc.cvc_cert;

import botan.constants;
static if (BOTAN_HAS_CARD_VERIFIABLE_CERTIFICATES):

public import botan.cert.cvc.cvc_gen_cert;
public import botan.cert.cvc.eac_asn_obj;
import botan.asn1.oids;
import botan.asn1.asn1_obj;
import botan.pubkey.algo.ecdsa;
import botan.utils.types;



alias EAC11CVC = FreeListRef!EAC11CVCImpl;

/**
* This class represents TR03110 (EAC) v1.1 CV Certificates
*/
final class EAC11CVCImpl : EAC11genCVC!EAC11CVCImpl//Signed_Object
{
public:
    /**
    * Get the CAR of the certificate.
    * @result the CAR of the certificate
    */
    const(ASN1Car) getCar() const
    {
        return m_car;
    }

    /**
    * Get the CED of this certificate.
    * @result the CED this certificate
    */
    const(ASN1Ced) getCed() const
    {
        return m_ced;
    }

    /**
    * Get the CEX of this certificate.
    * @result the CEX this certificate
    */
    const(ASN1Cex) getCex() const
    {
        return m_cex;
    }

    /**
    * Get the CHAT value.
    * @result the CHAT value
    */
    ubyte getChatValue() const
    {
        return m_chat_val;
    }

    bool opEquals(in EAC11CVC rhs) const
    {
        return (tbsData() == rhs.tbsData()
                && getConcatSig() == rhs.getConcatSig());
    }

    /*
    * Comparison
    */
    int opCmp(in EAC11CVCImpl rhs) const
    {
        if (this == rhs) return 0;
        else return -1;
    }

    /**
    * Construct a CVC from a data source
    * @param source = the data source
    */
    this(DataSource input)
    {
        init(input);
        m_self_signed = false;
        doDecode();
    }

    /**
    * Construct a CVC from a file
    * @param str = the path to the certificate file
    */
    this(in string input)
    {
        auto stream = DataSourceStream(input, true);
        init(cast(DataSource)stream);
        m_self_signed = false;
        doDecode();
    }

    /**
    * Construct a CVC from the copy of another CVC
    * @param other = the other CVC
    */
    this(const ref EAC11CVC other) {
        m_sig = other.m_sig.dup;
        m_sig_algo = AlgorithmIdentifier(other.m_sig_algo);
        m_tbs_bits = other.m_tbs_bits.dupr;
        m_PEM_label_pref = other.m_PEM_label_pref;
        m_PEM_labels_allowed = other.m_PEM_labels_allowed.dup;
        
        m_pk = cast(ECDSAPublicKey) other.m_pk; // no copy of this...
        m_chr = ASN1Chr(other.m_chr);
        m_self_signed = other.m_self_signed;

        m_car = ASN1Car(other.m_car);
        m_ced = ASN1Ced(other.m_ced);
        m_cex = ASN1Cex(other.m_cex);
        m_chat_val = other.m_chat_val;
        m_chat_oid = OID(other.m_chat_oid);

    }

    /**
    * Assign references to another CVC object
    * @param other = the other CVC object
    */
    void opAssign(ref EAC11CVC other) {
        m_sig = other.m_sig;
        m_sig_algo = other.m_sig_algo;
        m_tbs_bits = other.m_tbs_bits.dupr;
        m_PEM_label_pref = other.m_PEM_label_pref;
        m_PEM_labels_allowed = other.m_PEM_labels_allowed;
        m_pk = other.m_pk;
        m_chr = other.m_chr;
        m_self_signed = other.m_self_signed;

        m_car = other.m_car;
        m_ced = other.m_ced;
        m_cex = other.m_cex;
        m_chat_val = other.m_chat_val;
        m_chat_oid = other.m_chat_oid;
    }

    ~this() {}
protected:

    /*
    * Decode the TBSCertificate data
    */
    void forceDecode()
    {
        Vector!ubyte enc_pk;
        Vector!ubyte enc_chat_val;
        size_t cpi;
        BERDecoder tbs_cert = BERDecoder(m_tbs_bits);
        tbs_cert.decode(cpi, (cast(ASN1Tag)41), ASN1Tag.APPLICATION)
                .decode(m_car)
                .startCons((cast(ASN1Tag)73))
                .rawBytes(enc_pk)
                .endCons()
                .decode(m_chr)
                .startCons((cast(ASN1Tag)76))
                .decode(m_chat_oid)
                .decode(enc_chat_val, ASN1Tag.OCTET_STRING, (cast(ASN1Tag)19), ASN1Tag.APPLICATION)
                .endCons()
                .decode(m_ced)
                .decode(m_cex)
                .verifyEnd();
        
        if (enc_chat_val.length != 1)
            throw new DecodingError("CertificateHolderAuthorizationValue was not of length 1");
        
        if (cpi != 0)
            throw new DecodingError("EAC1_1 certificate's cpi was not 0");
        
        m_pk = decodeEac11Key(enc_pk, m_sig_algo);

        m_chat_val = enc_chat_val[0];

        m_self_signed = (m_car.iso8859() == m_chr.iso8859());
    }

    this() {}

    ASN1Car m_car;
    ASN1Ced m_ced;
    ASN1Cex m_cex;
    ubyte m_chat_val;
    OID m_chat_oid;
}

/**
* Create an arbitrary EAC 1.1 CVC.
* The desired key encoding must be set within the key (if applicable).
* @param signer = the signer used to sign the certificate
* @param public_key = the DER encoded public key to appear in
* the certificate
* @param car = the CAR of the certificate
* @param chr = the CHR of the certificate
* @param holder_auth_templ = the holder authorization value ubyte to
* appear in the CHAT of the certificate
* @param ced = the CED to appear in the certificate
* @param cex = the CEX to appear in the certificate
* @param rng = a random number generator
*/
EAC11CVC makeCvcCert(int ALLOC)(ref PKSigner signer,
			                    const ref Vector!(ubyte, ALLOC) public_key,
			                    in ASN1Car car,
			                    in ASN1Chr chr,
			                    in ubyte holder_auth_templ,
			                    in ASN1Ced ced,
			                    in ASN1Cex cex,
			                    RandomNumberGenerator rng)
{
    OID chat_oid = OIDS.lookup("CertificateHolderAuthorizationTemplate");
    Vector!ubyte enc_chat_val;
    enc_chat_val.pushBack(holder_auth_templ);
    
    Vector!ubyte enc_cpi;
    enc_cpi.pushBack(0x00);
    Array!ubyte tbs = DEREncoder()
                        .encode(enc_cpi, ASN1Tag.OCTET_STRING, (cast(ASN1Tag)41), ASN1Tag.APPLICATION) // cpi
                        .encode(car)
                        .rawBytes(public_key)
                        .encode(chr)
                        .startCons((cast(ASN1Tag)76), ASN1Tag.APPLICATION)
                        .encode(chat_oid)
                        .encode(enc_chat_val, ASN1Tag.OCTET_STRING, (cast(ASN1Tag)19), ASN1Tag.APPLICATION)
                        .endCons()
                        .encode(ced)
                        .encode(cex)
                        .getContentsUnlocked();
    
    Array!ubyte signed_cert = EAC11CVC.makeSigned(signer, EAC11CVC.buildCertBody(tbs), rng);
    
    auto source = DataSourceMemory(signed_cert);
    return EAC11CVC(cast(DataSource)source);
}

EAC11CVC makeCvcCert(int ALLOC)(ref PKSigner signer,
								auto const ref FreeListRef!(Vector!(ubyte, ALLOC)) public_key,
								in ASN1Car car,
								in ASN1Chr chr,
								in ubyte holder_auth_templ,
								in ASN1Ced ced,
								in ASN1Cex cex,
								RandomNumberGenerator rng)
{
	return makeCvcCert(signer, **public_key, car, chr, holder_auth_templ, ced, cex, rng);
}
/**
* Decode an EAC encoding ECDSA key
*/

ECDSAPublicKey decodeEac11Key(const ref Vector!ubyte,
                              ref AlgorithmIdentifier)
{
    throw new InternalError("decodeEac11Key: Unimplemented");
}
