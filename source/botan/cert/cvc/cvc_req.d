/*
* EAC11 CVC Request
* (C) 2008 Falko Strenzke
*      2010 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.cert.cvc.cvc_req;

import botan.constants;
static if (BOTAN_HAS_CARD_VERIFIABLE_CERTIFICATES):

import botan.cert.cvc.cvc_gen_cert;
import botan.asn1.oids;
import botan.asn1.ber_dec;
import botan.utils.types;
import botan.cert.cvc.cvc_cert;
import botan.cert.cvc.ecdsa_sig;
import botan.pubkey.algo.ecdsa;

alias EAC11Req = FreeListRef!EAC11ReqImpl;
/**
* This class represents TR03110 v1.1 EAC CV Certificate Requests.
*/
final class EAC11ReqImpl : EAC11genCVC!EAC11ReqImpl
{
public:

    /**
    * Compare for equality with other
    * @param other = compare for equality with this object
    */
    bool opEquals(in EAC11Req rhs) const
    {
        return (this.tbsData() == rhs.tbsData() &&
                this.getConcatSig() == rhs.getConcatSig());
    }

    int opCmp(in EAC11ReqImpl rhs) const
    {
        if (this == rhs)
            return 0;
        else return -1;

    }
    /**
    * Construct a CVC request from a data source.
    * @param source = the data source
    */
    this(DataSource source)
    {
        init(source);
        m_self_signed = true;
        doDecode();
    }

    /**
    * Construct a CVC request from a DER encoded CVC request file.
    * @param str = the path to the DER encoded file
    */
    this(in string str)
    {
        auto stream = DataSourceStream(str, true);
        init(cast(DataSource)stream);
        m_self_signed = true;
        doDecode();
    }

    // copy
    this(const ref EAC11Req other)
    {
        m_sig = other.m_sig.dup;
        m_sig_algo = AlgorithmIdentifier(other.m_sig_algo);
        m_tbs_bits = other.m_tbs_bits.dup;
        m_PEM_label_pref = other.m_PEM_label_pref;
        m_PEM_labels_allowed = other.m_PEM_labels_allowed.dup;
    
        m_pk = cast(ECDSAPublicKey)other.m_pk; // no copy of this...
        m_chr = ASN1Chr(other.m_chr);
        m_self_signed = other.m_self_signed;
    }

    // assign
    void opAssign(ref EAC11Req other) {
        m_sig = other.m_sig;
        m_sig_algo = other.m_sig_algo;
        m_tbs_bits = other.m_tbs_bits;
        m_PEM_label_pref = other.m_PEM_label_pref;
        m_PEM_labels_allowed = other.m_PEM_labels_allowed;
        m_pk = other.m_pk;
        m_chr = other.m_chr;
        m_self_signed = other.m_self_signed;
    }

protected:
    void forceDecode()
    {
        Vector!ubyte enc_pk;
        BERDecoder tbs_cert = BERDecoder(m_tbs_bits);
        size_t cpi;
        tbs_cert.decode(cpi, (cast(ASN1Tag)41), ASN1Tag.APPLICATION)
                .startCons((cast(ASN1Tag)73))
                .rawBytes(enc_pk)
                .endCons()
                .decode(m_chr)
                .verifyEnd();
        
        if (cpi != 0)
            throw new DecodingError("EAC1_1 requests cpi was not 0");
        
        m_pk = decodeEac11Key(enc_pk, m_sig_algo);
    }
}