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
        init(input);
        m_self_signed = true;
        doDecode();
    }

    /**
    * Construct a CVC request from a DER encoded CVC request file.
    * @param str = the path to the DER encoded file
    */
    this(in string str)
    {
        auto stream = scoped!DataSourceStream(input, true);
        init(stream);
        m_self_signed = true;
        doDecode();
    }

private:
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