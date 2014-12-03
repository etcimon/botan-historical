/*
* EAC11 CVC Request
* (C) 2008 Falko Strenzke
*      2010 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.cert.cvc.cvc_req;

import botan.constants;
static if (BOTAN_HAS_CVC_CERTIFICATES):

import botan.cert.cvc.cvc_gen_cert;
import botan.asn1.oids;
import botan.asn1.ber_dec;
import botan.utils.types;

alias EAC11Req = FreeListRef!EAC11ReqImpl;
/**
* This class represents TR03110 v1.1 EAC CV Certificate Requests.
*/
final class EAC11ReqImpl : EAC11GenCVC!EAC11ReqImpl
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

    bool opCmp(string op)(in EAC11ReqImpl rhs)
        if (op == "!=")
    {
        return !(this == rhs);

    }
    /**
    * Construct a CVC request from a data source.
    * @param source = the data source
    */
    this(DataSource source)
    {
        init(input);
        self_signed = true;
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
        self_signed = true;
        doDecode();
    }

    ~this(){}
private:
    void forceDecode()
    {
        Vector!ubyte enc_pk;
        BERDecoder tbs_cert = BERDecoder(tbs_bits);
        size_t cpi;
        tbs_cert.decode(cpi, ASN1Tag(41), ASN1Tag.APPLICATION)
                .startCons(ASN1Tag(73))
                .rawBytes(enc_pk)
                .endCons()
                .decode(m_chr)
                .verifyEnd();
        
        if (cpi != 0)
            throw new DecodingError("EAC1_1 requests cpi was not 0");
        
        m_pk = decodeEac11Key(enc_pk, sig_algo);
    }

    this() {}
}