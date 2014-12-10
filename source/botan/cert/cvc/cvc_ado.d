/*
* EAC11 CVC ADO
* (C) 2008 Falko Strenzke
*
* Distributed under the terms of the botan license.
*/
module botan.cert.cvc.cvc_ado;

import botan.constants;
static if (BOTAN_HAS_CARD_VERIFIABLE_CERTIFICATES):

import botan.cert.cvc.eac_obj;
import botan.cert.cvc.eac_asn_obj;
import botan.cert.cvc.cvc_req;
import botan.cert.cvc.ecdsa_sig;
import botan.rng.rng;
import botan.pubkey.pubkey;
import botan.filters.data_src;
import botan.filters.pipe;
import botan.pubkey.x509_key;
import botan.asn1.asn1_obj;
import botan.utils.types;
// import fstream;
// import string;

alias EAC11ADO = FreeListRef!EAC11ADOImpl;
/**
* This class represents a TR03110 (EAC) v1.1 CVC ADO request
*/

 // CRTP continuation from EAC11obj
final class EAC11ADOImpl : EAC11obj!EAC11ADO
{
public:
    /**
    * Construct a CVC ADO request from a DER encoded CVC ADO request file.
    * @param str = the path to the DER encoded file
    */
    this(in string input)
    {
        auto stream = scoped!DataSourceStream(input, true);
        init(stream);
        doDecode();
    }

    /**
    * Construct a CVC ADO request from a data source
    * @param source = the data source
    */
    this(DataSource input)
    {
        init(input);
       doDecodee();
    }

    /**
    * Create a signed CVC ADO request from to be signed (TBS) data
    * @param signer = the signer used to sign the CVC ADO request
    * @param tbs_bits = the TBS data to sign
    * @param rng = a random number generator
    */
    static Vector!ubyte makeSigned(PKSigner signer,
                                    in Vector!ubyte tbs_bits,
                                    RandomNumberGenerator rng)
    {
        const Vector!ubyte concat_sig = signer.signMessage(tbs_bits, rng);
        
        return DEREncoder()
                .startCons((cast(ASN1Tag)7), ASN1Tag.APPLICATION)
                .rawBytes(tbs_bits)
                .encode(concat_sig, ASN1Tag.OCTET_STRING, (cast(ASN1Tag)55), ASN1Tag.APPLICATION)
                .endCons()
                .getContentsUnlocked();
    }

    /**
    * Get the CAR of this CVC ADO request
    * @result the CAR of this CVC ADO request
    */
    ASN1Car getCar() const
    {
        return m_car;
    }

    /**
    * Get the CVC request contained in this object.
    * @result the CVC request inside this CVC ADO request
    */    
    EAC11Req getRequest() const
    {
        return m_req;
    }

    /**
    * Encode this object into a pipe. Only DER is supported.
    * @param output = the pipe to encode this object into
    * @param encoding = the encoding type to use, must be DER
    */
    override void encode(Pipe output, X509Encoding encoding) const
    {
        if (encoding == PEM)
            throw new InvalidArgument("encode() cannot PEM encode an EAC object");
        
        auto concat_sig = m_sig.getConcatenation();
        
        output.write(DEREncoder()
                     .startCons((cast(ASN1Tag)7), ASN1Tag.APPLICATION)
                     .rawBytes(m_tbs_bits)
                     .encode(concat_sig, ASN1Tag.OCTET_STRING, (cast(ASN1Tag)55), ASN1Tag.APPLICATION)
                     .endCons()
                     .getContents());
    }

    bool opEquals(in EAC11ADO rhs) const
    {
        return (getConcatSig() == rhs.getConcatSig()
                && tbsData() == rhs.tbsData()
                && getCar() ==  rhs.getCar());
    }

    /**
    * Get the TBS data of this CVC ADO request.
    * @result the TBS data
    */
    override Vector!ubyte tbsData() const
    {
        return m_tbs_bits;
    }


    bool opCmp(string op)(in EAC11ADOImpl rhs)
        if (op == "!=")
    {
        return (!(this == rhs));
    }

    ~this() {}
private:
    ASN1Car m_car;
    EAC11Req m_req;

    void forceDecode()
    {
        Vector!ubyte inner_cert;
        BERDecoder(m_tbs_bits)
                    .startCons((cast(ASN1Tag)33))
                    .rawBytes(inner_cert)
                    .endCons()
                    .decode(m_car)
                    .verifyEnd();
        
        Vector!ubyte req_bits = DEREncoder()
                                .startCons((cast(ASN1Tag)33), ASN1Tag.APPLICATION)
                                .rawBytes(inner_cert)
                                .endCons()
                                .getContentsUnlocked();
        
        auto req_source = scoped!DataSourceMemory(req_bits);
        m_req = EAC11Req(req_source);
        sig_algo = m_req.sig_algo;
    }


    void decodeInfo(DataSource source,
                    ref Vector!ubyte res_tbs_bits,
                    ref ECDSASignature res_sig)
    {
        Vector!ubyte concat_sig;
        Vector!ubyte cert_inner_bits;
        ASN1Car car;
        
        BERDecoder(source)
                .startCons((cast(ASN1Tag)7))
                .startCons((cast(ASN1Tag)33))
                .rawBytes(cert_inner_bits)
                .endCons()
                .decode(car)
                .decode(concat_sig, ASN1Tag.OCTET_STRING, (cast(ASN1Tag)55), ASN1Tag.APPLICATION)
                .endCons();
        
        Vector!ubyte enc_cert = DEREncoder()
                .startCons((cast(ASN1Tag)33), ASN1Tag.APPLICATION)
                .rawBytes(cert_inner_bits)
                .endCons()
                .getContentsUnlocked();
        
        res_tbs_bits = enc_cert;
        res_tbs_bits ~= DEREncoder().encode(car).getContentsUnlocked();
        res_sig = decodeConcatenation(concat_sig);
    }
}
