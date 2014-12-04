/*
* ECDSA Signature
* (C) 2007 Falko Strenzke, FlexSecure GmbH
* (C) 2008-2010 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.cert.cvc.ecdsa_sig;

import botan.constants;
static if (BOTAN_HAS_CVC_CERTIFICATES):

import botan.math.bigint.bigint;
import botan.asn1.der_enc;
import botan.asn1.ber_dec;
/**
* Class representing an ECDSA signature
*/
class ECDSASignature
{
public:
    this() {}
    this(in BigInt r, in BigInt s) {
        m_r = r;
        m_s = s;
    }

    this(in Vector!ubyte ber)
    {
        BERDecoder(ber)
                .startCons(ASN1Tag.SEQUENCE)
                .decode(m_r)
                .decode(m_s)
                .endCons()
                .verifyEnd();
    }

    BigInt getR() const { return m_r; }
    BigInt getS() const { return m_s; }

    /**
    * return the r||s
    */
    Vector!ubyte getConcatenation() const
    {
        // use the larger
        const size_t enc_len = m_r > m_s ? m_r.bytes() : m_s.bytes();
        
        const auto sv_r = BigInt.encode1363(m_r, enc_len);
        const auto sv_s = BigInt.encode1363(m_s, enc_len);
        
        SecureVector!ubyte result = SecureVector!ubyte(sv_r);
        result ~= sv_s;
        return unlock(result);
    }

    Vector!ubyte DER_encode() const
    {
        return DEREncoder()
                .startCons(ASN1Tag.SEQUENCE)
                .encode(getR())
                .encode(getS())
                .endCons()
                .getContentsUnlocked();
    }


    bool opEquals(in ECDSASignature other) const
    {
        return (getR() == other.getR() && getS() == other.getS());
    }

    bool opCmp(string op)(in ECDSASignature rhs)
        if (op == "!=")
    {
        return !(this == rhs);
    }

private:
    BigInt m_r;
    BigInt m_s;
}

ECDSASignature decodeConcatenation(in Vector!ubyte concat)
{
    if (concat.length % 2 != 0)
        throw new InvalidArgument("Erroneous length of signature");
    
    const size_t rs_len = concat.length / 2;
    
    BigInt r = BigInt.decode(concat.ptr, rs_len);
    BigInt s = BigInt.decode(&concat[rs_len], rs_len);
    
    return ECDSA_Signature(r, s);
}