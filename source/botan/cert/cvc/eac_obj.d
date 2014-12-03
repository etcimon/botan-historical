/*
* EAC11 objects
* (C) 2008 Falko Strenzke
*
* Distributed under the terms of the botan license.
*/
module botan.cert.cvc.eac_obj;

import botan.constants;
static if (BOTAN_HAS_CVC_CERTIFICATES):

import botan.cert.cvc.signed_obj;
import botan.cert.cvc.ecdsa_sig;
import botan.filters.data_src;
import botan.pubkey.pubkey;
import botan.utils.types;
import botan.utils.exceptn;


/**
* TR03110 v1.1 EAC CV Certificate
*/
// CRTP is used enable the call sequence:
class EAC11obj(Derived) : EAC_Signed_Object!Derived
{
public:
    /**
    * Return the signature as a concatenation of the encoded parts.
    * @result the concatenated signature
    */
    Vector!ubyte getConcatSig() const
    { return m_sig.getConcatenation(); }

    bool checkSignature(ref PublicKey key) const
    {
        return check_signature(key, m_sig.dEREncode());
    }

protected:
    ECDSA_Signature m_sig;

    void init(DataSource input)
    {
        try
        {
            decode_info(input, m_tbs_bits, m_sig);
        }
        catch(DecodingError)
        {
            throw new DecodingError(m_PEM_label_pref ~ " decoding failed");
        }
    }

    ~this(){}
}