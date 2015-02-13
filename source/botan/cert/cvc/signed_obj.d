/*
* EAC SIGNED Object
* (C) 2007 FlexSecure GmbH
*      2008 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.cert.cvc.signed_obj;

import botan.constants;
static if (BOTAN_HAS_CARD_VERIFIABLE_CERTIFICATES):

import botan.asn1.asn1_obj;
import botan.cert.x509.key_constraint;
import botan.pubkey.x509_key;
import botan.filters.pipe;
import botan.pubkey.pubkey;
import botan.asn1.oids;
import botan.utils.types;
import botan.utils.exceptn;
import botan.codec.pem;
import botan.utils.mem_ops;

import std.algorithm : splitter;

interface SignedObject {
    /**
    * Get the TBS (to-be-signed) data in this object.
    * @return DER encoded TBS data of this object
    */
	const(Vector!ubyte) tbsData() const;
    
    /**
    * Get the signature of this object as a concatenation, i.e. if the
    * signature consists of multiple parts (like in the case of ECDSA)
    * these will be concatenated.
    * @return signature as a concatenation of its parts
    */
	const(Vector!ubyte) getConcatSig() const;
    /**
    * Write this object DER encoded into a specified pipe.
    * @param pipe = the pipe to write the encoded object to
    * @param encoding = the encoding type to use
    */
    void encode(Pipe pipe, X509Encoding encoding = PEM_) const;
protected:
	abstract void forceDecode();
}

/**
* This class represents abstract signed EAC object
*/
abstract class EACSignedObject : SignedObject
{
public:


    /**
    * Get the signature algorithm identifier used to sign this object.
    * @result the signature algorithm identifier
    */
    const(AlgorithmIdentifier) signatureAlgorithm() const
    {
        return m_sig_algo;
    }

    /**
    * Check the signature of this object.
    * @param key = the public key associated with this signed object
    * @param sig = the signature we are checking
    * @return true if the signature was created by the private key
    * associated with this public key
    */
	bool checkSignature(ALLOC)(PublicKey pub_key, auto ref Vector!(ubyte, ALLOC) sig) const
    {
        try
        {
            Vector!string sig_info = splitter(OIDS.lookup(m_sig_algo.oid), '/');
            
            if (sig_info.length != 2 || sig_info[0] != pub_key.algoName)
            {
                return false;
            }
            
            string padding = sig_info[1];
            SignatureFormat format = (pub_key.messageParts() >= 2) ? DER_SEQUENCE : IEEE_1363;
            
			const(Vector!ubyte) to_sign = tbsData();
            
            PKVerifier verifier = PKVerifier(pub_key, padding, format);
            return verifier.verifyMessage(to_sign, sig);
        }
        catch (Throwable)
        {
            return false;
        }
    }



    /**
    * BER encode this object.
    * @return result containing the BER representation of this object.
    */
    Vector!ubyte BER_encode() const
    {
        Pipe ber;
        ber.startMsg();
        encode(ber, RAW_BER);
        ber.endMsg();
        return unlock(ber.readAll());
    }

    /**
    * PEM encode this object.
    * @return result containing the PEM representation of this object.
    */
    string PEM_encode() const
    {
        Pipe pem;
        pem.startMsg();
        encode(pem, PEM_);
        pem.endMsg();
        return pem.toString();
    }

    ~this() {}
protected:

    /*
    * Try to decode the actual information
    */
    void doDecode()
    {
        try {
            forceDecode();
        }
        catch(DecodingError e)
        {
            const string what = e.msg;
            throw new DecodingError("EACSignedObject decoding failed (" ~ what ~ ")");
        }
        catch(InvalidArgument e)
        {
            const string what = e.msg;
			throw new DecodingError("EACSignedObject decoding failed (" ~ what ~ ")");
        }
    }

    this() {}

    AlgorithmIdentifier m_sig_algo;
    Vector!ubyte m_tbs_bits;
    string[] m_PEM_labels_allowed;
}