/*
* X.509 SIGNED Object
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.cert.x509.x509_obj;

import botan.constants;
static if (BOTAN_HAS_X509_CERTIFICATES):

import botan.asn1.asn1_obj;
import botan.filters.pipe;
import botan.rng.rng;
import botan.pubkey.x509_key;
import botan.pubkey.pubkey;
import botan.asn1.oids;
import botan.asn1.der_enc;
import botan.asn1.ber_dec;
import botan.utils.parsing;
import botan.codec.pem;
import std.algorithm;
import botan.utils.types;
import botan.utils.types;
import std.array;

/**
* This class represents abstract X.509 signed objects as
* in the X.500 SIGNED macro
*/
class X509Object : ASN1Object
{
public:
    /**
    * The underlying data that is to be or was signed
    * @return data that is or was signed
    */
    final Vector!ubyte tbsData() const
    {
        return put_in_sequence(m_tbs_bits);
    }

    /**
    * @return signature on tbs_data()
    */
    final Vector!ubyte signature() const
    {
        return m_sig;
    }

    /**
    * @return signature algorithm that was used to generate signature
    */
    final AlgorithmIdentifier signatureAlgorithm() const
    {
        return m_sig_algo;
    }

    /**
    * @return hash algorithm that was used to generate signature
    */
    final string hashUsedForSignature() const
    {
        Vector!string sig_info = splitter(OIDS.lookup(m_sig_algo.oid), '/');
        
        if (sig_info.length != 2)
            throw new InternalError("Invalid name format found for " ~ m_sig_algo.oid.toString());
        
        Vector!string pad_and_hash = parse_algorithm_name(sig_info[1]);
        
        if (pad_and_hash.length != 2)
            throw new InternalError("Invalid name format " ~ sig_info[1]);
        
        return pad_and_hash[1];
    }


    /**
    * Create a signed X509 object.
    * @param signer = the signer used to sign the object
    * @param rng = the random number generator to use
    * @param alg_id = the algorithm identifier of the signature scheme
    * @param tbs = the tbs bits to be signed
    * @return signed X509 object
    */
    static Vector!ubyte makeSigned(ref PKSigner signer,
                             RandomNumberGenerator rng,
                             const AlgorithmIdentifier algo,
                             in SecureVector!ubyte tbs_bits)
    {
        return DEREncoder()
                .startCons(ASN1Tag.SEQUENCE)
                .rawBytes(m_tbs_bits)
                .encode(algo)
                .encode(signer.signMessage(m_tbs_bits, rng), ASN1Tag.BIT_STRING)
                .endCons()
                .getContentsUnlocked();
    }
    


    /**
    * Check the signature on this data
    * @param key = the public key purportedly used to sign this data
    * @return true if the signature is valid, otherwise false
    */
    final bool checkSignature(in PublicKey pub_key) const
    {
        try {
            Vector!string sig_info = splitter(OIDS.lookup(m_sig_algo.oid), '/');
            
            if (sig_info.length != 2 || sig_info[0] != pub_key.algo_name)
                return false;
            
            string padding = sig_info[1];
            Signature_Format format = (pub_key.message_parts() >= 2) ? DER_SEQUENCE : IEEE_1363;
            
            PKVerifier verifier = PKVerifier(pub_key, padding, format);
            return verifier.verifyMessage(tbs_data(), signature());
        }
        catch(Exception e)
        {
            return false;
        }
    }

    override void encodeInto(DEREncoder to) const
    {
        to.startCons(ASN1Tag.SEQUENCE)
                .startCons(ASN1Tag.SEQUENCE)
                .rawBytes(m_tbs_bits)
                .endCons()
                .encode(m_sig_algo)
                .encode(sig, ASN1Tag.BIT_STRING)
                .endCons();
    }

    /*
    * Read a BER encoded X.509 object
    */
    override void decodeFrom(BERDecoder from)
    {
        from.startCons(ASN1Tag.SEQUENCE)
                .startCons(ASN1Tag.SEQUENCE)
                .rawBytes(m_tbs_bits)
                .endCons()
                .decode(m_sig_algo)
                .decode(m_sig, ASN1Tag.BIT_STRING)
                .verifyEnd()
                .endCons();
    }


    /**
    * @return BER encoding of this
    */
    final Vector!ubyte BER_encode() const
    {
        auto der = BERDecoder();
        encodeInto(der);
        return der.getContentsUnlocked();
    }


    /**
    * @return PEM encoding of this
    */
    final string PEM_encode() const
    {
        return PEM.encode(BER_encode(), m_PEM_label_pref);
    }

    ~this() {}
protected:
    /*
    * Create a generic X.509 object
    */
    this(DataSource stream, in string labels)
    {
        init(stream, labels);
    }

    /*
    * Create a generic X.509 object
    */
    this(in string file, in string labels)
    {
        auto stream = scoped!DataSourceStream(file, true);
        init(stream, labels);
    }

    /*
    * Create a generic X.509 object
    */
    this(in Vector!ubyte vec, in string labels)
    {
        auto stream = scoped!DataSourceMemory(vec.ptr, vec.length);
        init(stream, labels);
    }

    /*
    * Try to decode the actual information
    */
    final void doDecode()
    {
        try {
            forceDecode();
        }
        catch(DecodingError e)
        {
            throw new DecodingError(m_PEM_label_pref ~ " decoding failed (" ~ e.msg ~ ")");
        }
        catch(InvalidArgument e)
        {
            throw new DecodingError(m_PEM_label_pref ~ " decoding failed (" ~ e.msg ~ ")");
        }
    }
    this() {}
    AlgorithmIdentifier m_sig_algo;
    Vector!ubyte m_tbs_bits, m_sig;
private:
    abstract void forceDecode();

    /*
    * Read a PEM or BER X.509 object
    */
    final void init(DataSource input, in string labels)
    {
        m_PEM_labels_allowed = splitter(labels, '/').array!(string[]);
        if (m_PEM_labels_allowed.length < 1)
            throw new InvalidArgument("Bad labels argument to X509Object");
        
        m_PEM_label_pref = m_PEM_labels_allowed;
        std.algorithm.sort(m_PEM_labels_allowed);
        
        try {
            if (maybe_BER(input) && !PEM.matches(input))
            {
                auto dec = BERDecoder(input);
                decodeFrom(dec);
            }
            else
            {
                string got_label;
                auto ber = scoped!DataSourceMemory(PEM.decode(input, got_label));
                if (m_PEM_labels_allowed.canFind(got_label))
                    throw new DecodingError("Invalid PEM label: " ~ got_label);
                
                auto dec = BERDecoder(ber);
                decodeFrom(dec);
            }
        }
        catch(DecodingError e)
        {
            throw new DecodingError(m_PEM_label_pref ~ " decoding failed: " ~ e.msg);
        }
    }

    string[] m_PEM_labels_allowed;
    string m_PEM_label_pref;
}
