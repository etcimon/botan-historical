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
class X509_Object : ASN1_Object
{
public:
    /**
    * The underlying data that is to be or was signed
    * @return data that is or was signed
    */
    final Vector!ubyte tbs_data() const
    {
        return asn1_obj.put_in_sequence(m_tbs_bits);
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
    final Algorithm_Identifier signature_algorithm() const
    {
        return m_sig_algo;
    }

    /**
    * @return hash algorithm that was used to generate signature
    */
    final string hash_used_for_signature() const
    {
        Vector!string sig_info = splitter(OIDS.lookup(m_sig_algo.oid), '/');
        
        if (sig_info.length != 2)
            throw new Internal_Error("Invalid name format found for " ~ m_sig_algo.oid.toString());
        
        Vector!string pad_and_hash = parse_algorithm_name(sig_info[1]);
        
        if (pad_and_hash.length != 2)
            throw new Internal_Error("Invalid name format " ~ sig_info[1]);
        
        return pad_and_hash[1];
    }


    /**
    * Create a signed X509 object.
    * @param signer the signer used to sign the object
    * @param rng the random number generator to use
    * @param alg_id the algorithm identifier of the signature scheme
    * @param tbs the tbs bits to be signed
    * @return signed X509 object
    */
    static Vector!ubyte make_signed(ref PK_Signer signer,
                             RandomNumberGenerator rng,
                             const Algorithm_Identifier algo,
                             in Secure_Vector!ubyte tbs_bits)
    {
        return DER_Encoder()
                .start_cons(ASN1_Tag.SEQUENCE)
                .raw_bytes(m_tbs_bits)
                .encode(algo)
                .encode(signer.sign_message(m_tbs_bits, rng), ASN1_Tag.BIT_STRING)
                .end_cons()
                .get_contents_unlocked();
    }
    


    /**
    * Check the signature on this data
    * @param key the public key purportedly used to sign this data
    * @return true if the signature is valid, otherwise false
    */
    final bool check_signature(in Public_Key pub_key) const
    {
        try {
            Vector!string sig_info = splitter(OIDS.lookup(m_sig_algo.oid), '/');
            
            if (sig_info.length != 2 || sig_info[0] != pub_key.algo_name)
                return false;
            
            string padding = sig_info[1];
            Signature_Format format = (pub_key.message_parts() >= 2) ? DER_SEQUENCE : IEEE_1363;
            
            PK_Verifier verifier = PK_Verifier(pub_key, padding, format);
            return verifier.verify_message(tbs_data(), signature());
        }
        catch(Exception e)
        {
            return false;
        }
    }

    override void encode_into(DER_Encoder to) const
    {
        to.start_cons(ASN1_Tag.SEQUENCE)
                .start_cons(ASN1_Tag.SEQUENCE)
                .raw_bytes(m_tbs_bits)
                .end_cons()
                .encode(m_sig_algo)
                .encode(sig, ASN1_Tag.BIT_STRING)
                .end_cons();
    }

    /*
    * Read a BER encoded X.509 object
    */
    override void decode_from(BER_Decoder from)
    {
        from.start_cons(ASN1_Tag.SEQUENCE)
                .start_cons(ASN1_Tag.SEQUENCE)
                .raw_bytes(m_tbs_bits)
                .end_cons()
                .decode(m_sig_algo)
                .decode(m_sig, ASN1_Tag.BIT_STRING)
                .verify_end()
                .end_cons();
    }


    /**
    * @return BER encoding of this
    */
    final Vector!ubyte BER_encode() const
    {
        auto der = BER_Decoder();
        encode_into(der);
        return der.get_contents_unlocked();
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
        auto stream = scoped!DataSource_Stream(file, true);
        init(stream, labels);
    }

    /*
    * Create a generic X.509 object
    */
    this(in Vector!ubyte vec, in string labels)
    {
        auto stream = scoped!DataSource_Memory(vec.ptr, vec.length);
        init(stream, labels);
    }

    /*
    * Try to decode the actual information
    */
    final void do_decode()
    {
        try {
            force_decode();
        }
        catch(Decoding_Error e)
        {
            throw new Decoding_Error(m_PEM_label_pref ~ " decoding failed (" ~ e.msg ~ ")");
        }
        catch(Invalid_Argument e)
        {
            throw new Decoding_Error(m_PEM_label_pref ~ " decoding failed (" ~ e.msg ~ ")");
        }
    }
    this() {}
    Algorithm_Identifier m_sig_algo;
    Vector!ubyte m_tbs_bits, m_sig;
private:
    abstract void force_decode();

    /*
    * Read a PEM or BER X.509 object
    */
    final void init(DataSource input, in string labels)
    {
        m_PEM_labels_allowed = splitter(labels, '/').array!(string[]);
        if (m_PEM_labels_allowed.length < 1)
            throw new Invalid_Argument("Bad labels argument to X509_Object");
        
        m_PEM_label_pref = m_PEM_labels_allowed;
        std.algorithm.sort(m_PEM_labels_allowed);
        
        try {
            if (asn1_obj.maybe_BER(input) && !PEM.matches(input))
            {
                auto dec = BER_Decoder(input);
                decode_from(dec);
            }
            else
            {
                string got_label;
                auto ber = scoped!DataSource_Memory(PEM.decode(input, got_label));
                if (m_PEM_labels_allowed.canFind(got_label))
                    throw new Decoding_Error("Invalid PEM label: " ~ got_label);
                
                auto dec = BER_Decoder(ber);
                decode_from(dec);
            }
        }
        catch(Decoding_Error e)
        {
            throw new Decoding_Error(m_PEM_label_pref ~ " decoding failed: " ~ e.msg);
        }
    }

    string[] m_PEM_labels_allowed;
    string m_PEM_label_pref;
}
