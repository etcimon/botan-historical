/*
* EAC SIGNED Object
* (C) 2007 FlexSecure GmbH
*	  2008 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.cert.cvc.signed_obj;

import botan.asn1.asn1_obj;
import botan.cert.x509.key_constraint;
import botan.x509_key;
import botan.filters.pipe;
import botan.pubkey;
import botan.asn1.oid_lookup.oids;
import vector;

/**
* This class represents abstract signed EAC object
*/
class EAC_Signed_Object
{
public:
	/**
	* Get the TBS (to-be-signed) data in this object.
	* @return DER encoded TBS data of this object
	*/
	abstract Vector!ubyte tbs_data() const;

	/**
	* Get the signature of this object as a concatenation, i.e. if the
	* signature consists of multiple parts (like in the case of ECDSA)
	* these will be concatenated.
	* @return signature as a concatenation of its parts
	*/

	/*
	 NOTE: this is here only because abstract signature objects have
	 not yet been introduced
	*/
	abstract Vector!ubyte get_concat_sig() const;

	/**
	* Get the signature algorithm identifier used to sign this object.
	* @result the signature algorithm identifier
	*/
	AlgorithmIdentifier signature_algorithm() const
	{
		return sig_algo;
	}

	/**
	* Check the signature of this object.
	* @param key the public key associated with this signed object
	* @param sig the signature we are checking
	* @return true if the signature was created by the private key
	* associated with this public key
	*/
	bool check_signature(ref Public_Key pub_key,
	                     in Vector!ubyte sig) const
	{
		try
		{
			Vector!string sig_info =
				std.algorithm.splitter(oids.lookup(sig_algo.oid), '/');
			
			if (sig_info.size() != 2 || sig_info[0] != pub_key.algo_name())
			{
				return false;
			}
			
			string padding = sig_info[1];
			Signature_Format format =
				(pub_key.message_parts() >= 2) ? DER_SEQUENCE : IEEE_1363;
			
			Vector!ubyte to_sign = tbs_data();
			
			PK_Verifier verifier = new PK_Verifier(pub_key, padding, format);
			scope(exit) delete verifier;
			return verifier.verify_message(to_sign, sig);
		}
		catch
		{
			return false;
		}
	}


	/**
	* Write this object DER encoded into a specified pipe.
	* @param pipe the pipe to write the encoded object to
	* @param encoding the encoding type to use
	*/
	abstract void encode(Pipe pipe,
							  X509_Encoding encoding = PEM) const;

	/**
	* BER encode this object.
	* @return result containing the BER representation of this object.
	*/
	Vector!ubyte BER_encode() const
	{
		Pipe ber;
		ber.start_msg();
		encode(ber, RAW_BER);
		ber.end_msg();
		return unlock(ber.read_all());
	}

	/**
	* PEM encode this object.
	* @return result containing the PEM representation of this object.
	*/
	string PEM_encode() const
	{
		Pipe pem;
		pem.start_msg();
		encode(pem, PEM);
		pem.end_msg();
		return pem.read_all_as_string();
	}

	~this() {}
package:

	/*
	* Try to decode the actual information
	*/
	void do_decode()
	{
		try {
			force_decode();
		}
		catch(Decoding_Error e)
		{
			const string what = e.what();
			throw new Decoding_Error(PEM_label_pref ~ " decoding failed (" ~ what ~ ")");
		}
		catch(Invalid_Argument e)
		{
			const string what = e.what();
			throw new Decoding_Error(PEM_label_pref ~ " decoding failed (" ~ what ~ ")");
		}
	}

	this() {}

	AlgorithmIdentifier sig_algo;
	Vector!ubyte tbs_bits;
	string PEM_label_pref;
	Vector!string PEM_labels_allowed;
private:
	abstract void force_decode();
};