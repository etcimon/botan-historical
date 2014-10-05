/*
* EAC SIGNED Object
* (C) 2007 FlexSecure GmbH
*	  2008 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.asn1.asn1_obj;
import botan.key_constraint;
import botan.x509_key;
import botan.pipe;
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
	AlgorithmIdentifier signature_algorithm() const;

	/**
	* Check the signature of this object.
	* @param key the public key associated with this signed object
	* @param sig the signature we are checking
	* @return true if the signature was created by the private key
	* associated with this public key
	*/
	bool check_signature(ref Public_Key key,
								in Vector!ubyte sig) const;

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
	Vector!ubyte BER_encode() const;

	/**
	* PEM encode this object.
	* @return result containing the PEM representation of this object.
	*/
	string PEM_encode() const;

	~this() {}
package:
	void do_decode();
	this() {}

	AlgorithmIdentifier sig_algo;
	Vector!ubyte tbs_bits;
	string PEM_label_pref;
	Vector!string PEM_labels_allowed;
private:
	abstract void force_decode();
};