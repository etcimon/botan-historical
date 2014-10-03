/*
* X.509 Public Key
* (C) 1999-2010 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.pk_keys;
import botan.asn1.alg_id;
import botan.pipe;
import string;
/**
* The two types of X509 encoding supported by Botan.
*/
enum X509_Encoding { RAW_BER, PEM };

/**
* This namespace contains functions for handling X.509 public keys
*/
namespace X509 {

/**
* BER encode a key
* @param key the public key to encode
* @return BER encoding of this key
*/
Vector!byte BER_encode(in Public_Key key);

/**
* PEM encode a public key into a string.
* @param key the key to encode
* @return PEM encoded key
*/
string PEM_encode(in Public_Key key);

/**
* Create a public key from a data source.
* @param source the source providing the DER or PEM encoded key
* @return new public key object
*/
Public_Key* load_key(DataSource& source);

/**
* Create a public key from a file
* @param filename pathname to the file to load
* @return new public key object
*/
Public_Key* load_key(in string filename);

/**
* Create a public key from a memory region.
* @param enc the memory region containing the DER or PEM encoded key
* @return new public key object
*/
Public_Key* load_key(in Vector!byte enc);

/**
* Copy a key.
* @param key the public key to copy
* @return new public key object
*/
Public_Key* copy_key(in Public_Key key);

}