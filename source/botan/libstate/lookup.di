/*
* Algorithm Lookup
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.libstate;
import botan.engine;
import botan.filters;
import botan.mode_pad;
import botan.kdf;
import botan.eme;
import botan.emsa;
import botan.pbkdf;
/**
* Retrieve an object prototype from the global factory
* @param algo_spec an algorithm name
* @return constant prototype object (use clone to create usable object),
			 library retains ownership
*/
 const BlockCipher
retrieve_block_cipher(in string algo_spec)
{
	Algorithm_Factory af = global_state().algorithm_factory();
	return af.prototype_block_cipher(algo_spec);
}

/**
* Retrieve an object prototype from the global factory
* @param algo_spec an algorithm name
* @return constant prototype object (use clone to create usable object),
			 library retains ownership
*/
 const StreamCipher
retrieve_stream_cipher(in string algo_spec)
{
	Algorithm_Factory af = global_state().algorithm_factory();
	return af.prototype_stream_cipher(algo_spec);
}

/**
* Retrieve an object prototype from the global factory
* @param algo_spec an algorithm name
* @return constant prototype object (use clone to create usable object),
			 library retains ownership
*/
 const HashFunction
retrieve_hash(in string algo_spec)
{
	Algorithm_Factory af = global_state().algorithm_factory();
	return af.prototype_hash_function(algo_spec);
}

/**
* Retrieve an object prototype from the global factory
* @param algo_spec an algorithm name
* @return constant prototype object (use clone to create usable object),
			 library retains ownership
*/
 const MessageAuthenticationCode
retrieve_mac(in string algo_spec)
{
	Algorithm_Factory af = global_state().algorithm_factory();
	return af.prototype_mac(algo_spec);
}

/*
* Get an algorithm object
*  NOTE: these functions create and return new objects, letting the
* caller assume ownership of them
*/

/**
* Block cipher factory method.
* @deprecated Call algorithm_factory() directly
*
* @param algo_spec the name of the desired block cipher
* @return pointer to the block cipher object
*/
 BlockCipher get_block_cipher(in string algo_spec)
{
	Algorithm_Factory af = global_state().algorithm_factory();
	return af.make_block_cipher(algo_spec);
}

/**
* Stream cipher factory method.
* @deprecated Call algorithm_factory() directly
*
* @param algo_spec the name of the desired stream cipher
* @return pointer to the stream cipher object
*/
 StreamCipher get_stream_cipher(in string algo_spec)
{
	Algorithm_Factory af = global_state().algorithm_factory();
	return af.make_stream_cipher(algo_spec);
}

/**
* Hash function factory method.
* @deprecated Call algorithm_factory() directly
*
* @param algo_spec the name of the desired hash function
* @return pointer to the hash function object
*/
 HashFunction get_hash(in string algo_spec)
{
	Algorithm_Factory af = global_state().algorithm_factory();
	return af.make_hash_function(algo_spec);
}

/**
* MAC factory method.
* @deprecated Call algorithm_factory() directly
*
* @param algo_spec the name of the desired MAC
* @return pointer to the MAC object
*/
 MessageAuthenticationCode get_mac(in string algo_spec)
{
	Algorithm_Factory af = global_state().algorithm_factory();
	return af.make_mac(algo_spec);
}

/**
* Password based key derivation function factory method
* @param algo_spec the name of the desired PBKDF algorithm
* @return pointer to newly allocated object of that type
*/
PBKDF get_pbkdf(in string algo_spec);

/**
* @deprecated Use get_pbkdf
* @param algo_spec the name of the desired algorithm
* @return pointer to newly allocated object of that type
*/
 PBKDF get_s2k(in string algo_spec)
{
	return get_pbkdf(algo_spec);
}

/*
* Get a cipher object
*/

/**
* Factory method for general symmetric cipher filters.
* @param algo_spec the name of the desired cipher
* @param key the key to be used for encryption/decryption performed by
* the filter
* @param iv the initialization vector to be used
* @param direction determines whether the filter will be an encrypting
* or decrypting filter
* @return pointer to newly allocated encryption or decryption filter
*/
Keyed_Filter get_cipher(in string algo_spec,
											  const SymmetricKey& key,
											  const InitializationVector& iv,
											  Cipher_Dir direction);

/**
* Factory method for general symmetric cipher filters.
* @param algo_spec the name of the desired cipher
* @param key the key to be used for encryption/decryption performed by
* the filter
* @param direction determines whether the filter will be an encrypting
* or decrypting filter
* @return pointer to the encryption or decryption filter
*/
Keyed_Filter get_cipher(in string algo_spec,
											  const SymmetricKey& key,
											  Cipher_Dir direction);

/**
* Factory method for general symmetric cipher filters. No key will be
* set in the filter.
*
* @param algo_spec the name of the desired cipher
* @param direction determines whether the filter will be an encrypting or
* decrypting filter
* @return pointer to the encryption or decryption filter
*/
Keyed_Filter get_cipher(in string algo_spec,
											  Cipher_Dir direction);

/**
* Check if an algorithm exists.
* @param algo_spec the name of the algorithm to check for
* @return true if the algorithm exists, false otherwise
*/
bool have_algorithm(in string algo_spec);

/**
* Check if a block cipher algorithm exists.
* @deprecated Call algorithm_factory() directly
*
* @param algo_spec the name of the algorithm to check for
* @return true if the algorithm exists, false otherwise
*/
 bool have_block_cipher(in string algo_spec)
{
	Algorithm_Factory af = global_state().algorithm_factory();
	return (af.prototype_block_cipher(algo_spec) != null);
}

/**
* Check if a stream cipher algorithm exists.
* @deprecated Call algorithm_factory() directly
*
* @param algo_spec the name of the algorithm to check for
* @return true if the algorithm exists, false otherwise
*/
 bool have_stream_cipher(in string algo_spec)
{
	Algorithm_Factory af = global_state().algorithm_factory();
	return (af.prototype_stream_cipher(algo_spec) != null);
}

/**
* Check if a hash algorithm exists.
* @deprecated Call algorithm_factory() directly
*
* @param algo_spec the name of the algorithm to check for
* @return true if the algorithm exists, false otherwise
*/
 bool have_hash(in string algo_spec)
{
	Algorithm_Factory af = global_state().algorithm_factory();
	return (af.prototype_hash_function(algo_spec) != null);
}

/**
* Check if a MAC algorithm exists.
* @deprecated Call algorithm_factory() directly
*
* @param algo_spec the name of the algorithm to check for
* @return true if the algorithm exists, false otherwise
*/
 bool have_mac(in string algo_spec)
{
	Algorithm_Factory af = global_state().algorithm_factory();
	return (af.prototype_mac(algo_spec) != null);
}

/*
* Query information about an algorithm
*/

/**
* Find out the block size of a certain symmetric algorithm.
* @deprecated Call algorithm_factory() directly
*
* @param algo_spec the name of the algorithm
* @return block size of the specified algorithm
*/
size_t block_size_of(in string algo_spec);

/**
* Find out the output length of a certain symmetric algorithm.
* @deprecated Call algorithm_factory() directly
*
* @param algo_spec the name of the algorithm
* @return output length of the specified algorithm
*/
size_t output_length_of(in string algo_spec);