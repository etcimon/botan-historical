/*
* PBE Lookup
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

#include <botan/pbe.h>
#include <vector>
#include <string>
#include <chrono>
/**
* Factory function for PBEs.
* @param algo_spec the name of the PBE algorithm to retrieve
* @param passphrase the passphrase to use for encryption
* @param msec how many milliseconds to run the PBKDF
* @param rng a random number generator
* @return pointer to a PBE with randomly created parameters
*/
PBE* get_pbe(in string algo_spec,
							  in string passphrase,
							  std::chrono::milliseconds msec,
							  RandomNumberGenerator& rng);

/**
* Factory function for PBEs.
* @param pbe_oid the oid of the desired PBE
* @param params a DataSource providing the DER encoded parameters to use
* @param passphrase the passphrase to use for decryption
* @return pointer to the PBE with the specified parameters
*/
PBE* get_pbe(const OID& pbe_oid,
							  in Array!byte params,
							  in string passphrase);