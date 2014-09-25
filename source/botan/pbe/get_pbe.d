/*
* PBE Retrieval
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/get_pbe.h>
#include <botan/oids.h>
#include <botan/scan_name.h>
#include <botan/parsing.h>
#include <botan/libstate.h>

#if defined(BOTAN_HAS_PBE_PKCS_V20)
  #include <botan/pbes2.h>
  #include <botan/hmac.h>
#endif

namespace Botan {

/*
* Get an encryption PBE, set new parameters
*/
PBE* get_pbe(const std::string& algo_spec,
             const std::string& passphrase,
             std::chrono::milliseconds msec,
             RandomNumberGenerator& rng)
   {
   SCAN_Name request(algo_spec);

   const std::string pbe = request.algo_name();
   std::string digest_name = request.arg(0);
   const std::string cipher = request.arg(1);

   std::vector<std::string> cipher_spec = split_on(cipher, '/');
   if(cipher_spec.size() != 2)
      throw Invalid_Argument("PBE: Invalid cipher spec " + cipher);

   const std::string cipher_algo = SCAN_Name::deref_alias(cipher_spec[0]);
   const std::string cipher_mode = cipher_spec[1];

   if(cipher_mode != "CBC")
      throw Invalid_Argument("PBE: Invalid cipher mode " + cipher);

   Algorithm_Factory& af = global_state().algorithm_factory();

   const BlockCipher* block_cipher = af.prototype_block_cipher(cipher_algo);
   if(!block_cipher)
      throw Algorithm_Not_Found(cipher_algo);

   const HashFunction* hash_function = af.prototype_hash_function(digest_name);
   if(!hash_function)
      throw Algorithm_Not_Found(digest_name);

   if(request.arg_count() != 2)
      throw Invalid_Algorithm_Name(algo_spec);

#if defined(BOTAN_HAS_PBE_PKCS_V20)
   if(pbe == "PBE-PKCS5v20")
      return new PBE_PKCS5v20(block_cipher->clone(),
                              new HMAC(hash_function->clone()),
                              passphrase,
                              msec,
                              rng);
#endif

   throw Algorithm_Not_Found(algo_spec);
   }

/*
* Get a decryption PBE, decode parameters
*/
PBE* get_pbe(const OID& pbe_oid,
             const std::vector<byte>& params,
             const std::string& passphrase)
   {
   SCAN_Name request(OIDS::lookup(pbe_oid));

   const std::string pbe = request.algo_name();

#if defined(BOTAN_HAS_PBE_PKCS_V20)
   if(pbe == "PBE-PKCS5v20")
      return new PBE_PKCS5v20(params, passphrase);
#endif

   throw Algorithm_Not_Found(pbe_oid.as_string());
   }

}
