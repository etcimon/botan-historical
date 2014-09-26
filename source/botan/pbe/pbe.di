/*
* PBE
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

#include <botan/asn1_oid.h>
#include <botan/data_src.h>
#include <botan/filter.h>
#include <botan/rng.h>
/**
* Password Based Encryption (PBE) Filter.
*/
class PBE : public Filter
{
	public:
		/**
		* DER encode the params (the number of iterations and the salt value)
		* @return encoded params
		*/
		abstract Vector!( byte ) encode_params() const;

		/**
		* Get this PBE's OID.
		* @return object identifier
		*/
		abstract OID get_oid() const;
};