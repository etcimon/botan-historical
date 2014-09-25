/*
* TLS Handshake Hash
* (C) 2004-2006,2011,2012 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#define BOTAN_TLS_HANDSHAKE_HASH_H__

#include <botan/secmem.h>
#include <botan/tls_version.h>
#include <botan/tls_magic.h>
namespace TLS {

using namespace Botan;

/**
* TLS Handshake Hash
*/
class Handshake_Hash
{
	public:
		void update(const byte in[], size_t length)
		{ data += std::make_pair(in, length); }

		void update(in Array!byte in)
		{ data += in; }

		SafeArray!byte final(Protocol_Version version,
										  in string mac_algo) const;

		SafeArray!byte final_ssl3(in SafeArray!byte master_secret) const;

		in Array!byte get_contents() const
		{ return data; }

		void reset() { data.clear(); }
	private:
		std::vector<byte> data;
};

}