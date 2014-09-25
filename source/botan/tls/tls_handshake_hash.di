/*
* TLS Handshake Hash
* (C) 2004-2006,2011,2012 Jack Lloyd
*
* Released under the terms of the botan license.
*/

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
		void update(in byte[] input)
		{ data += std::make_pair(input, length); }

		void update(in Array!byte input)
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