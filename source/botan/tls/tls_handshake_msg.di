/*
* TLS Handshake Message
* (C) 2012 Jack Lloyd
*
* Released under the terms of the botan license.
*/

#include <botan/tls_magic.h>
#include <vector>
#include <string>
namespace TLS {

/**
* TLS Handshake Message Base Class
*/
class Handshake_Message
{
	public:
		abstract Handshake_Type type() const;

		abstract Vector!( byte ) serialize() const;

		abstract ~Handshake_Message() {}
};

}