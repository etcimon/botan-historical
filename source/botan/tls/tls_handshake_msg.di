/*
* TLS Handshake Message
* (C) 2012 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#define BOTAN_TLS_HANDSHAKE_MSG_H__

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
		abstract Handshake_Type type() const = 0;

		abstract std::vector<byte> serialize() const = 0;

		abstract ~Handshake_Message() {}
};

}