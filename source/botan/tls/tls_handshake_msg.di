/*
* TLS Handshake Message
* (C) 2012 Jack Lloyd
*
* Released under the terms of the botan license.
*/

import botan.tls_magic;
import vector;
import string;
namespace TLS {

/**
* TLS Handshake Message Base Class
*/
class Handshake_Message
{
	public:
		abstract Handshake_Type type() const;

		abstract Vector!byte serialize() const;

		~this() {}
};

}