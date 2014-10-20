/*
* TLS Handshake Message
* (C) 2012 Jack Lloyd
*
* Released under the terms of the botan license.
*/

import botan.tls_magic;
import vector;
import string;


/**
* TLS Handshake Message Base Class
*/
class Handshake_Message
{
	public:
		abstract Handshake_Type type() const;

		abstract Vector!ubyte serialize() const;

		~this() {}
};

}