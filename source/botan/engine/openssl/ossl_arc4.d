/*
* OpenSSL RC4
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

import botan.internal.openssl_engine;
import botan.parsing;
import openssl.rc4;
namespace {

/**
* RC4 as implemented by OpenSSL
*/
class RC4_OpenSSL : StreamCipher
{
	public:
		void clear() { clear_mem(&state, 1); }

		string name() const;
		StreamCipher clone() const { return new RC4_OpenSSL(SKIP); }

		Key_Length_Specification key_spec() const
		{
			return Key_Length_Specification(1, 32);
		}		RC4_OpenSSL(size_t s = 0) : SKIP(s) { clear(); }
		~this() { clear(); }
	private:
		void cipher(const ubyte[], ubyte[], size_t);
		void key_schedule(const ubyte[], size_t);

		const size_t SKIP;
		RC4_KEY state;
};

/*
* Return the name of this type
*/
string RC4_OpenSSL::name() const
{
	if (SKIP == 0)	return "RC4";
	if (SKIP == 256) return "MARK-4";
	else				return "RC4_skip(" ~ std.conv.to!string(SKIP) ~ ")";
}

/*
* RC4 Key Schedule
*/
void RC4_OpenSSL::key_schedule(in ubyte* key, size_t length)
{
	RC4_set_key(&state, length, key);
	ubyte dummy = 0;
	for (size_t i = 0; i != SKIP; ++i)
		RC4(&state, 1, &dummy, &dummy);
}

/*
* RC4 Encryption
*/
void RC4_OpenSSL::cipher(in ubyte* input, ubyte* output, size_t length)
{
	RC4(&state, length, input, output);
}

}

/**
* Look for an OpenSSL-supported stream cipher (RC4)
*/
StreamCipher
OpenSSL_Engine::find_stream_cipher(in SCAN_Name request,
											  ref Algorithm_Factory) const
{
	if (request.algo_name() == "RC4")
		return new RC4_OpenSSL(request.arg_as_integer(0, 0));
	if (request.algo_name() == "RC4_drop")
		return new RC4_OpenSSL(768);

	return 0;
}

}
