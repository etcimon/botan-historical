/*
* PK Filters
* (C) 1999-2009 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.filters.filter;
import botan.pubkey;
/**
* PK_Encryptor Filter
*/
class PK_Encryptor_Filter : Filter
{
public:
	void write(in ubyte*, size_t);
	void end_msg();
	PK_Encryptor_Filter(PK_Encryptor* c,
							  RandomNumberGenerator rng_ref) :
		cipher(c), rng(rng_ref) {}
	~this() { delete cipher; }
private:
	PK_Encryptor* cipher;
	RandomNumberGenerator rng;
	SafeVector!ubyte buffer;
};

/**
* PK_Decryptor Filter
*/
class PK_Decryptor_Filter : Filter
{
public:
	void write(in ubyte*, size_t);
	void end_msg();
	PK_Decryptor_Filter(PK_Decryptor* c) : cipher(c) {}
	~this() { delete cipher; }
private:
	PK_Decryptor* cipher;
	SafeVector!ubyte buffer;
};

/**
* PK_Signer Filter
*/
class PK_Signer_Filter : Filter
{
public:
	void write(in ubyte*, size_t);
	void end_msg();

	PK_Signer_Filter(PK_Signer s,
						  RandomNumberGenerator rng_ref) :
		signer(s), rng(rng_ref) {}

	~this() { delete signer; }
private:
	PK_Signer signer;
	RandomNumberGenerator rng;
};

/**
* PK_Verifier Filter
*/
class PK_Verifier_Filter : Filter
{
public:
	void write(in ubyte*, size_t);
	void end_msg();

	void set_signature(in ubyte*, size_t);
	void set_signature(in SafeVector!ubyte);

	PK_Verifier_Filter(PK_Verifier* v) : verifier(v) {}
	PK_Verifier_Filter(PK_Verifier*, in ubyte*, size_t);
	PK_Verifier_Filter(PK_Verifier*, in SafeVector!ubyte);
	~this() { delete verifier; }
private:
	PK_Verifier* verifier;
	SafeVector!ubyte signature;
};