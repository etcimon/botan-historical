/*
* PK Filters
* (C) 1999-2009 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.filters.pk_filts;

import botan.filters.filter;
import botan.pubkey;
/**
* PK_Encryptor Filter
*/
class PK_Encryptor_Filter : Filter
{
public:
	/*
	* Append to the buffer
	*/
	void write(in ubyte* input, size_t length)
	{
		buffer ~= Pair(input, length);
	}
	/*
	* Encrypt the message
	*/
	void end_msg()
	{
		send(cipher.encrypt(buffer, rng));
		buffer.clear();
	}

	this(	PK_Encryptor* c,
			RandomNumberGenerator rng_ref) 
	{
		cipher = c;
		rng = rng_ref;
	}

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
	/*
	* Append to the buffer
	*/
	void write(in ubyte* input, size_t length)
	{
		buffer ~= Pair(input, length);
	}

	/*
	* Decrypt the message
	*/
	void end_msg()
	{
		send(cipher.decrypt(buffer));
		buffer.clear();
	}

	this(PK_Decryptor* c) {  cipher = c; }
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
	/*
	* Add more data
	*/
	void write(in ubyte* input, size_t length)
	{
		signer.update(input, length);
	}

	/*
	* Sign the message
	*/
	void end_msg()
	{
		send(signer.signature(rng));
	}


	this(PK_Signer s,
		 RandomNumberGenerator rng_ref)
	{
		signer = s;
		rng = rng_ref;
	}

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
	/*
	* Add more data
	*/
	void write(in ubyte* input, size_t length)
	{
		verifier.update(input, length);
	}
	
	/*
	* Verify the message
	*/
	void end_msg()
	{
		if (signature.empty())
			throw new Invalid_State("PK_Verifier_Filter: No signature to check against");
		bool is_valid = verifier.check_signature(signature);
		send((is_valid ? 1 : 0));
	}

	/*
	* Set the signature to check
	*/
	void set_signature(in ubyte* sig, size_t length)
	{
		signature.assign(sig, sig + length);
	}
	
	/*
	* Set the signature to check
	*/
	void set_signature(in SafeVector!ubyte sig)
	{
		signature = sig;
	}
	


	this(PK_Verifier* v) { verifier = v; }
	/*
	* PK_Verifier_Filter Constructor
	*/
	this(PK_Verifier* v, in ubyte* sig,
	     size_t length)
	{
		verifier = v;
		signature = SafeVector!ubyte(sig, sig + length);
	}
	
	/*
	* PK_Verifier_Filter Constructor
	*/
	this(PK_Verifier* v,
	     in SafeVector!ubyte sig) 
	{
		verifier = v;
		signature = sig;
	}

	~this() { delete verifier; }
private:
	PK_Verifier* verifier;
	SafeVector!ubyte signature;
};