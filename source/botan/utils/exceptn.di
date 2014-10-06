/*
* Exceptions
* (C) 1999-2009 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.types;
import botan.parsing;
import exception;
import stdexcept;
import string;
typedef Exception Exception;
typedef std::invalid_argument Invalid_Argument;

/**
* Invalid_State Exception
*/
struct Invalid_State : Exception
{
	Invalid_State(in string err) :
		Exception(err)
	{}
};

/**
* Lookup_Error Exception
*/
struct Lookup_Error : Exception
{
	Lookup_Error(in string err) :
		Exception(err)
	{}
};

/**
* Internal_Error Exception
*/
struct Internal_Error : Exception
{
	Internal_Error(in string err) :
		Exception("Internal error: " ~ err)
	{}
};

/**
* Invalid_Key_Length Exception
*/
struct Invalid_Key_Length : Invalid_Argument
{
	Invalid_Key_Length(in string name, size_t length) :
		Invalid_Argument(name ~ " cannot accept a key of length " ~
							  std.conv.to!string(length))
	{}
};

/**
* Invalid_IV_Length Exception
*/
struct Invalid_IV_Length : Invalid_Argument
{
	Invalid_IV_Length(in string mode, size_t bad_len) :
		Invalid_Argument("IV length " ~ std.conv.to!string(bad_len) +
							  " is invalid for " ~ mode)
	{}
};

/**
* PRNG_Unseeded Exception
*/
struct PRNG_Unseeded : Invalid_State
{
	PRNG_Unseeded(in string algo) :
		Invalid_State("PRNG not seeded: " ~ algo)
	{}
};

/**
* Policy_Violation Exception
*/
struct Policy_Violation : Invalid_State
{
	Policy_Violation(in string err) :
		Invalid_State("Policy violation: " ~ err)
	{}
};

/**
* Algorithm_Not_Found Exception
*/
struct Algorithm_Not_Found : Lookup_Error
{
	Algorithm_Not_Found(in string name) :
		Lookup_Error("Could not find any algorithm named \"" ~ name ~ "\"")
	{}
};

/**
* Invalid_Algorithm_Name Exception
*/
struct Invalid_Algorithm_Name : Invalid_Argument
{
	Invalid_Algorithm_Name(in string name):
		Invalid_Argument("Invalid algorithm name: " ~ name)
	{}
};

/**
* Encoding_Error Exception
*/
struct Encoding_Error : Invalid_Argument
{
	Encoding_Error(in string name) :
		Invalid_Argument("Encoding error: " ~ name) {}
};

/**
* Decoding_Error Exception
*/
struct Decoding_Error : Invalid_Argument
{
	Decoding_Error(in string name) :
		Invalid_Argument("Decoding error: " ~ name) {}
};

/**
* Integrity_Failure Exception
*/
struct Integrity_Failure : Exception
{
	Integrity_Failure(in string msg) :
		Exception("Integrity failure: " ~ msg) {}
};

/**
* Invalid_OID Exception
*/
struct Invalid_OID : Decoding_Error
{
	Invalid_OID(in string oid) :
		Decoding_Error("Invalid ASN.1 OID: " ~ oid) {}
};

/**
* Stream_IO_Error Exception
*/
struct Stream_IO_Error : Exception
{
	Stream_IO_Error(in string err) :
		Exception("I/O error: " ~ err)
	{}
};

/**
* Self Test Failure Exception
*/
struct Self_Test_Failure : Internal_Error
{
	Self_Test_Failure(in string err) :
		Internal_Error("Self test failed: " ~ err)
	{}
};

/**
* Memory Allocation Exception
*/
struct Memory_Exhaustion : std::bad_alloc
{
	string what() const noexcept
	{ return "Ran out of memory, allocation failed"; }
};