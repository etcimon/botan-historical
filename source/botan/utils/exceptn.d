/*
* Exceptions
* (C) 1999-2009 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.utils.exceptn;

import botan.types;
import botan.parsing;
import exception;
import stdexcept;
import string;
typedef Exception Exception;

/**
* Invalid_Argument Exception
*/
class Invalid_Argument : Exception
{
	this(in string err)
	{ super("Invalid argument: " ~ err); }
};

/**
* Invalid_State Exception
*/
class Invalid_State : Exception
{
	this(in string err)
	{ super(err); }
};

/**
* Logic_Error Exception
*/
class Logic_Error : Exception
{
	this(in string err)
	{ super(err); }
};

/**
* Lookup_Error Exception
*/
class Lookup_Error : Exception
{
	this(in string err)
	{ super(err); }
};

/**
* Internal_Error Exception
*/
class Internal_Error : Exception
{
	this(in string err) 
	{ super("Internal error: " ~ err); }
};

/**
* Invalid_Key_Length Exception
*/
class Invalid_Key_Length : Invalid_Argument
{
	this(in string name, size_t length) {
		super(name ~ " cannot accept a key of length " ~
		      std.conv.to!string(length));
	}
};

/**
* Invalid_IV_Length Exception
*/
class Invalid_IV_Length : Invalid_Argument
{
	this(in string mode, size_t bad_len) {
		super("IV length " ~ std.conv.to!string(bad_len) ~ " is invalid for " ~ mode);
	}
};

/**
* PRNG_Unseeded Exception
*/
class PRNG_Unseeded : Invalid_State
{
	this(in string algo) {
		super("PRNG not seeded: " ~ algo);
	}
};

/**
* Policy_Violation Exception
*/
class Policy_Violation : Invalid_State
{
	this(in string err) {
		super("Policy violation: " ~ err)
	}
};

/**
* Algorithm_Not_Found Exception
*/
class Algorithm_Not_Found : Lookup_Error
{
	this(in string name) {
		super("Could not find any algorithm named \"" ~ name ~ "\"")
	}
};

/**
* Invalid_Algorithm_Name Exception
*/
class Invalid_Algorithm_Name : Invalid_Argument
{
	this(in string name) {
		super("Invalid algorithm name: " ~ name)
	}
};

/**
* Encoding_Error Exception
*/
class Encoding_Error : Invalid_Argument
{
	this(in string name) {
		super("Encoding error: " ~ name) 
	}
};

/**
* Decoding_Error Exception
*/
class Decoding_Error : Invalid_Argument
{
	this(in string name) {
		super("Decoding error: " ~ name) }
};

/**
* Integrity_Failure Exception
*/
class Integrity_Failure : Exception
{
	this(in string msg) {
		super("Integrity failure: " ~ msg) }
};

/**
* Invalid_OID Exception
*/
class Invalid_OID : Decoding_Error
{
	this(in string oid) {
		super("Invalid ASN.1 OID: " ~ oid) }
};

/**
* Stream_IO_Error Exception
*/
class Stream_IO_Error : Exception
{
	this(in string err) {
		super("I/O error: " ~ err)
	}
};

/**
* Self Test Failure Exception
*/
class Self_Test_Failure : Internal_Error
{
	this(in string err) {
		super("Self test failed: " ~ err)
	}
};

/**
* Memory Allocation Exception
*/
class Memory_Exhaustion : Exception
{
	string what() const nothrow
	{ return "Ran out of memory, allocation failed"; }
};