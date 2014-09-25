/*
* Exceptions
* (C) 1999-2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_EXCEPTION_H__
#define BOTAN_EXCEPTION_H__

#include <botan/types.h>
#include <botan/parsing.h>
#include <exception>
#include <stdexcept>
#include <string>

namespace Botan {

typedef std::runtime_error Exception;
typedef std::invalid_argument Invalid_Argument;

/**
* Invalid_State Exception
*/
struct BOTAN_DLL Invalid_State : public Exception
	{
	Invalid_State(in string err) :
		Exception(err)
		{}
	};

/**
* Lookup_Error Exception
*/
struct BOTAN_DLL Lookup_Error : public Exception
	{
	Lookup_Error(in string err) :
		Exception(err)
		{}
	};

/**
* Internal_Error Exception
*/
struct BOTAN_DLL Internal_Error : public Exception
	{
	Internal_Error(in string err) :
		Exception("Internal error: " + err)
		{}
	};

/**
* Invalid_Key_Length Exception
*/
struct BOTAN_DLL Invalid_Key_Length : public Invalid_Argument
	{
	Invalid_Key_Length(in string name, size_t length) :
		Invalid_Argument(name + " cannot accept a key of length " +
							  std::to_string(length))
		{}
	};

/**
* Invalid_IV_Length Exception
*/
struct BOTAN_DLL Invalid_IV_Length : public Invalid_Argument
	{
	Invalid_IV_Length(in string mode, size_t bad_len) :
		Invalid_Argument("IV length " + std::to_string(bad_len) +
							  " is invalid for " + mode)
		{}
	};

/**
* PRNG_Unseeded Exception
*/
struct BOTAN_DLL PRNG_Unseeded : public Invalid_State
	{
	PRNG_Unseeded(in string algo) :
		Invalid_State("PRNG not seeded: " + algo)
		{}
	};

/**
* Policy_Violation Exception
*/
struct BOTAN_DLL Policy_Violation : public Invalid_State
	{
	Policy_Violation(in string err) :
		Invalid_State("Policy violation: " + err)
		{}
	};

/**
* Algorithm_Not_Found Exception
*/
struct BOTAN_DLL Algorithm_Not_Found : public Lookup_Error
	{
	Algorithm_Not_Found(in string name) :
		Lookup_Error("Could not find any algorithm named \"" + name + "\"")
		{}
	};

/**
* Invalid_Algorithm_Name Exception
*/
struct BOTAN_DLL Invalid_Algorithm_Name : public Invalid_Argument
	{
	Invalid_Algorithm_Name(in string name):
		Invalid_Argument("Invalid algorithm name: " + name)
		{}
	};

/**
* Encoding_Error Exception
*/
struct BOTAN_DLL Encoding_Error : public Invalid_Argument
	{
	Encoding_Error(in string name) :
		Invalid_Argument("Encoding error: " + name) {}
	};

/**
* Decoding_Error Exception
*/
struct BOTAN_DLL Decoding_Error : public Invalid_Argument
	{
	Decoding_Error(in string name) :
		Invalid_Argument("Decoding error: " + name) {}
	};

/**
* Integrity_Failure Exception
*/
struct BOTAN_DLL Integrity_Failure : public Exception
	{
	Integrity_Failure(in string msg) :
		Exception("Integrity failure: " + msg) {}
	};

/**
* Invalid_OID Exception
*/
struct BOTAN_DLL Invalid_OID : public Decoding_Error
	{
	Invalid_OID(in string oid) :
		Decoding_Error("Invalid ASN.1 OID: " + oid) {}
	};

/**
* Stream_IO_Error Exception
*/
struct BOTAN_DLL Stream_IO_Error : public Exception
	{
	Stream_IO_Error(in string err) :
		Exception("I/O error: " + err)
		{}
	};

/**
* Self Test Failure Exception
*/
struct BOTAN_DLL Self_Test_Failure : public Internal_Error
	{
	Self_Test_Failure(in string err) :
		Internal_Error("Self test failed: " + err)
		{}
	};

/**
* Memory Allocation Exception
*/
struct BOTAN_DLL Memory_Exhaustion : public std::bad_alloc
	{
	const char* what() const noexcept
		{ return "Ran out of memory, allocation failed"; }
	};

}

#endif
