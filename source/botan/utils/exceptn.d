/*
* Exceptions
* (C) 1999-2009 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.utils.exceptn;

import botan.utils.types;
import botan.utils.parsing;
import std.exception;
// import string;

class RangeError : Exception
{
    this(in string err)
    { super("Out of bounds: " ~ err); }
}

/**
* Invalid_Argument Exception
*/
class InvalidArgument : Exception
{
    this(in string err)
    { super("Invalid argument: " ~ err); }
}

/**
* Invalid_State Exception
*/
class InvalidState : Exception
{
    this(in string err)
    { super(err); }
}

/**
* Logic_Error Exception
*/
final class LogicError : Exception
{
    this(in string err)
    { super(err); }
}

/**
* Lookup_Error Exception
*/
final class LookupError : Exception
{
    this(in string err)
    { super(err); }
}

/**
* Internal_Error Exception
*/
class InternalError : Exception
{
    this(in string err) 
    { super("Internal error: " ~ err); }
}

/**
* Invalid_Key_Length Exception
*/
final class InvalidKeyLength : Invalid_Argument
{
    this(in string name, size_t length) {
        super(name ~ " cannot accept a key of length " ~
              to!string(length));
    }
}

/**
* Invalid_IV_Length Exception
*/
final class InvalidIVLength : Invalid_Argument
{
    this(in string mode, size_t bad_len) {
        super("IV length " ~ to!string(bad_len) ~ " is invalid for " ~ mode);
    }
}

/**
* PRNG_Unseeded Exception
*/
final class PRNGUnseeded : Invalid_State
{
    this(in string algo) {
        super("PRNG not seeded: " ~ algo);
    }
}

/**
* Policy_Violation Exception
*/
final class PolicyViolation : Invalid_State
{
    this(in string err) {
        super("TLSPolicy violation: " ~ err);
    }
}

/**
* Algorithm_Not_Found Exception
*/
final class AlgorithmNotFound : Lookup_Error
{
    this(in string name) {
        super("Could not find any algorithm named \"" ~ name ~ "\"");
    }
}

/**
* Invalid_Algorithm_Name Exception
*/
final class InvalidAlgorithmName : Invalid_Argument
{
    this(in string name) {
        super("Invalid algorithm name: " ~ name);
    }
}

/**
* Encoding_Error Exception
*/
final class EncodingError : Invalid_Argument
{
    this(in string name) {
        super("Encoding error: " ~ name);
    }
}

/**
* Decoding_Error Exception
*/
class DecodingError : Invalid_Argument
{
    this(in string name) 
    {
        super("Decoding error: " ~ name);
    }
}

/**
* Integrity_Failure Exception
*/
final class IntegrityFailure : Exception
{
    this(in string msg) {
        super("Integrity failure: " ~ msg);
    }
}

/**
* Invalid_OID Exception
*/
final class InvalidOID : Decoding_Error
{
    this(in string oid) {
        super("Invalid ASN.1 OID: " ~ oid);
    }
}

/**
* Stream_IO_Error Exception
*/
final class StreamIOError : Exception
{
    this(in string err) {
        super("I/O error: " ~ err);
    }
}

/**
* Self Test Failure Exception
*/
final class SelfTestFailure : Internal_Error
{
    this(in string err) {
        super("Self test failed: " ~ err);
    }
}

/**
* Memory Allocation Exception
*/
final class MemoryExhaustion : Exception
{
    string what() const nothrow
    { return "Ran out of memory, allocation failed"; }
}