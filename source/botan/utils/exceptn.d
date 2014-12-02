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

class Range_Error : Exception
{
    this(in string err)
    { super("Out of bounds: " ~ err); }
}

/**
* Invalid_Argument Exception
*/
class Invalid_Argument : Exception
{
    this(in string err)
    { super("Invalid argument: " ~ err); }
}

/**
* Invalid_State Exception
*/
class Invalid_State : Exception
{
    this(in string err)
    { super(err); }
}

/**
* Logic_Error Exception
*/
final class Logic_Error : Exception
{
    this(in string err)
    { super(err); }
}

/**
* Lookup_Error Exception
*/
final class Lookup_Error : Exception
{
    this(in string err)
    { super(err); }
}

/**
* Internal_Error Exception
*/
class Internal_Error : Exception
{
    this(in string err) 
    { super("Internal error: " ~ err); }
}

/**
* Invalid_Key_Length Exception
*/
final class Invalid_Key_Length : Invalid_Argument
{
    this(in string name, size_t length) {
        super(name ~ " cannot accept a key of length " ~
              to!string(length));
    }
}

/**
* Invalid_IV_Length Exception
*/
final class Invalid_IV_Length : Invalid_Argument
{
    this(in string mode, size_t bad_len) {
        super("IV length " ~ to!string(bad_len) ~ " is invalid for " ~ mode);
    }
}

/**
* PRNG_Unseeded Exception
*/
final class PRNG_Unseeded : Invalid_State
{
    this(in string algo) {
        super("PRNG not seeded: " ~ algo);
    }
}

/**
* Policy_Violation Exception
*/
final class Policy_Violation : Invalid_State
{
    this(in string err) {
        super("TLS_Policy violation: " ~ err);
    }
}

/**
* Algorithm_Not_Found Exception
*/
final class Algorithm_Not_Found : Lookup_Error
{
    this(in string name) {
        super("Could not find any algorithm named \"" ~ name ~ "\"");
    }
}

/**
* Invalid_Algorithm_Name Exception
*/
final class Invalid_Algorithm_Name : Invalid_Argument
{
    this(in string name) {
        super("Invalid algorithm name: " ~ name);
    }
}

/**
* Encoding_Error Exception
*/
final class Encoding_Error : Invalid_Argument
{
    this(in string name) {
        super("Encoding error: " ~ name);
    }
}

/**
* Decoding_Error Exception
*/
class Decoding_Error : Invalid_Argument
{
    this(in string name) 
    {
        super("Decoding error: " ~ name);
    }
}

/**
* Integrity_Failure Exception
*/
final class Integrity_Failure : Exception
{
    this(in string msg) {
        super("Integrity failure: " ~ msg);
    }
}

/**
* Invalid_OID Exception
*/
final class Invalid_OID : Decoding_Error
{
    this(in string oid) {
        super("Invalid ASN.1 OID: " ~ oid);
    }
}

/**
* Stream_IO_Error Exception
*/
final class Stream_IO_Error : Exception
{
    this(in string err) {
        super("I/O error: " ~ err);
    }
}

/**
* Self Test Failure Exception
*/
final class Self_Test_Failure : Internal_Error
{
    this(in string err) {
        super("Self test failed: " ~ err);
    }
}

/**
* Memory Allocation Exception
*/
final class Memory_Exhaustion : Exception
{
    string what() const nothrow
    { return "Ran out of memory, allocation failed"; }
}