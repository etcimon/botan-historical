/*
* Low Level Types
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.utils.types;

import botan.build;
import botan.utils.assert_;
import cstddef;
// stdint.h;
// todo:
/// memory;
/// Vector
/// HashMap
/// SafeVector
/// Deque
/// ...

/**
* The primary namespace for the botan library
Kept here to advise about equivalence between C++ and D types
typedef uint8_t ubyte;
typedef uint16_t ushort;
typedef uint32_t uint;
typedef uint64_t ulong;

typedef int32_t int;
*/

/**
* A default buffer size; typically a memory page
*/
immutable size_t DEFAULT_BUFFERSIZE = 4096;

/**
* The two possible directions for cipher filters, determining whether they
* actually perform encryption or decryption.
*/
typedef Cipher_Dir = bool;
enum : Cipher_Dir { ENCRYPTION, DECRYPTION };

