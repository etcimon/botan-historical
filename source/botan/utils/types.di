/*
* Low Level Types
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

#include <botan/build.h>
#include <botan/assert.h>
#include <cstddef>
#include <stdint.h>
#include <memory>

/**
* The primary namespace for the botan library
*/using ::uint8_t;
using ::uint16_t;
using ::uint32_t;
using ::uint64_t;
using ::int32_t;

using ::size_t;

typedef uint8_t byte;
typedef uint16_t ushort;
typedef uint32_t uint;
typedef uint64_t ulong;

typedef int32_t s32bit;

/**
* A default buffer size; typically a memory page
*/
static const size_t DEFAULT_BUFFERSIZE = BOTAN_DEFAULT_BUFFER_SIZE;

/**
* The two possible directions for cipher filters, determining whether they
* actually perform encryption or decryption.
*/
enum Cipher_Dir { ENCRYPTION, DECRYPTION };

}

namespace Botan_types {

using Botan::byte;
using Botan::uint;