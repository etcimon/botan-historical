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
public import botan.utils.memory;
public import std.typecons : scoped;

alias Scoped(T) = typeof(scoped!T());

immutable size_t DEFAULT_BUFFERSIZE = 4096;

/**
* The two possible directions for cipher filters, determining whether they
* actually perform encryption or decryption.
*/
typedef Cipher_Dir = bool;
enum : Cipher_Dir { ENCRYPTION, DECRYPTION };

