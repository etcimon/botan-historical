/*
* CLMUL hook
* (C) 2013 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.types;
void gcm_multiply_clmul(byte x[16], const byte H[16]);