/*
* CLMUL hook
* (C) 2013 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#define BOTAN_GCM_CLMUL_H__

#include <botan/types.h>
void gcm_multiply_clmul(byte x[16], const byte H[16]);