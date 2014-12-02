module botan.utils.simd.altivec;

/*
* LDC, GDC, DMD Intrinsics for SSE 2
* (C) 2014-. Etienne Cimon
*
* Distributed under the terms of the MIT License.
*/
 
import botan.constants;
static if (BOTAN_HAS_SIMD_ALTIVEC):


import core.simd;

pure:
nothrow:
@trusted:

alias vector = byte16;

