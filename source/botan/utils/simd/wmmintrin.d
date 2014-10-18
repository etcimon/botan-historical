module botan.utils.simd.wmmintrin;

align(16) union __m128i { ubyte[16] data; };
align(8) union __m64 { ubyte[8] data; };