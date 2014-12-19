/*
* SAFER-SK
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.block.safer_sk;

import botan.constants;
static if (BOTAN_HAS_SAFER):

import botan.block.block_cipher;
import botan.utils.rotate;
import botan.utils.parsing;
import botan.utils.rotate;
import std.conv : to;

ubyte opCast(T : ubyte)(int val) {
    return cast(ubyte) val;
}

/**
* SAFER-SK
*/
final class SAFERSK : BlockCipherFixedParams!(8, 16), BlockCipher, SymmetricAlgorithm
{
public:

    /*
    * SAFER-SK Encryption
    */
    override void encryptN(const(ubyte)* input, ubyte* output, size_t blocks)
    {
        foreach (size_t i; 0 .. blocks)
        {
            ubyte A = input[0], B = input[1], C = input[2], D = input[3],
                E = input[4], F = input[5], G = input[6], H = input[7], X, Y;
            
            for (size_t j = 0; j != 16*m_rounds; j += 16)
            {
                A = EXP[A ^ m_EK[j  ]]; B = LOG[B + m_EK[j+1]];
                C = LOG[C + m_EK[j+2]]; D = EXP[D ^ m_EK[j+3]];
                E = EXP[E ^ m_EK[j+4]]; F = LOG[F + m_EK[j+5]];
                G = LOG[G + m_EK[j+6]]; H = EXP[H ^ m_EK[j+7]];
                
                A += m_EK[j+ 8]; B ^= m_EK[j+ 9]; C ^= m_EK[j+10]; D += m_EK[j+11];
                E += m_EK[j+12]; F ^= m_EK[j+13]; G ^= m_EK[j+14]; H += m_EK[j+15];
                
                B += A; D += C; F += E; H += G; A += B; C += D; E += F; G += H;
                C += A; G += E; D += B; H += F; A += C; E += G; B += D; F += H;
                H += D; Y = cast(ubyte)(D + H); D = cast(ubyte)(B + F); X = cast(ubyte)(B + D); B = cast(ubyte)(A + E);
                A += B; F = cast(ubyte)(C + G); E = cast(ubyte)(C + F); C = X; G = Y;
            }
            
            output[0] = A ^ m_EK[16*m_rounds+0]; output[1] = cast(ubyte) (B + m_EK[16*m_rounds+1]);
            output[2] = cast(ubyte) (C + m_EK[16*m_rounds+2]); output[3] = D ^ m_EK[16*m_rounds+3];
            output[4] = E ^ m_EK[16*m_rounds+4]; output[5] = cast(ubyte) (F + m_EK[16*m_rounds+5]);
            output[6] = cast(ubyte) (G + m_EK[16*m_rounds+6]); output[7] = H ^ m_EK[16*m_rounds+7];
            
            input += BLOCK_SIZE;
            output += BLOCK_SIZE;
        }
    }

    /*
    * SAFER-SK Decryption
    */
    override void decryptN(const(ubyte)* input, ubyte* output, size_t blocks)
    {
        foreach (size_t i; 0 .. blocks)
        {
            ubyte A = input[0], B = input[1], C = input[2], D = input[3],
                E = input[4], F = input[5], G = input[6], H = input[7];
            
            A ^= m_EK[16*m_rounds+0]; B -= m_EK[16*m_rounds+1]; C -= m_EK[16*m_rounds+2];
            D ^= m_EK[16*m_rounds+3]; E ^= m_EK[16*m_rounds+4]; F -= m_EK[16*m_rounds+5];
            G -= m_EK[16*m_rounds+6]; H ^= m_EK[16*m_rounds+7];
            
            for (size_t j = 16*(m_rounds-1); j >= 0; j -= 16)
            {
                ubyte T = E; E = B; B = C; C = T; T = F; F = D; D = G; G = T;
                A -= E; B -= F; C -= G; D -= H; E -= A; F -= B; G -= C; H -= D;
                A -= C; E -= G; B -= D; F -= H; C -= A; G -= E; D -= B; H -= F;
                A -= B; C -= D; E -= F; G -= H; B -= A; D -= C; F -= E; H -= G;
                
                A = LOG[A - m_EK[j+8 ] + 256]; B = EXP[B ^ m_EK[j+9 ]];
                C = EXP[C ^ m_EK[j+10]];         D = LOG[D - m_EK[j+11] + 256];
                E = LOG[E - m_EK[j+12] + 256]; F = EXP[F ^ m_EK[j+13]];
                G = EXP[G ^ m_EK[j+14]];         H = LOG[H - m_EK[j+15] + 256];
                
                A ^= m_EK[j+0]; B -= m_EK[j+1]; C -= m_EK[j+2]; D ^= m_EK[j+3];
                E ^= m_EK[j+4]; F -= m_EK[j+5]; G -= m_EK[j+6]; H ^= m_EK[j+7];
            }
            
            output[0] = A; output[1] = B; output[2] = C; output[3] = D;
            output[4] = E; output[5] = F; output[6] = G; output[7] = H;
            
            input += BLOCK_SIZE;
            output += BLOCK_SIZE;
        }
    }

    void clear()
    {
        zap(m_EK);
    }

    /*
    * Return the name of this type
    */
    override @property string name() const
    {
        return "SAFER-SK(" ~ to!string(m_rounds) ~ ")";
    }

    /*
    * Return a clone of this object
    */
    override BlockCipher clone() const
    {
        return new SAFERSK(m_rounds);
    }

    /**
    * @param rounds = the number of rounds to use - must be between 1
    * and 13
    */
    this(size_t r)
    {
        m_rounds = r;
        if (m_rounds > 13 || m_rounds == 0)
            throw new InvalidArgument(name ~ ": Invalid number of rounds");
    }

    override @property size_t parallelism() const { return 1; }
protected:
    /*
    * SAFER-SK Key Schedule
    */
    override void keySchedule(const(ubyte)* key, size_t)
    {
        __gshared immutable ubyte[208] BIAS = [
            0x16, 0x73, 0x3B, 0x1E, 0x8E, 0x70, 0xBD, 0x86, 0x47, 0x7E, 0x24, 0x56,
            0xF1, 0x77, 0x88, 0x46, 0xB1, 0xBA, 0xA3, 0xB7, 0x10, 0x0A, 0xC5, 0x37,
            0xC9, 0x5A, 0x28, 0xAC, 0x64, 0xA5, 0xEC, 0xAB, 0xC6, 0x67, 0x95, 0x58,
            0x0D, 0xF8, 0x9A, 0xF6, 0x66, 0xDC, 0x05, 0x3D, 0xD3, 0x8A, 0xC3, 0xD8,
            0x6A, 0xE9, 0x36, 0x49, 0x43, 0xBF, 0xEB, 0xD4, 0x9B, 0x68, 0xA0, 0x65,
            0x5D, 0x57, 0x92, 0x1F, 0x71, 0x5C, 0xBB, 0x22, 0xC1, 0xBE, 0x7B, 0xBC,
            0x63, 0x94, 0x5F, 0x2A, 0x61, 0xB8, 0x34, 0x32, 0xFD, 0xFB, 0x17, 0x40,
            0xE6, 0x51, 0x1D, 0x41, 0x8F, 0x29, 0xDD, 0x04, 0x80, 0xDE, 0xE7, 0x31,
            0x7F, 0x01, 0xA2, 0xF7, 0x39, 0xDA, 0x6F, 0x23, 0xFE, 0x3A, 0xD0, 0x1C,
            0xD1, 0x30, 0x3E, 0x12, 0xCD, 0x0F, 0xE0, 0xA8, 0xAF, 0x82, 0x59, 0x2C,
            0x7D, 0xAD, 0xB2, 0xEF, 0xC2, 0x87, 0xCE, 0x75, 0x13, 0x02, 0x90, 0x4F,
            0x2E, 0x72, 0x33, 0x85, 0x8D, 0xCF, 0xA9, 0x81, 0xE2, 0xC4, 0x27, 0x2F,
            0x7A, 0x9F, 0x52, 0xE1, 0x15, 0x38, 0x2B, 0xFC, 0x42, 0xC7, 0x08, 0xE4,
            0x09, 0x55, 0x5E, 0x8C, 0x76, 0x60, 0xFF, 0xDF, 0xD7, 0x98, 0xFA, 0x0B,
            0x00, 0x1A, 0xF9, 0xA6, 0xB9, 0xE8, 0x9E, 0x62, 0xD9, 0x91, 0x50, 0xD2,
            0xEE, 0x18, 0xB4, 0x07, 0xEA, 0x5B, 0xA4, 0xC8, 0x0E, 0xCB, 0x48, 0x69,
            0x4E, 0x9C, 0x35, 0x79, 0x45, 0x4D, 0x54, 0xE5, 0x3C, 0x0C, 0x4A, 0x8B,
            0x3F, 0xCC, 0xA7, 0xDB ];
        
        __gshared immutable ubyte[208] KEY_INDEX = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10, 0x11, 0x09, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x00, 0x01,
            0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x09, 0x0A, 0x0B, 0x05, 0x06, 0x07, 0x08,
            0x00, 0x01, 0x02, 0x03, 0x0F, 0x10, 0x11, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x07, 0x08, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x11, 0x09, 0x0A, 0x0B,
            0x0C, 0x0D, 0x0E, 0x0F, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x02, 0x03, 0x04, 0x05,
            0x06, 0x07, 0x08, 0x00, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x09, 0x0A,
            0x04, 0x05, 0x06, 0x07, 0x08, 0x00, 0x01, 0x02, 0x0E, 0x0F, 0x10, 0x11,
            0x09, 0x0A, 0x0B, 0x0C, 0x06, 0x07, 0x08, 0x00, 0x01, 0x02, 0x03, 0x04,
            0x10, 0x11, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x08, 0x00, 0x01, 0x02,
            0x03, 0x04, 0x05, 0x06, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10, 0x11, 0x09, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x00, 0x01,
            0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x09, 0x0A, 0x0B, 0x05, 0x06, 0x07, 0x08,
            0x00, 0x01, 0x02, 0x03, 0x0F, 0x10, 0x11, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x07, 0x08, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x11, 0x09, 0x0A, 0x0B,
            0x0C, 0x0D, 0x0E, 0x0F ];
        
        m_EK.resize(16 * m_rounds + 8);
        
        SecureVector!ubyte KB = SecureVector!ubyte(18);
        
        foreach (size_t i; 0 .. 8)
        {
            KB[i] = rotateLeft(key[i], 5);
            KB[ 8] ^= KB[i];
            m_EK[i] = key[i+8];
            KB[i+9] = m_EK[i];
            KB[17] ^= KB[i+9];
        }
        
        foreach (size_t i; 0 .. m_rounds)
        {
            foreach (size_t j; 0 .. 18)
                KB[j] = rotateLeft(KB[j], 6);
            foreach (size_t j; 0 .. 16)
                m_EK[16*i+j+8] = cast(ubyte)(KB[KEY_INDEX[16*i+j]] + BIAS[16*i+j]);
        }
    }


    size_t m_rounds;
    SecureVector!ubyte m_EK;
}

private:

__gshared immutable ubyte[256] EXP = [
    0x01, 0x2D, 0xE2, 0x93, 0xBE, 0x45, 0x15, 0xAE, 0x78, 0x03, 0x87, 0xA4,
    0xB8, 0x38, 0xCF, 0x3F, 0x08, 0x67, 0x09, 0x94, 0xEB, 0x26, 0xA8, 0x6B,
    0xBD, 0x18, 0x34, 0x1B, 0xBB, 0xBF, 0x72, 0xF7, 0x40, 0x35, 0x48, 0x9C,
    0x51, 0x2F, 0x3B, 0x55, 0xE3, 0xC0, 0x9F, 0xD8, 0xD3, 0xF3, 0x8D, 0xB1,
    0xFF, 0xA7, 0x3E, 0xDC, 0x86, 0x77, 0xD7, 0xA6, 0x11, 0xFB, 0xF4, 0xBA,
    0x92, 0x91, 0x64, 0x83, 0xF1, 0x33, 0xEF, 0xDA, 0x2C, 0xB5, 0xB2, 0x2B,
    0x88, 0xD1, 0x99, 0xCB, 0x8C, 0x84, 0x1D, 0x14, 0x81, 0x97, 0x71, 0xCA,
    0x5F, 0xA3, 0x8B, 0x57, 0x3C, 0x82, 0xC4, 0x52, 0x5C, 0x1C, 0xE8, 0xA0,
    0x04, 0xB4, 0x85, 0x4A, 0xF6, 0x13, 0x54, 0xB6, 0xDF, 0x0C, 0x1A, 0x8E,
    0xDE, 0xE0, 0x39, 0xFC, 0x20, 0x9B, 0x24, 0x4E, 0xA9, 0x98, 0x9E, 0xAB,
    0xF2, 0x60, 0xD0, 0x6C, 0xEA, 0xFA, 0xC7, 0xD9, 0x00, 0xD4, 0x1F, 0x6E,
    0x43, 0xBC, 0xEC, 0x53, 0x89, 0xFE, 0x7A, 0x5D, 0x49, 0xC9, 0x32, 0xC2,
    0xF9, 0x9A, 0xF8, 0x6D, 0x16, 0xDB, 0x59, 0x96, 0x44, 0xE9, 0xCD, 0xE6,
    0x46, 0x42, 0x8F, 0x0A, 0xC1, 0xCC, 0xB9, 0x65, 0xB0, 0xD2, 0xC6, 0xAC,
    0x1E, 0x41, 0x62, 0x29, 0x2E, 0x0E, 0x74, 0x50, 0x02, 0x5A, 0xC3, 0x25,
    0x7B, 0x8A, 0x2A, 0x5B, 0xF0, 0x06, 0x0D, 0x47, 0x6F, 0x70, 0x9D, 0x7E,
    0x10, 0xCE, 0x12, 0x27, 0xD5, 0x4C, 0x4F, 0xD6, 0x79, 0x30, 0x68, 0x36,
    0x75, 0x7D, 0xE4, 0xED, 0x80, 0x6A, 0x90, 0x37, 0xA2, 0x5E, 0x76, 0xAA,
    0xC5, 0x7F, 0x3D, 0xAF, 0xA5, 0xE5, 0x19, 0x61, 0xFD, 0x4D, 0x7C, 0xB7,
    0x0B, 0xEE, 0xAD, 0x4B, 0x22, 0xF5, 0xE7, 0x73, 0x23, 0x21, 0xC8, 0x05,
    0xE1, 0x66, 0xDD, 0xB3, 0x58, 0x69, 0x63, 0x56, 0x0F, 0xA1, 0x31, 0x95,
    0x17, 0x07, 0x3A, 0x28 ];

__gshared immutable ubyte[512] LOG = [
    0x80, 0x00, 0xB0, 0x09, 0x60, 0xEF, 0xB9, 0xFD, 0x10, 0x12, 0x9F, 0xE4,
    0x69, 0xBA, 0xAD, 0xF8, 0xC0, 0x38, 0xC2, 0x65, 0x4F, 0x06, 0x94, 0xFC,
    0x19, 0xDE, 0x6A, 0x1B, 0x5D, 0x4E, 0xA8, 0x82, 0x70, 0xED, 0xE8, 0xEC,
    0x72, 0xB3, 0x15, 0xC3, 0xFF, 0xAB, 0xB6, 0x47, 0x44, 0x01, 0xAC, 0x25,
    0xC9, 0xFA, 0x8E, 0x41, 0x1A, 0x21, 0xCB, 0xD3, 0x0D, 0x6E, 0xFE, 0x26,
    0x58, 0xDA, 0x32, 0x0F, 0x20, 0xA9, 0x9D, 0x84, 0x98, 0x05, 0x9C, 0xBB,
    0x22, 0x8C, 0x63, 0xE7, 0xC5, 0xE1, 0x73, 0xC6, 0xAF, 0x24, 0x5B, 0x87,
    0x66, 0x27, 0xF7, 0x57, 0xF4, 0x96, 0xB1, 0xB7, 0x5C, 0x8B, 0xD5, 0x54,
    0x79, 0xDF, 0xAA, 0xF6, 0x3E, 0xA3, 0xF1, 0x11, 0xCA, 0xF5, 0xD1, 0x17,
    0x7B, 0x93, 0x83, 0xBC, 0xBD, 0x52, 0x1E, 0xEB, 0xAE, 0xCC, 0xD6, 0x35,
    0x08, 0xC8, 0x8A, 0xB4, 0xE2, 0xCD, 0xBF, 0xD9, 0xD0, 0x50, 0x59, 0x3F,
    0x4D, 0x62, 0x34, 0x0A, 0x48, 0x88, 0xB5, 0x56, 0x4C, 0x2E, 0x6B, 0x9E,
    0xD2, 0x3D, 0x3C, 0x03, 0x13, 0xFB, 0x97, 0x51, 0x75, 0x4A, 0x91, 0x71,
    0x23, 0xBE, 0x76, 0x2A, 0x5F, 0xF9, 0xD4, 0x55, 0x0B, 0xDC, 0x37, 0x31,
    0x16, 0x74, 0xD7, 0x77, 0xA7, 0xE6, 0x07, 0xDB, 0xA4, 0x2F, 0x46, 0xF3,
    0x61, 0x45, 0x67, 0xE3, 0x0C, 0xA2, 0x3B, 0x1C, 0x85, 0x18, 0x04, 0x1D,
    0x29, 0xA0, 0x8F, 0xB2, 0x5A, 0xD8, 0xA6, 0x7E, 0xEE, 0x8D, 0x53, 0x4B,
    0xA1, 0x9A, 0xC1, 0x0E, 0x7A, 0x49, 0xA5, 0x2C, 0x81, 0xC4, 0xC7, 0x36,
    0x2B, 0x7F, 0x43, 0x95, 0x33, 0xF2, 0x6C, 0x68, 0x6D, 0xF0, 0x02, 0x28,
    0xCE, 0xDD, 0x9B, 0xEA, 0x5E, 0x99, 0x7C, 0x14, 0x86, 0xCF, 0xE5, 0x42,
    0xB8, 0x40, 0x78, 0x2D, 0x3A, 0xE9, 0x64, 0x1F, 0x92, 0x90, 0x7D, 0x39,
    0x6F, 0xE0, 0x89, 0x30, 0x80, 0x00, 0xB0, 0x09, 0x60, 0xEF, 0xB9, 0xFD,
    0x10, 0x12, 0x9F, 0xE4, 0x69, 0xBA, 0xAD, 0xF8, 0xC0, 0x38, 0xC2, 0x65,
    0x4F, 0x06, 0x94, 0xFC, 0x19, 0xDE, 0x6A, 0x1B, 0x5D, 0x4E, 0xA8, 0x82,
    0x70, 0xED, 0xE8, 0xEC, 0x72, 0xB3, 0x15, 0xC3, 0xFF, 0xAB, 0xB6, 0x47,
    0x44, 0x01, 0xAC, 0x25, 0xC9, 0xFA, 0x8E, 0x41, 0x1A, 0x21, 0xCB, 0xD3,
    0x0D, 0x6E, 0xFE, 0x26, 0x58, 0xDA, 0x32, 0x0F, 0x20, 0xA9, 0x9D, 0x84,
    0x98, 0x05, 0x9C, 0xBB, 0x22, 0x8C, 0x63, 0xE7, 0xC5, 0xE1, 0x73, 0xC6,
    0xAF, 0x24, 0x5B, 0x87, 0x66, 0x27, 0xF7, 0x57, 0xF4, 0x96, 0xB1, 0xB7,
    0x5C, 0x8B, 0xD5, 0x54, 0x79, 0xDF, 0xAA, 0xF6, 0x3E, 0xA3, 0xF1, 0x11,
    0xCA, 0xF5, 0xD1, 0x17, 0x7B, 0x93, 0x83, 0xBC, 0xBD, 0x52, 0x1E, 0xEB,
    0xAE, 0xCC, 0xD6, 0x35, 0x08, 0xC8, 0x8A, 0xB4, 0xE2, 0xCD, 0xBF, 0xD9,
    0xD0, 0x50, 0x59, 0x3F, 0x4D, 0x62, 0x34, 0x0A, 0x48, 0x88, 0xB5, 0x56,
    0x4C, 0x2E, 0x6B, 0x9E, 0xD2, 0x3D, 0x3C, 0x03, 0x13, 0xFB, 0x97, 0x51,
    0x75, 0x4A, 0x91, 0x71, 0x23, 0xBE, 0x76, 0x2A, 0x5F, 0xF9, 0xD4, 0x55,
    0x0B, 0xDC, 0x37, 0x31, 0x16, 0x74, 0xD7, 0x77, 0xA7, 0xE6, 0x07, 0xDB,
    0xA4, 0x2F, 0x46, 0xF3, 0x61, 0x45, 0x67, 0xE3, 0x0C, 0xA2, 0x3B, 0x1C,
    0x85, 0x18, 0x04, 0x1D, 0x29, 0xA0, 0x8F, 0xB2, 0x5A, 0xD8, 0xA6, 0x7E,
    0xEE, 0x8D, 0x53, 0x4B, 0xA1, 0x9A, 0xC1, 0x0E, 0x7A, 0x49, 0xA5, 0x2C,
    0x81, 0xC4, 0xC7, 0x36, 0x2B, 0x7F, 0x43, 0x95, 0x33, 0xF2, 0x6C, 0x68,
    0x6D, 0xF0, 0x02, 0x28, 0xCE, 0xDD, 0x9B, 0xEA, 0x5E, 0x99, 0x7C, 0x14,
    0x86, 0xCF, 0xE5, 0x42, 0xB8, 0x40, 0x78, 0x2D, 0x3A, 0xE9, 0x64, 0x1F,
    0x92, 0x90, 0x7D, 0x39, 0x6F, 0xE0, 0x89, 0x30 ];