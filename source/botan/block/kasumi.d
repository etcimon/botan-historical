/*
* KASUMI
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.block.kasumi;

import botan.block.block_cipher;
import botan.utils.loadstor;
import botan.rotate;

/**
* KASUMI, the block cipher used in 3G telephony
*/
class KASUMI : Block_Cipher_Fixed_Params!(8, 16)
{
public:
	/*
	* KASUMI Encryption
	*/
	void encrypt_n(ubyte* input, ubyte* output, size_t blocks) const
	{
		for (size_t i = 0; i != blocks; ++i)
		{
			ushort B0 = load_be!ushort(input, 0);
			ushort B1 = load_be!ushort(input, 1);
			ushort B2 = load_be!ushort(input, 2);
			ushort B3 = load_be!ushort(input, 3);
			
			for (size_t j = 0; j != 8; j += 2)
			{
				const ushort* K = &EK[8*j];
				
				ushort R = B1 ^ (rotate_left(B0, 1) & K[0]);
				ushort L = B0 ^ (rotate_left(R, 1) | K[1]);
				
				L = FI(L ^ K[ 2], K[ 3]) ^ R;
				R = FI(R ^ K[ 4], K[ 5]) ^ L;
				L = FI(L ^ K[ 6], K[ 7]) ^ R;
				
				R = B2 ^= R;
				L = B3 ^= L;
				
				R = FI(R ^ K[10], K[11]) ^ L;
				L = FI(L ^ K[12], K[13]) ^ R;
				R = FI(R ^ K[14], K[15]) ^ L;
				
				R ^= (rotate_left(L, 1) & K[8]);
				L ^= (rotate_left(R, 1) | K[9]);
				
				B0 ^= L;
				B1 ^= R;
			}
			
			store_be(output, B0, B1, B2, B3);
			
			input += BLOCK_SIZE;
			output += BLOCK_SIZE;
		}
	}


	/*
	* KASUMI Decryption
	*/
	void decrypt_n(ubyte* input, ubyte* output, size_t blocks) const
	{
		for (size_t i = 0; i != blocks; ++i)
		{
			ushort B0 = load_be!ushort(input, 0);
			ushort B1 = load_be!ushort(input, 1);
			ushort B2 = load_be!ushort(input, 2);
			ushort B3 = load_be!ushort(input, 3);
			
			for (size_t j = 0; j != 8; j += 2)
			{
				const ushort* K = &EK[8*(6-j)];
				
				ushort L = B2, R = B3;
				
				L = FI(L ^ K[10], K[11]) ^ R;
				R = FI(R ^ K[12], K[13]) ^ L;
				L = FI(L ^ K[14], K[15]) ^ R;
				
				L ^= (rotate_left(R, 1) & K[8]);
				R ^= (rotate_left(L, 1) | K[9]);
				
				R = B0 ^= R;
				L = B1 ^= L;
				
				L ^= (rotate_left(R, 1) & K[0]);
				R ^= (rotate_left(L, 1) | K[1]);
				
				R = FI(R ^ K[2], K[3]) ^ L;
				L = FI(L ^ K[4], K[5]) ^ R;
				R = FI(R ^ K[6], K[7]) ^ L;
				
				B2 ^= L;
				B3 ^= R;
			}
			
			store_be(output, B0, B1, B2, B3);
			
			input += BLOCK_SIZE;
			output += BLOCK_SIZE;
		}
	}


	void clear()
	{
		zap(EK);
	}
	string name() const { return "KASUMI"; }
	BlockCipher clone() const { return new KASUMI; }
private:
	/*
	* KASUMI Key Schedule
	*/
	void key_schedule(in ubyte* key, size_t)
	{
		immutable ushort[] RC = { 0x0123, 0x4567, 0x89AB, 0xCDEF,
			0xFEDC, 0xBA98, 0x7654, 0x3210 };
		
		SafeVector!ushort K = SafeVector!ushort(16);
		for (size_t i = 0; i != 8; ++i)
		{
			K[i] = load_be!ushort(key, i);
			K[i+8] = K[i] ^ RC[i];
		}
		
		EK.resize(64);
		
		for (size_t i = 0; i != 8; ++i)
		{
			EK[8*i  ] = rotate_left(K[(i+0) % 8	 ], 2);
			EK[8*i+1] = rotate_left(K[(i+2) % 8 + 8], 1);
			EK[8*i+2] = rotate_left(K[(i+1) % 8	 ], 5);
			EK[8*i+3] = K[(i+4) % 8 + 8];
			EK[8*i+4] = rotate_left(K[(i+5) % 8	 ], 8);
			EK[8*i+5] = K[(i+3) % 8 + 8];
			EK[8*i+6] = rotate_left(K[(i+6) % 8	 ], 13);
			EK[8*i+7] = K[(i+7) % 8 + 8];
		}
	}


	SafeVector!ushort EK;
};


package:

/*
* KASUMI S-Boxes
*/
immutable ubyte[128] KASUMI_SBOX_S7 = [
	0x36, 0x32, 0x3E, 0x38, 0x16, 0x22, 0x5E, 0x60, 0x26, 0x06, 0x3F, 0x5D,
	0x02, 0x12, 0x7B, 0x21, 0x37, 0x71, 0x27, 0x72, 0x15, 0x43, 0x41, 0x0C,
	0x2F, 0x49, 0x2E, 0x1B, 0x19, 0x6F, 0x7C, 0x51, 0x35, 0x09, 0x79, 0x4F,
	0x34, 0x3C, 0x3A, 0x30, 0x65, 0x7F, 0x28, 0x78, 0x68, 0x46, 0x47, 0x2B,
	0x14, 0x7A, 0x48, 0x3D, 0x17, 0x6D, 0x0D, 0x64, 0x4D, 0x01, 0x10, 0x07,
	0x52, 0x0A, 0x69, 0x62, 0x75, 0x74, 0x4C, 0x0B, 0x59, 0x6A, 0x00, 0x7D,
	0x76, 0x63, 0x56, 0x45, 0x1E, 0x39, 0x7E, 0x57, 0x70, 0x33, 0x11, 0x05,
	0x5F, 0x0E, 0x5A, 0x54, 0x5B, 0x08, 0x23, 0x67, 0x20, 0x61, 0x1C, 0x42,
	0x66, 0x1F, 0x1A, 0x2D, 0x4B, 0x04, 0x55, 0x5C, 0x25, 0x4A, 0x50, 0x31,
	0x44, 0x1D, 0x73, 0x2C, 0x40, 0x6B, 0x6C, 0x18, 0x6E, 0x53, 0x24, 0x4E,
	0x2A, 0x13, 0x0F, 0x29, 0x58, 0x77, 0x3B, 0x03 ];

immutable ushort[512] KASUMI_SBOX_S9 = [
	0x00A7, 0x00EF, 0x00A1, 0x017B, 0x0187, 0x014E, 0x0009, 0x0152, 0x0026,
	0x00E2, 0x0030, 0x0166, 0x01C4, 0x0181, 0x005A, 0x018D, 0x00B7, 0x00FD,
	0x0093, 0x014B, 0x019F, 0x0154, 0x0033, 0x016A, 0x0132, 0x01F4, 0x0106,
	0x0052, 0x00D8, 0x009F, 0x0164, 0x00B1, 0x00AF, 0x00F1, 0x01E9, 0x0025,
	0x00CE, 0x0011, 0x0000, 0x014D, 0x002C, 0x00FE, 0x017A, 0x003A, 0x008F,
	0x00DC, 0x0051, 0x0190, 0x005F, 0x0003, 0x013B, 0x00F5, 0x0036, 0x00EB,
	0x00DA, 0x0195, 0x01D8, 0x0108, 0x00AC, 0x01EE, 0x0173, 0x0122, 0x018F,
	0x004C, 0x00A5, 0x00C5, 0x018B, 0x0079, 0x0101, 0x01E0, 0x01A7, 0x00D4,
	0x00F0, 0x001C, 0x01CE, 0x00B0, 0x0196, 0x01FB, 0x0120, 0x00DF, 0x01F5,
	0x0197, 0x00F9, 0x0109, 0x0059, 0x00BA, 0x00DD, 0x01AC, 0x00A4, 0x004A,
	0x01B8, 0x00C4, 0x01CA, 0x01A5, 0x015E, 0x00A3, 0x00E8, 0x009E, 0x0086,
	0x0162, 0x000D, 0x00FA, 0x01EB, 0x008E, 0x00BF, 0x0045, 0x00C1, 0x01A9,
	0x0098, 0x00E3, 0x016E, 0x0087, 0x0158, 0x012C, 0x0114, 0x00F2, 0x01B5,
	0x0140, 0x0071, 0x0116, 0x000B, 0x00F3, 0x0057, 0x013D, 0x0024, 0x005D,
	0x01F0, 0x001B, 0x01E7, 0x01BE, 0x01E2, 0x0029, 0x0044, 0x009C, 0x01C9,
	0x0083, 0x0146, 0x0193, 0x0153, 0x0014, 0x0027, 0x0073, 0x01BA, 0x007C,
	0x01DB, 0x0180, 0x01FC, 0x0035, 0x0070, 0x00AA, 0x01DF, 0x0097, 0x007E,
	0x00A9, 0x0049, 0x010C, 0x0117, 0x0141, 0x00A8, 0x016C, 0x016B, 0x0124,
	0x002E, 0x01F3, 0x0189, 0x0147, 0x0144, 0x0018, 0x01C8, 0x010B, 0x009D,
	0x01CC, 0x01E8, 0x01AA, 0x0135, 0x00E5, 0x01B7, 0x01FA, 0x00D0, 0x010F,
	0x015D, 0x0191, 0x01B2, 0x00EC, 0x0010, 0x00D1, 0x0167, 0x0034, 0x0038,
	0x0078, 0x00C7, 0x0115, 0x01D1, 0x01A0, 0x00FC, 0x011F, 0x00F6, 0x0006,
	0x0053, 0x0131, 0x01A4, 0x0159, 0x0099, 0x01F6, 0x0041, 0x003D, 0x00F4,
	0x011A, 0x00AD, 0x00DE, 0x01A2, 0x0043, 0x0182, 0x0170, 0x0105, 0x0065,
	0x01DC, 0x0123, 0x00C3, 0x01AE, 0x0031, 0x004F, 0x00A6, 0x014A, 0x0118,
	0x017F, 0x0175, 0x0080, 0x017E, 0x0198, 0x009B, 0x01EF, 0x016F, 0x0184,
	0x0112, 0x006B, 0x01CB, 0x01A1, 0x003E, 0x01C6, 0x0084, 0x00E1, 0x00CB,
	0x013C, 0x00EA, 0x000E, 0x012D, 0x005B, 0x01F7, 0x011E, 0x01A8, 0x00D3,
	0x015B, 0x0133, 0x008C, 0x0176, 0x0023, 0x0067, 0x007D, 0x01AB, 0x0013,
	0x00D6, 0x01C5, 0x0092, 0x01F2, 0x013A, 0x01BC, 0x00E6, 0x0100, 0x0149,
	0x00C6, 0x011D, 0x0032, 0x0074, 0x004E, 0x019A, 0x000A, 0x00CD, 0x01FE,
	0x00AB, 0x00E7, 0x002D, 0x008B, 0x01D3, 0x001D, 0x0056, 0x01F9, 0x0020,
	0x0048, 0x001A, 0x0156, 0x0096, 0x0139, 0x01EA, 0x01AF, 0x00EE, 0x019B,
	0x0145, 0x0095, 0x01D9, 0x0028, 0x0077, 0x00AE, 0x0163, 0x00B9, 0x00E9,
	0x0185, 0x0047, 0x01C0, 0x0111, 0x0174, 0x0037, 0x006E, 0x00B2, 0x0142,
	0x000C, 0x01D5, 0x0188, 0x0171, 0x00BE, 0x0001, 0x006D, 0x0177, 0x0089,
	0x00B5, 0x0058, 0x004B, 0x0134, 0x0104, 0x01E4, 0x0062, 0x0110, 0x0172,
	0x0113, 0x019C, 0x006F, 0x0150, 0x013E, 0x0004, 0x01F8, 0x01EC, 0x0103,
	0x0130, 0x004D, 0x0151, 0x01B3, 0x0015, 0x0165, 0x012F, 0x014C, 0x01E3,
	0x0012, 0x002F, 0x0055, 0x0019, 0x01F1, 0x01DA, 0x0121, 0x0064, 0x010D,
	0x0128, 0x01DE, 0x010E, 0x006A, 0x001F, 0x0068, 0x01B1, 0x0054, 0x019E,
	0x01E6, 0x018A, 0x0060, 0x0063, 0x009A, 0x01FF, 0x0094, 0x019D, 0x0169,
	0x0199, 0x00FF, 0x00A2, 0x00D7, 0x012E, 0x00C9, 0x010A, 0x015F, 0x0157,
	0x0090, 0x01B9, 0x016D, 0x006C, 0x012A, 0x00FB, 0x0022, 0x00B6, 0x01FD,
	0x008A, 0x00D2, 0x014F, 0x0085, 0x0137, 0x0160, 0x0148, 0x008D, 0x018C,
	0x015A, 0x007B, 0x013F, 0x01C2, 0x0119, 0x01AD, 0x00E4, 0x01BB, 0x01E1,
	0x005C, 0x0194, 0x01E5, 0x01A6, 0x00F8, 0x0129, 0x0017, 0x00D5, 0x0082,
	0x01D2, 0x0016, 0x00D9, 0x011B, 0x0046, 0x0126, 0x0168, 0x01A3, 0x007F,
	0x0138, 0x0179, 0x0007, 0x01D4, 0x00C2, 0x0002, 0x0075, 0x0127, 0x01CF,
	0x0102, 0x00E0, 0x01BF, 0x00F7, 0x00BB, 0x0050, 0x018E, 0x011C, 0x0161,
	0x0069, 0x0186, 0x012B, 0x01D7, 0x01D6, 0x00B8, 0x0039, 0x00C8, 0x015C,
	0x003F, 0x00CC, 0x00BC, 0x0021, 0x01C3, 0x0061, 0x001E, 0x0136, 0x00DB,
	0x005E, 0x00A0, 0x0081, 0x01ED, 0x0040, 0x00B3, 0x0107, 0x0066, 0x00BD,
	0x00CF, 0x0072, 0x0192, 0x01B6, 0x01DD, 0x0183, 0x007A, 0x00C0, 0x002A,
	0x017D, 0x0005, 0x0091, 0x0076, 0x00B4, 0x01C1, 0x0125, 0x0143, 0x0088,
	0x017C, 0x002B, 0x0042, 0x003C, 0x01C7, 0x0155, 0x01BD, 0x00CA, 0x01B0,
	0x0008, 0x00ED, 0x000F, 0x0178, 0x01B4, 0x01D0, 0x003B, 0x01CD ];

/*
* KASUMI FI Function
*/
ushort FI(ushort I, ushort K)
{
	ushort D9 = (I >> 7);
	ubyte D7 = (I & 0x7F);
	D9 = KASUMI_SBOX_S9[D9] ^ D7;
	D7 = KASUMI_SBOX_S7[D7] ^ (D9 & 0x7F);
	
	D7 ^= (K >> 9);
	D9 = KASUMI_SBOX_S9[D9 ^ (K & 0x1FF)] ^ D7;
	D7 = KASUMI_SBOX_S7[D7] ^ (D9 & 0x7F);
	return (D7 << 9) | D9;
}