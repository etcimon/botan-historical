/*
* CAST-128
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.block.cast128;

import botan.constants;
static if (BOTAN_HAS_CAST):

import botan.block.block_cipher;
import botan.block.cast_sboxes;
import botan.utils.loadstor;
import botan.utils.rotate;
import botan.utils.types;

/**
* CAST-128
*/
final class CAST128 : BlockCipherFixedParams!(8, 11, 16), SymmetricAlgorithm
{
public:
    /*
    * CAST-128 Encryption
    */
    override void encryptN(ubyte* input, ubyte* output, size_t blocks) const
    {
        foreach (size_t i; 0 .. blocks)
        {
            uint L = loadBigEndian!uint(input, 0);
            uint R = loadBigEndian!uint(input, 1);
            
            R1(L, R, m_MK[ 0], m_RK[ 0]);
            R2(R, L, m_MK[ 1], m_RK[ 1]);
            R3(L, R, m_MK[ 2], m_RK[ 2]);
            R1(R, L, m_MK[ 3], m_RK[ 3]);
            R2(L, R, m_MK[ 4], m_RK[ 4]);
            R3(R, L, m_MK[ 5], m_RK[ 5]);
            R1(L, R, m_MK[ 6], m_RK[ 6]);
            R2(R, L, m_MK[ 7], m_RK[ 7]);
            R3(L, R, m_MK[ 8], m_RK[ 8]);
            R1(R, L, m_MK[ 9], m_RK[ 9]);
            R2(L, R, m_MK[10], m_RK[10]);
            R3(R, L, m_MK[11], m_RK[11]);
            R1(L, R, m_MK[12], m_RK[12]);
            R2(R, L, m_MK[13], m_RK[13]);
            R3(L, R, m_MK[14], m_RK[14]);
            R1(R, L, m_MK[15], m_RK[15]);
            
            storeBigEndian(output, R, L);
            
            input += BLOCK_SIZE;
            output += BLOCK_SIZE;
        }
    }

    /*
    * CAST-128 Decryption
    */
    override void decryptN(ubyte* input, ubyte* output, size_t blocks) const
    {
        foreach (size_t i; 0 .. blocks)
        {
            uint L = loadBigEndian!uint(input, 0);
            uint R = loadBigEndian!uint(input, 1);
            
            R1(L, R, m_MK[15], m_RK[15]);
            R3(R, L, m_MK[14], m_RK[14]);
            R2(L, R, m_MK[13], m_RK[13]);
            R1(R, L, m_MK[12], m_RK[12]);
            R3(L, R, m_MK[11], m_RK[11]);
            R2(R, L, m_MK[10], m_RK[10]);
            R1(L, R, m_MK[ 9], m_RK[ 9]);
            R3(R, L, m_MK[ 8], m_RK[ 8]);
            R2(L, R, m_MK[ 7], m_RK[ 7]);
            R1(R, L, m_MK[ 6], m_RK[ 6]);
            R3(L, R, m_MK[ 5], m_RK[ 5]);
            R2(R, L, m_MK[ 4], m_RK[ 4]);
            R1(L, R, m_MK[ 3], m_RK[ 3]);
            R3(R, L, m_MK[ 2], m_RK[ 2]);
            R2(L, R, m_MK[ 1], m_RK[ 1]);
            R1(R, L, m_MK[ 0], m_RK[ 0]);
            
            storeBigEndian(output, R, L);
            
            input += BLOCK_SIZE;
            output += BLOCK_SIZE;
        }
    }


    override void clear()
    {
        zap(m_MK);
        zap(m_RK);
    }

    @property string name() const { return "CAST-128"; }
    override @property size_t parallelism() const { return 1; }
    override BlockCipher clone() const { return new CAST128; }

protected:
    /*
    * CAST-128 Key Schedule
    */
    override void keySchedule(in ubyte* key, size_t length)
    {

        m_MK.reserve(48);
        m_RK.reserve(48);
        
        SecureVector!uint X = SecureVector!uint(4);
        foreach (size_t i; 0 .. length)
            X[i/4] = (X[i/4] << 8) + key[i];
        
        cast_ks(m_MK, X);
        
        SecureVector!uint RK32 = SecureVector!uint(48);
        cast_ks(RK32, X);
        
        foreach (size_t i; 0 .. 16)
            m_RK[i] = RK32[i] % 32;
    }

private:
    /*
    * S-Box Based Key Expansion
    */
    static void cast_ks(ref SecureVector!uint K,
                        ref SecureVector!uint X)
    {
        __gshared immutable uint[256] S5 = [
            0x7EC90C04, 0x2C6E74B9, 0x9B0E66DF, 0xA6337911, 0xB86A7FFF, 0x1DD358F5,
            0x44DD9D44, 0x1731167F, 0x08FBF1FA, 0xE7F511CC, 0xD2051B00, 0x735ABA00,
            0x2AB722D8, 0x386381CB, 0xACF6243A, 0x69BEFD7A, 0xE6A2E77F, 0xF0C720CD,
            0xC4494816, 0xCCF5C180, 0x38851640, 0x15B0A848, 0xE68B18CB, 0x4CAADEFF,
            0x5F480A01, 0x0412B2AA, 0x259814FC, 0x41D0EFE2, 0x4E40B48D, 0x248EB6FB,
            0x8DBA1CFE, 0x41A99B02, 0x1A550A04, 0xBA8F65CB, 0x7251F4E7, 0x95A51725,
            0xC106ECD7, 0x97A5980A, 0xC539B9AA, 0x4D79FE6A, 0xF2F3F763, 0x68AF8040,
            0xED0C9E56, 0x11B4958B, 0xE1EB5A88, 0x8709E6B0, 0xD7E07156, 0x4E29FEA7,
            0x6366E52D, 0x02D1C000, 0xC4AC8E05, 0x9377F571, 0x0C05372A, 0x578535F2,
            0x2261BE02, 0xD642A0C9, 0xDF13A280, 0x74B55BD2, 0x682199C0, 0xD421E5EC,
            0x53FB3CE8, 0xC8ADEDB3, 0x28A87FC9, 0x3D959981, 0x5C1FF900, 0xFE38D399,
            0x0C4EFF0B, 0x062407EA, 0xAA2F4FB1, 0x4FB96976, 0x90C79505, 0xB0A8A774,
            0xEF55A1FF, 0xE59CA2C2, 0xA6B62D27, 0xE66A4263, 0xDF65001F, 0x0EC50966,
            0xDFDD55BC, 0x29DE0655, 0x911E739A, 0x17AF8975, 0x32C7911C, 0x89F89468,
            0x0D01E980, 0x524755F4, 0x03B63CC9, 0x0CC844B2, 0xBCF3F0AA, 0x87AC36E9,
            0xE53A7426, 0x01B3D82B, 0x1A9E7449, 0x64EE2D7E, 0xCDDBB1DA, 0x01C94910,
            0xB868BF80, 0x0D26F3FD, 0x9342EDE7, 0x04A5C284, 0x636737B6, 0x50F5B616,
            0xF24766E3, 0x8ECA36C1, 0x136E05DB, 0xFEF18391, 0xFB887A37, 0xD6E7F7D4,
            0xC7FB7DC9, 0x3063FCDF, 0xB6F589DE, 0xEC2941DA, 0x26E46695, 0xB7566419,
            0xF654EFC5, 0xD08D58B7, 0x48925401, 0xC1BACB7F, 0xE5FF550F, 0xB6083049,
            0x5BB5D0E8, 0x87D72E5A, 0xAB6A6EE1, 0x223A66CE, 0xC62BF3CD, 0x9E0885F9,
            0x68CB3E47, 0x086C010F, 0xA21DE820, 0xD18B69DE, 0xF3F65777, 0xFA02C3F6,
            0x407EDAC3, 0xCBB3D550, 0x1793084D, 0xB0D70EBA, 0x0AB378D5, 0xD951FB0C,
            0xDED7DA56, 0x4124BBE4, 0x94CA0B56, 0x0F5755D1, 0xE0E1E56E, 0x6184B5BE,
            0x580A249F, 0x94F74BC0, 0xE327888E, 0x9F7B5561, 0xC3DC0280, 0x05687715,
            0x646C6BD7, 0x44904DB3, 0x66B4F0A3, 0xC0F1648A, 0x697ED5AF, 0x49E92FF6,
            0x309E374F, 0x2CB6356A, 0x85808573, 0x4991F840, 0x76F0AE02, 0x083BE84D,
            0x28421C9A, 0x44489406, 0x736E4CB8, 0xC1092910, 0x8BC95FC6, 0x7D869CF4,
            0x134F616F, 0x2E77118D, 0xB31B2BE1, 0xAA90B472, 0x3CA5D717, 0x7D161BBA,
            0x9CAD9010, 0xAF462BA2, 0x9FE459D2, 0x45D34559, 0xD9F2DA13, 0xDBC65487,
            0xF3E4F94E, 0x176D486F, 0x097C13EA, 0x631DA5C7, 0x445F7382, 0x175683F4,
            0xCDC66A97, 0x70BE0288, 0xB3CDCF72, 0x6E5DD2F3, 0x20936079, 0x459B80A5,
            0xBE60E2DB, 0xA9C23101, 0xEBA5315C, 0x224E42F2, 0x1C5C1572, 0xF6721B2C,
            0x1AD2FFF3, 0x8C25404E, 0x324ED72F, 0x4067B7FD, 0x0523138E, 0x5CA3BC78,
            0xDC0FD66E, 0x75922283, 0x784D6B17, 0x58EBB16E, 0x44094F85, 0x3F481D87,
            0xFCFEAE7B, 0x77B5FF76, 0x8C2302BF, 0xAAF47556, 0x5F46B02A, 0x2B092801,
            0x3D38F5F7, 0x0CA81F36, 0x52AF4A8A, 0x66D5E7C0, 0xDF3B0874, 0x95055110,
            0x1B5AD7A8, 0xF61ED5AD, 0x6CF6E479, 0x20758184, 0xD0CEFA65, 0x88F7BE58,
            0x4A046826, 0x0FF6F8F3, 0xA09C7F70, 0x5346ABA0, 0x5CE96C28, 0xE176EDA3,
            0x6BAC307F, 0x376829D2, 0x85360FA9, 0x17E3FE2A, 0x24B79767, 0xF5A96B20,
            0xD6CD2595, 0x68FF1EBF, 0x7555442C, 0xF19F06BE, 0xF9E0659A, 0xEEB9491D,
            0x34010718, 0xBB30CAB8, 0xE822FE15, 0x88570983, 0x750E6249, 0xDA627E55,
            0x5E76FFA8, 0xB1534546, 0x6D47DE08, 0xEFE9E7D4 ];
        
        __gshared immutable uint[256] S6 = [
            0xF6FA8F9D, 0x2CAC6CE1, 0x4CA34867, 0xE2337F7C, 0x95DB08E7, 0x016843B4,
            0xECED5CBC, 0x325553AC, 0xBF9F0960, 0xDFA1E2ED, 0x83F0579D, 0x63ED86B9,
            0x1AB6A6B8, 0xDE5EBE39, 0xF38FF732, 0x8989B138, 0x33F14961, 0xC01937BD,
            0xF506C6DA, 0xE4625E7E, 0xA308EA99, 0x4E23E33C, 0x79CBD7CC, 0x48A14367,
            0xA3149619, 0xFEC94BD5, 0xA114174A, 0xEAA01866, 0xA084DB2D, 0x09A8486F,
            0xA888614A, 0x2900AF98, 0x01665991, 0xE1992863, 0xC8F30C60, 0x2E78EF3C,
            0xD0D51932, 0xCF0FEC14, 0xF7CA07D2, 0xD0A82072, 0xFD41197E, 0x9305A6B0,
            0xE86BE3DA, 0x74BED3CD, 0x372DA53C, 0x4C7F4448, 0xDAB5D440, 0x6DBA0EC3,
            0x083919A7, 0x9FBAEED9, 0x49DBCFB0, 0x4E670C53, 0x5C3D9C01, 0x64BDB941,
            0x2C0E636A, 0xBA7DD9CD, 0xEA6F7388, 0xE70BC762, 0x35F29ADB, 0x5C4CDD8D,
            0xF0D48D8C, 0xB88153E2, 0x08A19866, 0x1AE2EAC8, 0x284CAF89, 0xAA928223,
            0x9334BE53, 0x3B3A21BF, 0x16434BE3, 0x9AEA3906, 0xEFE8C36E, 0xF890CDD9,
            0x80226DAE, 0xC340A4A3, 0xDF7E9C09, 0xA694A807, 0x5B7C5ECC, 0x221DB3A6,
            0x9A69A02F, 0x68818A54, 0xCEB2296F, 0x53C0843A, 0xFE893655, 0x25BFE68A,
            0xB4628ABC, 0xCF222EBF, 0x25AC6F48, 0xA9A99387, 0x53BDDB65, 0xE76FFBE7,
            0xE967FD78, 0x0BA93563, 0x8E342BC1, 0xE8A11BE9, 0x4980740D, 0xC8087DFC,
            0x8DE4BF99, 0xA11101A0, 0x7FD37975, 0xDA5A26C0, 0xE81F994F, 0x9528CD89,
            0xFD339FED, 0xB87834BF, 0x5F04456D, 0x22258698, 0xC9C4C83B, 0x2DC156BE,
            0x4F628DAA, 0x57F55EC5, 0xE2220ABE, 0xD2916EBF, 0x4EC75B95, 0x24F2C3C0,
            0x42D15D99, 0xCD0D7FA0, 0x7B6E27FF, 0xA8DC8AF0, 0x7345C106, 0xF41E232F,
            0x35162386, 0xE6EA8926, 0x3333B094, 0x157EC6F2, 0x372B74AF, 0x692573E4,
            0xE9A9D848, 0xF3160289, 0x3A62EF1D, 0xA787E238, 0xF3A5F676, 0x74364853,
            0x20951063, 0x4576698D, 0xB6FAD407, 0x592AF950, 0x36F73523, 0x4CFB6E87,
            0x7DA4CEC0, 0x6C152DAA, 0xCB0396A8, 0xC50DFE5D, 0xFCD707AB, 0x0921C42F,
            0x89DFF0BB, 0x5FE2BE78, 0x448F4F33, 0x754613C9, 0x2B05D08D, 0x48B9D585,
            0xDC049441, 0xC8098F9B, 0x7DEDE786, 0xC39A3373, 0x42410005, 0x6A091751,
            0x0EF3C8A6, 0x890072D6, 0x28207682, 0xA9A9F7BE, 0xBF32679D, 0xD45B5B75,
            0xB353FD00, 0xCBB0E358, 0x830F220A, 0x1F8FB214, 0xD372CF08, 0xCC3C4A13,
            0x8CF63166, 0x061C87BE, 0x88C98F88, 0x6062E397, 0x47CF8E7A, 0xB6C85283,
            0x3CC2ACFB, 0x3FC06976, 0x4E8F0252, 0x64D8314D, 0xDA3870E3, 0x1E665459,
            0xC10908F0, 0x513021A5, 0x6C5B68B7, 0x822F8AA0, 0x3007CD3E, 0x74719EEF,
            0xDC872681, 0x073340D4, 0x7E432FD9, 0x0C5EC241, 0x8809286C, 0xF592D891,
            0x08A930F6, 0x957EF305, 0xB7FBFFBD, 0xC266E96F, 0x6FE4AC98, 0xB173ECC0,
            0xBC60B42A, 0x953498DA, 0xFBA1AE12, 0x2D4BD736, 0x0F25FAAB, 0xA4F3FCEB,
            0xE2969123, 0x257F0C3D, 0x9348AF49, 0x361400BC, 0xE8816F4A, 0x3814F200,
            0xA3F94043, 0x9C7A54C2, 0xBC704F57, 0xDA41E7F9, 0xC25AD33A, 0x54F4A084,
            0xB17F5505, 0x59357CBE, 0xEDBD15C8, 0x7F97C5AB, 0xBA5AC7B5, 0xB6F6DEAF,
            0x3A479C3A, 0x5302DA25, 0x653D7E6A, 0x54268D49, 0x51A477EA, 0x5017D55B,
            0xD7D25D88, 0x44136C76, 0x0404A8C8, 0xB8E5A121, 0xB81A928A, 0x60ED5869,
            0x97C55B96, 0xEAEC991B, 0x29935913, 0x01FDB7F1, 0x088E8DFA, 0x9AB6F6F5,
            0x3B4CBF9F, 0x4A5DE3AB, 0xE6051D35, 0xA0E1D855, 0xD36B4CF1, 0xF544EDEB,
            0xB0E93524, 0xBEBB8FBD, 0xA2D762CF, 0x49C92F54, 0x38B5F331, 0x7128A454,
            0x48392905, 0xA65B1DB8, 0x851C97BD, 0xD675CF2F ];
        
        __gshared immutable uint[256] S7 = [
            0x85E04019, 0x332BF567, 0x662DBFFF, 0xCFC65693, 0x2A8D7F6F, 0xAB9BC912,
            0xDE6008A1, 0x2028DA1F, 0x0227BCE7, 0x4D642916, 0x18FAC300, 0x50F18B82,
            0x2CB2CB11, 0xB232E75C, 0x4B3695F2, 0xB28707DE, 0xA05FBCF6, 0xCD4181E9,
            0xE150210C, 0xE24EF1BD, 0xB168C381, 0xFDE4E789, 0x5C79B0D8, 0x1E8BFD43,
            0x4D495001, 0x38BE4341, 0x913CEE1D, 0x92A79C3F, 0x089766BE, 0xBAEEADF4,
            0x1286BECF, 0xB6EACB19, 0x2660C200, 0x7565BDE4, 0x64241F7A, 0x8248DCA9,
            0xC3B3AD66, 0x28136086, 0x0BD8DFA8, 0x356D1CF2, 0x107789BE, 0xB3B2E9CE,
            0x0502AA8F, 0x0BC0351E, 0x166BF52A, 0xEB12FF82, 0xE3486911, 0xD34D7516,
            0x4E7B3AFF, 0x5F43671B, 0x9CF6E037, 0x4981AC83, 0x334266CE, 0x8C9341B7,
            0xD0D854C0, 0xCB3A6C88, 0x47BC2829, 0x4725BA37, 0xA66AD22B, 0x7AD61F1E,
            0x0C5CBAFA, 0x4437F107, 0xB6E79962, 0x42D2D816, 0x0A961288, 0xE1A5C06E,
            0x13749E67, 0x72FC081A, 0xB1D139F7, 0xF9583745, 0xCF19DF58, 0xBEC3F756,
            0xC06EBA30, 0x07211B24, 0x45C28829, 0xC95E317F, 0xBC8EC511, 0x38BC46E9,
            0xC6E6FA14, 0xBAE8584A, 0xAD4EBC46, 0x468F508B, 0x7829435F, 0xF124183B,
            0x821DBA9F, 0xAFF60FF4, 0xEA2C4E6D, 0x16E39264, 0x92544A8B, 0x009B4FC3,
            0xABA68CED, 0x9AC96F78, 0x06A5B79A, 0xB2856E6E, 0x1AEC3CA9, 0xBE838688,
            0x0E0804E9, 0x55F1BE56, 0xE7E5363B, 0xB3A1F25D, 0xF7DEBB85, 0x61FE033C,
            0x16746233, 0x3C034C28, 0xDA6D0C74, 0x79AAC56C, 0x3CE4E1AD, 0x51F0C802,
            0x98F8F35A, 0x1626A49F, 0xEED82B29, 0x1D382FE3, 0x0C4FB99A, 0xBB325778,
            0x3EC6D97B, 0x6E77A6A9, 0xCB658B5C, 0xD45230C7, 0x2BD1408B, 0x60C03EB7,
            0xB9068D78, 0xA33754F4, 0xF430C87D, 0xC8A71302, 0xB96D8C32, 0xEBD4E7BE,
            0xBE8B9D2D, 0x7979FB06, 0xE7225308, 0x8B75CF77, 0x11EF8DA4, 0xE083C858,
            0x8D6B786F, 0x5A6317A6, 0xFA5CF7A0, 0x5DDA0033, 0xF28EBFB0, 0xF5B9C310,
            0xA0EAC280, 0x08B9767A, 0xA3D9D2B0, 0x79D34217, 0x021A718D, 0x9AC6336A,
            0x2711FD60, 0x438050E3, 0x069908A8, 0x3D7FEDC4, 0x826D2BEF, 0x4EEB8476,
            0x488DCF25, 0x36C9D566, 0x28E74E41, 0xC2610ACA, 0x3D49A9CF, 0xBAE3B9DF,
            0xB65F8DE6, 0x92AEAF64, 0x3AC7D5E6, 0x9EA80509, 0xF22B017D, 0xA4173F70,
            0xDD1E16C3, 0x15E0D7F9, 0x50B1B887, 0x2B9F4FD5, 0x625ABA82, 0x6A017962,
            0x2EC01B9C, 0x15488AA9, 0xD716E740, 0x40055A2C, 0x93D29A22, 0xE32DBF9A,
            0x058745B9, 0x3453DC1E, 0xD699296E, 0x496CFF6F, 0x1C9F4986, 0xDFE2ED07,
            0xB87242D1, 0x19DE7EAE, 0x053E561A, 0x15AD6F8C, 0x66626C1C, 0x7154C24C,
            0xEA082B2A, 0x93EB2939, 0x17DCB0F0, 0x58D4F2AE, 0x9EA294FB, 0x52CF564C,
            0x9883FE66, 0x2EC40581, 0x763953C3, 0x01D6692E, 0xD3A0C108, 0xA1E7160E,
            0xE4F2DFA6, 0x693ED285, 0x74904698, 0x4C2B0EDD, 0x4F757656, 0x5D393378,
            0xA132234F, 0x3D321C5D, 0xC3F5E194, 0x4B269301, 0xC79F022F, 0x3C997E7E,
            0x5E4F9504, 0x3FFAFBBD, 0x76F7AD0E, 0x296693F4, 0x3D1FCE6F, 0xC61E45BE,
            0xD3B5AB34, 0xF72BF9B7, 0x1B0434C0, 0x4E72B567, 0x5592A33D, 0xB5229301,
            0xCFD2A87F, 0x60AEB767, 0x1814386B, 0x30BCC33D, 0x38A0C07D, 0xFD1606F2,
            0xC363519B, 0x589DD390, 0x5479F8E6, 0x1CB8D647, 0x97FD61A9, 0xEA7759F4,
            0x2D57539D, 0x569A58CF, 0xE84E63AD, 0x462E1B78, 0x6580F87E, 0xF3817914,
            0x91DA55F4, 0x40A230F3, 0xD1988F35, 0xB6E318D2, 0x3FFA50BC, 0x3D40F021,
            0xC3C0BDAE, 0x4958C24C, 0x518F36B2, 0x84B1D370, 0x0FEDCE83, 0x878DDADA,
            0xF2A279C7, 0x94E01BE8, 0x90716F4B, 0x954B8AA3 ];
        
        __gshared immutable uint[256] S8 = [
            0xE216300D, 0xBBDDFFFC, 0xA7EBDABD, 0x35648095, 0x7789F8B7, 0xE6C1121B,
            0x0E241600, 0x052CE8B5, 0x11A9CFB0, 0xE5952F11, 0xECE7990A, 0x9386D174,
            0x2A42931C, 0x76E38111, 0xB12DEF3A, 0x37DDDDFC, 0xDE9ADEB1, 0x0A0CC32C,
            0xBE197029, 0x84A00940, 0xBB243A0F, 0xB4D137CF, 0xB44E79F0, 0x049EEDFD,
            0x0B15A15D, 0x480D3168, 0x8BBBDE5A, 0x669DED42, 0xC7ECE831, 0x3F8F95E7,
            0x72DF191B, 0x7580330D, 0x94074251, 0x5C7DCDFA, 0xABBE6D63, 0xAA402164,
            0xB301D40A, 0x02E7D1CA, 0x53571DAE, 0x7A3182A2, 0x12A8DDEC, 0xFDAA335D,
            0x176F43E8, 0x71FB46D4, 0x38129022, 0xCE949AD4, 0xB84769AD, 0x965BD862,
            0x82F3D055, 0x66FB9767, 0x15B80B4E, 0x1D5B47A0, 0x4CFDE06F, 0xC28EC4B8,
            0x57E8726E, 0x647A78FC, 0x99865D44, 0x608BD593, 0x6C200E03, 0x39DC5FF6,
            0x5D0B00A3, 0xAE63AFF2, 0x7E8BD632, 0x70108C0C, 0xBBD35049, 0x2998DF04,
            0x980CF42A, 0x9B6DF491, 0x9E7EDD53, 0x06918548, 0x58CB7E07, 0x3B74EF2E,
            0x522FFFB1, 0xD24708CC, 0x1C7E27CD, 0xA4EB215B, 0x3CF1D2E2, 0x19B47A38,
            0x424F7618, 0x35856039, 0x9D17DEE7, 0x27EB35E6, 0xC9AFF67B, 0x36BAF5B8,
            0x09C467CD, 0xC18910B1, 0xE11DBF7B, 0x06CD1AF8, 0x7170C608, 0x2D5E3354,
            0xD4DE495A, 0x64C6D006, 0xBCC0C62C, 0x3DD00DB3, 0x708F8F34, 0x77D51B42,
            0x264F620F, 0x24B8D2BF, 0x15C1B79E, 0x46A52564, 0xF8D7E54E, 0x3E378160,
            0x7895CDA5, 0x859C15A5, 0xE6459788, 0xC37BC75F, 0xDB07BA0C, 0x0676A3AB,
            0x7F229B1E, 0x31842E7B, 0x24259FD7, 0xF8BEF472, 0x835FFCB8, 0x6DF4C1F2,
            0x96F5B195, 0xFD0AF0FC, 0xB0FE134C, 0xE2506D3D, 0x4F9B12EA, 0xF215F225,
            0xA223736F, 0x9FB4C428, 0x25D04979, 0x34C713F8, 0xC4618187, 0xEA7A6E98,
            0x7CD16EFC, 0x1436876C, 0xF1544107, 0xBEDEEE14, 0x56E9AF27, 0xA04AA441,
            0x3CF7C899, 0x92ECBAE6, 0xDD67016D, 0x151682EB, 0xA842EEDF, 0xFDBA60B4,
            0xF1907B75, 0x20E3030F, 0x24D8C29E, 0xE139673B, 0xEFA63FB8, 0x71873054,
            0xB6F2CF3B, 0x9F326442, 0xCB15A4CC, 0xB01A4504, 0xF1E47D8D, 0x844A1BE5,
            0xBAE7DFDC, 0x42CBDA70, 0xCD7DAE0A, 0x57E85B7A, 0xD53F5AF6, 0x20CF4D8C,
            0xCEA4D428, 0x79D130A4, 0x3486EBFB, 0x33D3CDDC, 0x77853B53, 0x37EFFCB5,
            0xC5068778, 0xE580B3E6, 0x4E68B8F4, 0xC5C8B37E, 0x0D809EA2, 0x398FEB7C,
            0x132A4F94, 0x43B7950E, 0x2FEE7D1C, 0x223613BD, 0xDD06CAA2, 0x37DF932B,
            0xC4248289, 0xACF3EBC3, 0x5715F6B7, 0xEF3478DD, 0xF267616F, 0xC148CBE4,
            0x9052815E, 0x5E410FAB, 0xB48A2465, 0x2EDA7FA4, 0xE87B40E4, 0xE98EA084,
            0x5889E9E1, 0xEFD390FC, 0xDD07D35B, 0xDB485694, 0x38D7E5B2, 0x57720101,
            0x730EDEBC, 0x5B643113, 0x94917E4F, 0x503C2FBA, 0x646F1282, 0x7523D24A,
            0xE0779695, 0xF9C17A8F, 0x7A5B2121, 0xD187B896, 0x29263A4D, 0xBA510CDF,
            0x81F47C9F, 0xAD1163ED, 0xEA7B5965, 0x1A00726E, 0x11403092, 0x00DA6D77,
            0x4A0CDD61, 0xAD1F4603, 0x605BDFB0, 0x9EEDC364, 0x22EBE6A8, 0xCEE7D28A,
            0xA0E736A0, 0x5564A6B9, 0x10853209, 0xC7EB8F37, 0x2DE705CA, 0x8951570F,
            0xDF09822B, 0xBD691A6C, 0xAA12E4F2, 0x87451C0F, 0xE0F6A27A, 0x3ADA4819,
            0x4CF1764F, 0x0D771C2B, 0x67CDB156, 0x350D8384, 0x5938FA0F, 0x42399EF3,
            0x36997B07, 0x0E84093D, 0x4AA93E61, 0x8360D87B, 0x1FA98B0C, 0x1149382C,
            0xE97625A5, 0x0614D1B7, 0x0E25244B, 0x0C768347, 0x589E8D82, 0x0D2059D1,
            0xA466BB1E, 0xF8DA0A82, 0x04F19130, 0xBA6E4EC0, 0x99265164, 0x1EE7230D,
            0x50B2AD80, 0xEAEE6801, 0x8DB2A283, 0xEA8BF59E ];
        
        class ByteReader
        {
        public:
            ubyte opCall(size_t i) { return cast(ubyte)(X[i/4] >> (8*(3 - (i%4)))); } 
            this(in uint* x) { X = x; }
        private:
            const uint* X;
        }
        
        SecureVector!uint Z = SecureVector!uint(4);
        auto x = scoped!ByteReader(X.ptr);
        auto z = scoped!ByteReader(Z.ptr);
        Z[0]  = X[0] ^ S5[x(13)] ^ S6[x(15)] ^ S7[x(12)] ^ S8[x(14)] ^ S7[x( 8)];
        Z[1]  = X[2] ^ S5[z( 0)] ^ S6[z( 2)] ^ S7[z( 1)] ^ S8[z( 3)] ^ S8[x(10)];
        Z[2]  = X[3] ^ S5[z( 7)] ^ S6[z( 6)] ^ S7[z( 5)] ^ S8[z( 4)] ^ S5[x( 9)];
        Z[3]  = X[1] ^ S5[z(10)] ^ S6[z( 9)] ^ S7[z(11)] ^ S8[z( 8)] ^ S6[x(11)];
        K[ 0] = S5[z( 8)] ^ S6[z( 9)] ^ S7[z( 7)] ^ S8[z( 6)] ^ S5[z( 2)];
        K[ 1] = S5[z(10)] ^ S6[z(11)] ^ S7[z( 5)] ^ S8[z( 4)] ^ S6[z( 6)];
        K[ 2] = S5[z(12)] ^ S6[z(13)] ^ S7[z( 3)] ^ S8[z( 2)] ^ S7[z( 9)];
        K[ 3] = S5[z(14)] ^ S6[z(15)] ^ S7[z( 1)] ^ S8[z( 0)] ^ S8[z(12)];
        X[0]  = Z[2] ^ S5[z( 5)] ^ S6[z( 7)] ^ S7[z( 4)] ^ S8[z( 6)] ^ S7[z( 0)];
        X[1]  = Z[0] ^ S5[x( 0)] ^ S6[x( 2)] ^ S7[x( 1)] ^ S8[x( 3)] ^ S8[z( 2)];
        X[2]  = Z[1] ^ S5[x( 7)] ^ S6[x( 6)] ^ S7[x( 5)] ^ S8[x( 4)] ^ S5[z( 1)];
        X[3]  = Z[3] ^ S5[x(10)] ^ S6[x( 9)] ^ S7[x(11)] ^ S8[x( 8)] ^ S6[z( 3)];
        K[ 4] = S5[x( 3)] ^ S6[x( 2)] ^ S7[x(12)] ^ S8[x(13)] ^ S5[x( 8)];
        K[ 5] = S5[x( 1)] ^ S6[x( 0)] ^ S7[x(14)] ^ S8[x(15)] ^ S6[x(13)];
        K[ 6] = S5[x( 7)] ^ S6[x( 6)] ^ S7[x( 8)] ^ S8[x( 9)] ^ S7[x( 3)];
        K[ 7] = S5[x( 5)] ^ S6[x( 4)] ^ S7[x(10)] ^ S8[x(11)] ^ S8[x( 7)];
        Z[0]  = X[0] ^ S5[x(13)] ^ S6[x(15)] ^ S7[x(12)] ^ S8[x(14)] ^ S7[x( 8)];
        Z[1]  = X[2] ^ S5[z( 0)] ^ S6[z( 2)] ^ S7[z( 1)] ^ S8[z( 3)] ^ S8[x(10)];
        Z[2]  = X[3] ^ S5[z( 7)] ^ S6[z( 6)] ^ S7[z( 5)] ^ S8[z( 4)] ^ S5[x( 9)];
        Z[3]  = X[1] ^ S5[z(10)] ^ S6[z( 9)] ^ S7[z(11)] ^ S8[z( 8)] ^ S6[x(11)];
        K[ 8] = S5[z( 3)] ^ S6[z( 2)] ^ S7[z(12)] ^ S8[z(13)] ^ S5[z( 9)];
        K[ 9] = S5[z( 1)] ^ S6[z( 0)] ^ S7[z(14)] ^ S8[z(15)] ^ S6[z(12)];
        K[10] = S5[z( 7)] ^ S6[z( 6)] ^ S7[z( 8)] ^ S8[z( 9)] ^ S7[z( 2)];
        K[11] = S5[z( 5)] ^ S6[z( 4)] ^ S7[z(10)] ^ S8[z(11)] ^ S8[z( 6)];
        X[0]  = Z[2] ^ S5[z( 5)] ^ S6[z( 7)] ^ S7[z( 4)] ^ S8[z( 6)] ^ S7[z( 0)];
        X[1]  = Z[0] ^ S5[x( 0)] ^ S6[x( 2)] ^ S7[x( 1)] ^ S8[x( 3)] ^ S8[z( 2)];
        X[2]  = Z[1] ^ S5[x( 7)] ^ S6[x( 6)] ^ S7[x( 5)] ^ S8[x( 4)] ^ S5[z( 1)];
        X[3]  = Z[3] ^ S5[x(10)] ^ S6[x( 9)] ^ S7[x(11)] ^ S8[x( 8)] ^ S6[z( 3)];
        K[12] = S5[x( 8)] ^ S6[x( 9)] ^ S7[x( 7)] ^ S8[x( 6)] ^ S5[x( 3)];
        K[13] = S5[x(10)] ^ S6[x(11)] ^ S7[x( 5)] ^ S8[x( 4)] ^ S6[x( 7)];
        K[14] = S5[x(12)] ^ S6[x(13)] ^ S7[x( 3)] ^ S8[x( 2)] ^ S7[x( 8)];
        K[15] = S5[x(14)] ^ S6[x(15)] ^ S7[x( 1)] ^ S8[x( 0)] ^ S8[x(13)];
    }

    SecureVector!uint m_MK;
    SecureVector!ubyte m_RK;
}

private:
    
import botan.utils.get_byte : get_byte;
/*
* CAST-128 Round Type 1
*/
void R1(ref uint L, uint R, uint MK, ubyte RK) pure
{
    uint T = rotateLeft(MK + R, RK);
    L ^= (CAST_SBOX1[get_byte(0, T)] ^ CAST_SBOX2[get_byte(1, T)]) -
        CAST_SBOX3[get_byte(2, T)] + CAST_SBOX4[get_byte(3, T)];
}

/*
* CAST-128 Round Type 2
*/
void R2(ref uint L, uint R, uint MK, ubyte RK) pure
{
    uint T = rotateLeft(MK ^ R, RK);
    L ^= (CAST_SBOX1[get_byte(0, T)]  - CAST_SBOX2[get_byte(1, T)] +
    CAST_SBOX3[get_byte(2, T)]) ^ CAST_SBOX4[get_byte(3, T)];
}

/*
* CAST-128 Round Type 3
*/
void R3(ref uint L, uint R, uint MK, ubyte RK) pure
{
    uint T = rotateLeft(MK - R, RK);
    L ^= ((CAST_SBOX1[get_byte(0, T)]  + CAST_SBOX2[get_byte(1, T)]) ^
          CAST_SBOX3[get_byte(2, T)]) - CAST_SBOX4[get_byte(3, T)];
}