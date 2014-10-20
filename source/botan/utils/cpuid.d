/*
* Runtime CPU detection
* (C) 2009-2010,2013 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.utils.cpuid;

import core.cpuid;
import botan.utils.types;
import iosfwd;
import botan.utils.types;
import botan.utils.get_byte;
import botan.utils.mem_ops;
import ostream;


/**
* A class handling runtime CPU feature detection
*/
class CPUID
{
public:
	/**
	* Probe the CPU and see what extensions are supported
	*/
	static this()
	{

		if (max_cpuid == 0)
			return;

		version(PPC)	
			if (altivec_check_sysctl() || altivec_check_pvr_emul())
				m_altivec_capable = true;


		m_x86_processor_flags[0] = (cast(ulong)(miscfeatures) << 32) | features;
		
		if (is_intel)
			m_cache_line_size = 8 * get_byte(2, brand);
		
		if (max_cpuid >= 7)
			m_x86_processor_flags[1] = (cast(ulong)(extreserved) << 32) | extfeatures;
		
		if (is_amd)
		{
			m_cache_line_size = get_byte(3, l1cache);			
			
			version(X86_64) {
				/*
				* If we don't have access to CPUID, we can still safely assume that
				* any x86-64 processor has SSE2 and RDTSC
				*/
				if (m_x86_processor_flags[0] == 0)
					m_x86_processor_flags[0] = (1 << CPUID_SSE2_BIT) | (1 << CPUID_RDTSC_BIT);
			}
		}
		
	}


	/**
	* Return a best guess of the cache line size
	*/
	static size_t cache_line_size() { return m_cache_line_size; }

	/**
	* Check if the processor supports RDTSC
	*/
	static bool has_rdtsc()
	{ return x86_processor_flags_has(CPUID_RDTSC_BIT); }

	/**
	* Check if the processor supports SSE2
	*/
	static bool has_sse2()
	{ return x86_processor_flags_has(CPUID_SSE2_BIT); }

	/**
	* Check if the processor supports SSSE3
	*/
	static bool has_ssse3()
	{ return x86_processor_flags_has(CPUID_SSSE3_BIT); }

	/**
	* Check if the processor supports SSE4.1
	*/
	static bool has_sse41()
	{ return x86_processor_flags_has(CPUID_SSE41_BIT); }

	/**
	* Check if the processor supports SSE4.2
	*/
	static bool has_sse42()
	{ return x86_processor_flags_has(CPUID_SSE42_BIT); }

	/**
	* Check if the processor supports AVX2
	*/
	static bool has_avx2()
	{ return x86_processor_flags_has(CPUID_AVX2_BIT); }

	/**
	* Check if the processor supports AVX-512F
	*/
	static bool has_avx512f()
	{ return x86_processor_flags_has(CPUID_AVX512F_BIT); }

	/**
	* Check if the processor supports BMI2
	*/
	static bool has_bmi2()
	{ return x86_processor_flags_has(CPUID_BMI2_BIT); }

	/**
	* Check if the processor supports AES-NI
	*/
	static bool has_aes_ni()
	{ return x86_processor_flags_has(CPUID_AESNI_BIT); }

	/**
	* Check if the processor supports CLMUL
	*/
	static bool has_clmul()
	{ return x86_processor_flags_has(CPUID_CLMUL_BIT); }

	/**
	* Check if the processor supports Intel SHA extension
	*/
	static bool has_intel_sha()
	{ return x86_processor_flags_has(CPUID_SHA_BIT); }

	/**
	* Check if the processor supports ADX extension
	*/
	static bool has_adx()
	{ return x86_processor_flags_has(CPUID_ADX_BIT); }

	/**
	* Check if the processor supports RDRAND
	*/
	static bool has_rdrand()
	{ return x86_processor_flags_has(CPUID_RDRAND_BIT); }

	/**
	* Check if the processor supports RDSEED
	*/
	static bool has_rdseed()
	{ return x86_processor_flags_has(CPUID_RDSEED_BIT); }

	/**
	* Check if the processor supports AltiVec/VMX
	*/
	static bool has_altivec() { return m_altivec_capable; }

	static string toString()
	{
		import std.array : Appender;
		Appender!string app;
		
		app ~= "CPUID flags: ";
		
		app ~= CPUID.has_sse2;
		app ~= CPUID.has_ssse3;
		app ~= CPUID.has_sse41;
		app ~= CPUID.has_sse42;
		app ~= CPUID.has_avx2;
		app ~= CPUID.has_avx512f;
		app ~= CPUID.has_altivec;
		
		app ~= CPUID.has_rdtsc;
		app ~= CPUID.has_bmi2;
		app ~= CPUID.has_clmul;
		app ~= CPUID.has_aes_ni;
		app ~= CPUID.has_rdrand;
		app ~= CPUID.has_rdseed;
		app ~= CPUID.has_intel_sha;
		app ~= CPUID.has_adx;

		return app.data;
	}
private:
	enum CPUID_bits {
		CPUID_RDTSC_BIT = 4,
		CPUID_SSE2_BIT = 26,
		CPUID_CLMUL_BIT = 33,
		CPUID_SSSE3_BIT = 41,
		CPUID_SSE41_BIT = 51,
		CPUID_SSE42_BIT = 52,
		CPUID_AESNI_BIT = 57,
		CPUID_RDRAND_BIT = 62,

		CPUID_AVX2_BIT = 64+5,
		CPUID_BMI2_BIT = 64+8,
		CPUID_AVX512F_BIT = 64+16,
		CPUID_RDSEED_BIT = 64+18,
		CPUID_ADX_BIT = 64+19,
		CPUID_SHA_BIT = 64+29,
	};

	static bool x86_processor_flags_has(ulong bit)
	{
		return ((m_x86_processor_flags[bit/64] >> (bit % 64)) & 1);
	}

	static ulong[2] m_x86_processor_flags;
	static size_t m_cache_line_size;
	static bool m_altivec_capable;
};




package:


private __gshared {
	bool is_intel; // true = _probably_ an Intel processor, might be faking
	bool is_amd; // true = _probably_ an AMD processor

	uint apic;
	uint max_cpuid;
	uint max_extended_cpuid; // 0
	uint extfeatures;
	uint extreserved;
	uint miscfeatures;
	uint amdmiscfeatures;
	uint features;
	uint amdfeatures; 
	uint l1cache;
}

shared static this() {
	
	string processorName;
	char[12] vendorID;

	{
		uint a, b, c, d, a2;
		char * venptr = vendorID.ptr;
		version(D_InlineAsm_X86)
		{
			asm {
				mov EAX, 0;
				cpuid;
				mov a, EAX;
				mov EAX, venptr;
				mov [EAX], EBX;
				mov [EAX + 4], EDX;
				mov [EAX + 8], ECX;
			}
		}
		else version(D_InlineAsm_X86_64)
		{
			asm {
				mov EAX, 0;
				cpuid;
				mov a, EAX;
				mov RAX, venptr;
				mov [RAX], EBX;
				mov [RAX + 4], EDX;
				mov [RAX + 8], ECX;
			}
		}

		asm {
			mov EAX, 0x8000_0000;
			cpuid;
			mov a2, EAX;
		}

		max_cpuid = a;
		max_extended_cpuid = a2;
	
	}

	is_intel = vendorID == "GenuineIntel";
	is_amd = vendorID == "AuthenticAMD";

	{
		uint a, b, c, d;

		asm {
			mov EAX, 1; // model, stepping
			cpuid;
			mov a, EAX;
			mov b, EBX;
			mov c, ECX;
			mov d, EDX;
		}
		/// EAX(a) contains stepping, model, family, processor type, extended model,
		/// extended family

		apic = b;
		miscfeatures = c;
		features = d;
	}

	if (max_cpuid >= 7)
	{
		uint ext, reserved;
		asm
		{
			mov EAX, 7; // Structured extended feature leaf.
			mov ECX, 0; // Main leaf.
			cpuid;
			mov ext, EBX; // HLE, AVX2, RTM, etc.
			mov reserved, ECX;
		}
		extreserved = reserved;
		extfeatures = ext;
	}
	
	/*if (miscfeatures & OSXSAVE_BIT)
	{
		uint a, d;

		asm {
			mov ECX, 0;
			xgetbv;
			mov d, EDX;
			mov a, EAX;
		}
		xfeatures = cast(ulong)d << 32 | a;
	}*/

	if (max_extended_cpuid >= 0x8000_0001) {
		uint c, d;

		asm {
			mov EAX, 0x8000_0001;
			cpuid;
			mov c, ECX;
			mov d, EDX;
		}

		amdmiscfeatures = c;
		amdfeatures = d;

	}
	if (max_extended_cpuid >= 0x8000_0005) {
		uint c;
		asm {
			mov EAX, 0x8000_0005; // L1 cache
			cpuid;
			// EAX has L1_TLB_4M.
			// EBX has L1_TLB_4K
			// EDX has L1 instruction cache
			mov c, ECX;
		}

		l1cache = c;

	}
	

	// Try to detect fraudulent vendorIDs
	if (amd3dnow) is_intel = false;


}


version (PPC) {
	bool altivec_check_sysctl()
	{
		version (OSX)
			enum supported = true;
		else version (BSD)
			enum supported = true;
		else enum supported = false;
		static if (supported) {
			int[2] sels = { CTL_MACHDEP, CPU_ALTIVEC };
			// From Apple's docs
			int[2] sels = { CTL_HW, HW_VECTORUNIT };
			int vector_type = 0;
			size_t length = sizeof(vector_type);
			int error = sysctl(sels, 2, &vector_type, &length, NULL, 0);
			
			if (error == 0 && vector_type > 0)
				return true;
		}
		return false;
	}
	
	bool altivec_check_pvr_emul()
	{
		bool altivec_capable = false;
		
		version(linux) {
			
			
			/*
			On PowerPC, MSR 287 is PVR, the Processor Version Number
			Normally it is only accessible to ring 0, but Linux and NetBSD
			(others, too, maybe?) will trap and emulate it for us.

			PVR identifiers for various AltiVec enabled CPUs. Taken from
			PearPC and Linux sources, mostly.
			*/
			
			const ushort PVR_G4_7400  = 0x000C;
			const ushort PVR_G5_970	= 0x0039;
			const ushort PVR_G5_970FX = 0x003C;
			const ushort PVR_G5_970MP = 0x0044;
			const ushort PVR_G5_970GX = 0x0045;
			const ushort PVR_POWER6	= 0x003E;
			const ushort PVR_POWER7	= 0x003F;
			const ushort PVR_CELL_PPU = 0x0070;
			
			// Motorola produced G4s with PVR 0x800[0123C] (at least)
			const ushort PVR_G4_74xx_24  = 0x800;
			
			uint pvr = 0;
			
			mixin(`asm { mfspr [pvr], 287; }`); // not supported in DMD?
			
			// Top 16 bit suffice to identify model
			pvr >>= 16;
			
			altivec_capable |= (pvr == PVR_G4_7400);
			altivec_capable |= ((pvr >> 4) == PVR_G4_74xx_24);
			altivec_capable |= (pvr == PVR_G5_970);
			altivec_capable |= (pvr == PVR_G5_970FX);
			altivec_capable |= (pvr == PVR_G5_970MP);
			altivec_capable |= (pvr == PVR_G5_970GX);
			altivec_capable |= (pvr == PVR_POWER6);
			altivec_capable |= (pvr == PVR_POWER7);
			altivec_capable |= (pvr == PVR_CELL_PPU);
			
		}
		
		return altivec_capable;
		
	}
	
}