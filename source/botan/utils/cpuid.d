/*
* Runtime CPU detection
* (C) 2009-2010,2013 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

import botan.cpuid;
import botan.types;
import botan.get_byte;
import botan.mem_ops;
import ostream;

#if defined(BOTAN_TARGET_CPU_IS_PPC_FAMILY)

#if defined(BOTAN_TARGET_OS_IS_DARWinput)
  import sys.sysctl;
#endif

#if defined(BOTAN_TARGET_OS_IS_OPENBSD)
  import sys.param;
  import sys.sysctl;
  import machine.cpu;
#endif

#endif

#if defined(BOTAN_TARGET_CPU_IS_X86_FAMILY)

#if defined(BOTAN_BUILD_COMPILER_IS_MSVC)

import intrin.h;

#define X86_CPUID(type, output) do { __cpuid((int*)output, type); } while(0)
#define X86_CPUID_SUBLEVEL(type, level, output) do { __cpuidex((int*)output, type, level); } while(0)

#elif defined(BOTAN_BUILD_COMPILER_IS_INTEL)

import ia32intrin.h;

#define X86_CPUID(type, output) do { __cpuid(output, type); } while(0)
#define X86_CPUID_SUBLEVEL(type, level, output) do { __cpuidex((int*)output, type, level); } while(0)

#elif defined(BOTAN_TARGET_ARCH_IS_X86_64) && BOTAN_USE_GCC_INLINE_ASM

#define X86_CPUID(type, output)																	 \
	asm("cpuid\t" : "=a" (output[0]), "=b" (output[1]), "=c" (output[2]), "=d" (output[3]) \
		 : "0" (type))

#define X86_CPUID_SUBLEVEL(type, level, output)												\
	asm("cpuid\t" : "=a" (output[0]), "=b" (output[1]), "=c" (output[2]), "=d" (output[3]) \
		 : "0" (type), "2" (level))

#elif defined(BOTAN_BUILD_COMPILER_IS_GCC)

import cpuid.h;

#define X86_CPUID(type, output) do { __get_cpuid(type, output, output+1, output+2, output+3); } while(0)

#define X86_CPUID_SUBLEVEL(type, level, output) \
	do { __cpuid_count(type, level, output[0], output[1], output[2], output[3]); } while(0)

#else

#warning "No way of calling cpuid for this compiler"

#define X86_CPUID(type, output) do { clear_mem(output, 4); } while(0)
#define X86_CPUID_SUBLEVEL(type, level, output) do { clear_mem(output, 4); } while(0)

#endif

#endif
ulong[2] CPUID::m_x86_processor_flags = { 0, 0 };
size_t CPUID::m_cache_line_size = 0;
bool CPUID::m_altivec_capable = false;

namespace {

#if defined(BOTAN_TARGET_CPU_IS_PPC_FAMILY)

bool altivec_check_sysctl()
{
#if defined(BOTAN_TARGET_OS_IS_DARWinput) || defined(BOTAN_TARGET_OS_IS_OPENBSD)

#if defined(BOTAN_TARGET_OS_IS_OPENBSD)
	int[2] sels = { CTL_MACHDEP, CPU_ALTIVEC };
#else
	// From Apple's docs
	int[2] sels = { CTL_HW, HW_VECTORUNIT };
#endif
	int vector_type = 0;
	size_t length = sizeof(vector_type);
	int error = sysctl(sels, 2, &vector_type, &length, NULL, 0);

	if (error == 0 && vector_type > 0)
		return true;
#endif

	return false;
}

bool altivec_check_pvr_emul()
{
	bool altivec_capable = false;

#if defined(BOTAN_TARGET_OS_IS_LINUX) || defined(BOTAN_TARGET_OS_IS_NETBSD)

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

	asm volatile("mfspr %0, 287" : "=r" (pvr));

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
#endif

	return altivec_capable;}

void CPUID::print(std::ostream& o)
{
	o << "CPUID flags: ";

#define CPUID_PRINT(flag) do { if (has_##flag()) o << #flag << " "; } while(0)
	CPUID_PRINT(sse2);
	CPUID_PRINT(ssse3);
	CPUID_PRINT(sse41);
	CPUID_PRINT(sse42);
	CPUID_PRINT(avx2);
	CPUID_PRINT(avx512f);
	CPUID_PRINT(altivec);

	CPUID_PRINT(rdtsc);
	CPUID_PRINT(bmi2);
	CPUID_PRINT(clmul);
	CPUID_PRINT(aes_ni);
	CPUID_PRINT(rdrand);
	CPUID_PRINT(rdseed);
	CPUID_PRINT(intel_sha);
	CPUID_PRINT(adx);
#undef CPUID_PRINT
	o << "";
}

void CPUID::initialize()
{
#if defined(BOTAN_TARGET_CPU_IS_PPC_FAMILY)
		if (altivec_check_sysctl() || altivec_check_pvr_emul())
			m_altivec_capable = true;
#endif

#if defined(BOTAN_TARGET_CPU_IS_X86_FAMILY)
	immutable uint[3] INTEL_CPUID = { 0x756E6547, 0x6C65746E, 0x49656E69 };
	immutable uint[3] AMD_CPUID = { 0x68747541, 0x444D4163, 0x69746E65 };

	uint[4] cpuid = { 0 };
	X86_CPUID(0, cpuid);

	const uint max_supported_sublevel = cpuid[0];

	if (max_supported_sublevel == 0)
		return;

	const bool is_intel = same_mem(cpuid + 1, INTEL_CPUID, 3);
	const bool is_amd = same_mem(cpuid + 1, AMD_CPUID, 3);

	X86_CPUID(1, cpuid);

	m_x86_processor_flags[0] = (cast(ulong)(cpuid[2]) << 32) | cpuid[3];

	if (is_intel)
		m_cache_line_size = 8 * get_byte(2, cpuid[1]);

	if (max_supported_sublevel >= 7)
	{
		clear_mem(cpuid, 4);
		X86_CPUID_SUBLEVEL(7, 0, cpuid);
		m_x86_processor_flags[1] = (cast(ulong)(cpuid[2]) << 32) | cpuid[1];
	}

	if (is_amd)
	{
		X86_CPUID(0x80000005, cpuid);
		m_cache_line_size = get_byte(3, cpuid[2]);
	

#if defined(BOTAN_TARGET_ARCH_IS_X86_64)
	/*
	* If we don't have access to CPUID, we can still safely assume that
	* any x86-64 processor has SSE2 and RDTSC
	*/
	if (m_x86_processor_flags[0] == 0)
		m_x86_processor_flags[0] = (1 << CPUID_SSE2_BIT) | (1 << CPUID_RDTSC_BIT);
#endif
}

}
