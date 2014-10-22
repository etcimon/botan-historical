/*
* High Resolution Timestamp Entropy Source
* (C) 1999-2009 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.entropy.hres_timer;

import botan.entropy.entropy_src;

import botan.utils.cpuid;
import std.datetime;

static if (BOTAN_TARGET_OS_HAS_QUERY_PERF_COUNTER)
	import core.sys.windows.windows;

static if (BOTAN_TARGET_OS_HAS_CLOCK_GETTIME) {
	version(linux) import core.sys.linux.time;
	else version(Posix) import core.sys.posix.time; 
}

/**
* Entropy source using high resolution timers
*
* @note Any results from timers are marked as not contributing entropy
* to the poll, as a local attacker could observe them directly.
*/
class High_Resolution_Timestamp : EntropySource
{
public:
	string name() const { return "High Resolution Timestamp"; }
	/*
* Get the timestamp
*/
	void poll(ref Entropy_Accumulator accum)
	{
		// Don't count any timestamps as contributing any entropy
		const double ESTIMATED_ENTROPY_PER_BYTE = 0.0;

		{
			auto timestamp = Clock.currStdTime();
			accum.add(timestamp, ESTIMATED_ENTROPY_PER_BYTE);
		}
		
		static if (BOTAN_TARGET_OS_HAS_QUERY_PERF_COUNTER) {
			{
				LARGE_INTEGER tv;
				QueryPerformanceCounter(&tv);
				accum.add(tv.QuadPart, ESTIMATED_ENTROPY_PER_BYTE);
			}
		}
		
		static if (BOTAN_TARGET_OS_HAS_CLOCK_GETTIME) {
			
			void CLOCK_GETTIME_POLL( src)
			{
				timespec ts;
				clock_gettime(src, &ts);
				accum.add(&ts, (ts).sizeof, ESTIMATED_ENTROPY_PER_BYTE);
			}
			
			version(CLOCK_REALTIME) {
				CLOCK_GETTIME_POLL(CLOCK_REALTIME);
			}
			
			version(CLOCK_REALTIME_COARSE) {
				CLOCK_GETTIME_POLL(CLOCK_REALTIME_COARSE);
			}
			
			version(CLOCK_MONOTONIC) {
				CLOCK_GETTIME_POLL(CLOCK_MONOTONIC);
			}
			
			version(CLOCK_MONOTONIC_COARSE) {
				CLOCK_GETTIME_POLL(CLOCK_MONOTONIC_COARSE);
			}
			
			version(CLOCK_MONOTONIC_RAW) {
				CLOCK_GETTIME_POLL(CLOCK_MONOTONIC_RAW);
			}
			
			version(CLOCK_BOOTTIME) {
				CLOCK_GETTIME_POLL(CLOCK_BOOTTIME);
			}
			
			version(CLOCK_PROCESS_CPUTIME_ID) {
				CLOCK_GETTIME_POLL(CLOCK_PROCESS_CPUTIME_ID);
			}
			
			version(CLOCK_THREAD_CPUTIME_ID) {
				CLOCK_GETTIME_POLL(CLOCK_THREAD_CPUTIME_ID);
			}
			
		}
		
		static if (BOTAN_USE_GCC_INLINE_ASM) {
			
			ulong rtc = 0;
			
			static if (BOTAN_TARGET_CPU_IS_X86_FAMILY) {
				if (CPUID.has_rdtsc()) // not availble on all x86 CPUs
				{
					uint rtc_low = 0, rtc_high = 0;
					// asm volatile("rdtsc" : "=d" (rtc_high), "=a" (rtc_low));
					rtc = (cast(ulong)(rtc_high) << 32) | rtc_low;
				}
				
			}
			else static if (BOTAN_TARGET_CPU_IS_PPC_FAMILY) {
				uint rtc_low = 0, rtc_high = 0;
				// asm volatile("mftbu %0; mftb %1" : "=r" (rtc_high), "=r" (rtc_low));
				rtc = (cast(ulong)(rtc_high) << 32) | rtc_low;
				
			}
			else static if (BOTAN_TARGET_ARCH_IS_ALPHA) {
				// asm volatile("rpcc %0" : "=r" (rtc));
				
			}
			else static if (BOTAN_TARGET_ARCH_IS_SPARC64){
				static if (BOTAN_TARGET_OS_IS_OPENBSD) {} else {
					// asm volatile("rd %%tick, %0" : "=r" (rtc));
				}
			} 
			else static if (BOTAN_TARGET_ARCH_IS_IA64) {
				// asm volatile("mov %0=ar.itc" : "=r" (rtc));
				
			}
			else static if (BOTAN_TARGET_ARCH_IS_S390X) {
				// asm volatile("stck 0(%0)" : : "a" (&rtc) : "memory", "cc");
				
			}
			else static if (BOTAN_TARGET_ARCH_IS_HPPA) {
				// asm volatile("mfctl 16,%0" : "=r" (rtc)); // 64-bit only?
				
			}
			
			accum.add(rtc, ESTIMATED_ENTROPY_PER_BYTE);
			
		}
	}

};