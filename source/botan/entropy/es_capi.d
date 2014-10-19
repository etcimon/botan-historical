/*
* Win32 CAPI EntropySource
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.entropy.es_capi;

version(Windows):
static if (BOTAN_HAS_ENTROPY_SRC_CAPI):

import botan.entropy.entropy_src;
import vector;
import botan.utils.parsing;
import windows.h;
import wincrypt.h;

/**
* Win32 CAPI Entropy Source
*/
class Win32_CAPI_EntropySource : EntropySource
{
public:
	string name() const { return "Win32 CryptoGenRandom"; }

	/*
	* Gather Entropy from Win32 CAPI
	*/
	void poll(ref Entropy_Accumulator accum)
	{
		SafeVector!ubyte io_buffer = accum.get_io_buffer(32);
		
		for (size_t i = 0; i != prov_types.length; ++i)
		{
			CSP_Handle csp(prov_types[i]);
			
			size_t got = csp.gen_random(&io_buffer[0], io_buffer.length);
			
			if (got)
			{
				accum.add(&io_buffer[0], io_buffer.length, 6);
				break;
			}
		}
	}

	/**
	* Win32_Capi_Entropysource Constructor
	* @param provs list of providers, separated by ':'
	*/
	this(in string provs = "")
	{
		Vector!string capi_provs = splitter(provs, ':');
		
		for (size_t i = 0; i != capi_provs.length; ++i)
		{
			if (capi_provs[i] == "RSA_FULL")  prov_types.push_back(PROV_RSA_FULL);
			if (capi_provs[i] == "INTEL_SEC") prov_types.push_back(PROV_INTEL_SEC);
			if (capi_provs[i] == "FORTEZZA")  prov_types.push_back(PROV_FORTEZZA);
			if (capi_provs[i] == "RNG")		 prov_types.push_back(PROV_RNG);
		}
		
		if (prov_types.length == 0)
			prov_types.push_back(PROV_RSA_FULL);
	}

	private:
		Vector!( ulong ) prov_types;
};

class CSP_Handle
{
public:
	this(ulong capi_provider)
	{
		valid = false;
		DWORD prov_type = cast(DWORD)capi_provider;
		
		if (CryptAcquireContext(&handle, 0, 0,
		                        prov_type, CRYPT_VERIFYCONTEXT))
			valid = true;
	}
	
	~this()
	{
		if (is_valid())
			CryptReleaseContext(handle, 0);
	}
	
	size_t gen_random(ubyte* output) const
	{
		if (is_valid() && CryptGenRandom(handle, cast(DWORD)(output.length), output))
			return output.length;
		return 0;
	}
	
	bool is_valid() const { return valid; }
	
	HCRYPTPROV get_handle() const { return handle; }
private:
	HCRYPTPROV handle;
	bool valid;
};




