/*
* Win32 CAPI EntropySource
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.entropy_src;
import vector;
/**
* Win32 CAPI Entropy Source
*/
class Win32_CAPI_EntropySource : EntropySource
{
	public:
		string name() const { return "Win32 CryptoGenRandom"; }

		void poll(Entropy_Accumulator& accum);

	  /**
	  * Win32_Capi_Entropysource Constructor
	  * @param provs list of providers, separated by ':'
	  */
		Win32_CAPI_EntropySource(in string provs = "");
	private:
		Vector!( ulong ) prov_types;
};