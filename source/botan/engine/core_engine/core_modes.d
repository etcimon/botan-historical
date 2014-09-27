/*
* Core Engine
* (C) 1999-2007,2011,2013 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

import botan.internal.core_engine;
import botan.parsing;
import botan.filters;
import botan.algo_factory;
import botan.mode_pad;
import botan.transform_filter;

#if defined(BOTAN_HAS_MODE_CFB)
  import botan.cfb;
#endif

#if defined(BOTAN_HAS_MODE_ECB)
  import botan.ecb;
#endif

#if defined(BOTAN_HAS_MODE_CBC)
  import botan.cbc;
#endif

#if defined(BOTAN_HAS_MODE_XTS)
  import botan.xts;
#endif

#if defined(BOTAN_HAS_OFB)
  import botan.ofb;
#endif

#if defined(BOTAN_HAS_CTR_BE)
  import botan.ctr;
#endif

#if defined(BOTAN_HAS_AEAD_FILTER)

import botan.aead_filt;

#if defined(BOTAN_HAS_AEAD_CCM)
  import botan.ccm;
#endif

#if defined(BOTAN_HAS_AEAD_EAX)
  import botan.eax;
#endif

#if defined(BOTAN_HAS_AEAD_OCB)
  import botan.ocb;
#endif

#if defined(BOTAN_HAS_AEAD_GCM)
  import botan.gcm;
#endif

#endif
namespace {

/**
* Get a block cipher padding method by name
*/
BlockCipherModePaddingMethod* get_bc_pad(in string algo_spec,
													  in string def_if_empty)
{
#if defined(BOTAN_HAS_CIPHER_MODE_PADDING)
	if (algo_spec == "NoPadding" || (algo_spec == "" && def_if_empty == "NoPadding"))
		return new Null_Padding;

	if (algo_spec == "PKCS7" || (algo_spec == "" && def_if_empty == "PKCS7"))
		return new PKCS7_Padding;

	if (algo_spec == "OneAndZeros")
		return new OneAndZeros_Padding;

	if (algo_spec == "X9.23")
		return new ANSI_X923_Padding;

#endif

	throw new Algorithm_Not_Found(algo_spec);
}

}

Keyed_Filter* get_cipher_mode(const BlockCipher* block_cipher,
										Cipher_Dir direction,
										in string mode,
										in string padding)
{
#if defined(BOTAN_HAS_OFB)
	if (mode == "OFB")
		return new StreamCipher_Filter(new OFB(block_cipher->clone()));
#endif

#if defined(BOTAN_HAS_CTR_BE)
	if (mode == "CTR-BE")
		return new StreamCipher_Filter(new CTR_BE(block_cipher->clone()));
#endif

#if defined(BOTAN_HAS_MODE_ECB)
	if (mode == "ECB" || mode == "")
	{
		if (direction == ENCRYPTION)
			return new Transformation_Filter(
				new ECB_Encryption(block_cipher->clone(), get_bc_pad(padding, "NoPadding")));
		else
			return new Transformation_Filter(
				new ECB_Decryption(block_cipher->clone(), get_bc_pad(padding, "NoPadding")));
	}
#endif

	if (mode == "CBC")
	{
#if defined(BOTAN_HAS_MODE_CBC)
		if (padding == "CTS")
		{
			if (direction == ENCRYPTION)
				return new Transformation_Filter(new CTS_Encryption(block_cipher->clone()));
			else
				return new Transformation_Filter(new CTS_Decryption(block_cipher->clone()));
		}

		if (direction == ENCRYPTION)
			return new Transformation_Filter(
				new CBC_Encryption(block_cipher->clone(), get_bc_pad(padding, "PKCS7")));
		else
			return new Transformation_Filter(
				new CBC_Decryption(block_cipher->clone(), get_bc_pad(padding, "PKCS7")));
#else
		return null;
#endif
	}

#if defined(BOTAN_HAS_MODE_XTS)
	if (mode == "XTS")
	{
		if (direction == ENCRYPTION)
			return new Transformation_Filter(new XTS_Encryption(block_cipher->clone()));
		else
			return new Transformation_Filter(new XTS_Decryption(block_cipher->clone()));
	}
#endif

	if (mode.find("CFB") != string::npos ||
		mode.find("EAX") != string::npos ||
		mode.find("GCM") != string::npos ||
		mode.find("OCB") != string::npos ||
		mode.find("CCM") != string::npos)
	{
		Vector!( string ) algo_info = parse_algorithm_name(mode);
		const string mode_name = algo_info[0];

		size_t bits = 8 * block_cipher->block_size();
		if (algo_info.size() > 1)
			bits = to_uint(algo_info[1]);

#if defined(BOTAN_HAS_MODE_CFB)
		if (mode_name == "CFB")
		{
			if (direction == ENCRYPTION)
				return new Transformation_Filter(new CFB_Encryption(block_cipher->clone(), bits));
			else
				return new Transformation_Filter(new CFB_Decryption(block_cipher->clone(), bits));
		}
#endif

		if (bits % 8 != 0)
			throw new std::invalid_argument("AEAD interface does not support non-octet length tags");

#if defined(BOTAN_HAS_AEAD_FILTER)

		const size_t tag_size = bits / 8;

#if defined(BOTAN_HAS_AEAD_CCM)
		if (mode_name == "CCM")
		{
			const size_t L = (algo_info.size() == 3) ? to_uint(algo_info[2]) : 3;
			if (direction == ENCRYPTION)
				return new AEAD_Filter(new CCM_Encryption(block_cipher->clone(), tag_size, L));
			else
				return new AEAD_Filter(new CCM_Decryption(block_cipher->clone(), tag_size, L));
		}
#endif

#if defined(BOTAN_HAS_AEAD_EAX)
		if (mode_name == "EAX")
		{
			if (direction == ENCRYPTION)
				return new AEAD_Filter(new EAX_Encryption(block_cipher->clone(), tag_size));
			else
				return new AEAD_Filter(new EAX_Decryption(block_cipher->clone(), tag_size));
		}
#endif

#if defined(BOTAN_HAS_AEAD_OCB)
	if (mode_name == "OCB")
	{
		if (direction == ENCRYPTION)
			return new AEAD_Filter(new OCB_Encryption(block_cipher->clone(), tag_size));
		else
			return new AEAD_Filter(new OCB_Decryption(block_cipher->clone(), tag_size));
	}
#endif

#if defined(BOTAN_HAS_AEAD_GCM)
	if (mode_name == "GCM")
	{
		if (direction == ENCRYPTION)
			return new AEAD_Filter(new GCM_Encryption(block_cipher->clone(), tag_size));
		else
			return new AEAD_Filter(new GCM_Decryption(block_cipher->clone(), tag_size));
	}
#endif

#endif
	}

	return null;
}

/*
* Get a cipher object
*/
Keyed_Filter* Core_Engine::get_cipher(in string algo_spec,
												  Cipher_Dir direction,
												  Algorithm_Factory& af)
{
	Vector!( string ) algo_parts = split_on(algo_spec, '/');
	if (algo_parts.empty())
		throw new Invalid_Algorithm_Name(algo_spec);

	const string cipher_name = algo_parts[0];

	// check if it is a stream cipher first (easy case)
	const StreamCipher* stream_cipher = af.prototype_stream_cipher(cipher_name);
	if (stream_cipher)
		return new StreamCipher_Filter(stream_cipher->clone());

	const BlockCipher* block_cipher = af.prototype_block_cipher(cipher_name);
	if (!block_cipher)
		return null;

	if (algo_parts.size() >= 4)
		return null; // 4 part mode, not something we know about

	if (algo_parts.size() < 2)
		throw new Lookup_Error("Cipher specification '" + algo_spec +
								 "' is missing mode identifier");

	string mode = algo_parts[1];

	string padding;
	if (algo_parts.size() == 3)
		padding = algo_parts[2];
	else
		padding = (mode == "CBC") ? "PKCS7" : "NoPadding";

	if (mode == "ECB" && padding == "CTS")
		return null;
	else if ((mode != "CBC" && mode != "ECB") && padding != "NoPadding")
		throw new Invalid_Algorithm_Name(algo_spec);

	Keyed_Filter* filt = get_cipher_mode(block_cipher, direction, mode, padding);
	if (filt)
		return filt;

	if (padding != "NoPadding")
		throw new Algorithm_Not_Found(cipher_name + "/" + mode + "/" + padding);
	else
		throw new Algorithm_Not_Found(cipher_name + "/" + mode);
}

}
