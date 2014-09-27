/*
* Filters
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.block_cipher;
import botan.stream_cipher;
import botan.hash;
import botan.mac;

import botan.pipe;
import botan.basefilt;
import botan.key_filt;
import botan.data_snk;

import botan.scan_name;

#if defined(BOTAN_HAS_CODEC_FILTERS)
  import botan.b64_filt;
  import botan.hex_filt;
#endif
/**
* Stream Cipher Filter
*/
class StreamCipher_Filter : public Keyed_Filter
{
	public:

		string name() const { return cipher->name(); }

		/**
		* Write input data
		* @param input data
		* @param input_len length of input in bytes
		*/
		void write(in byte* input, size_t input_len);

		bool valid_iv_length(size_t iv_len) const
		{ return cipher->valid_iv_length(iv_len); }

		/**
		* Set the initialization vector for this filter.
		* @param iv the initialization vector to set
		*/
		void set_iv(in InitializationVector iv);

		/**
		* Set the key of this filter.
		* @param key the key to set
		*/
		void set_key(in SymmetricKey key) { cipher->set_key(key); }

		Key_Length_Specification key_spec() const override { return cipher->key_spec(); }

		/**
		* Construct a stream cipher filter.
		* @param cipher_obj a cipher object to use
		*/
		StreamCipher_Filter(StreamCipher* cipher_obj);

		/**
		* Construct a stream cipher filter.
		* @param cipher_obj a cipher object to use
		* @param key the key to use inside this filter
		*/
		StreamCipher_Filter(StreamCipher* cipher_obj, const SymmetricKey& key);

		/**
		* Construct a stream cipher filter.
		* @param cipher the name of the desired cipher
		*/
		StreamCipher_Filter(in string cipher);

		/**
		* Construct a stream cipher filter.
		* @param cipher the name of the desired cipher
		* @param key the key to use inside this filter
		*/
		StreamCipher_Filter(in string cipher, const SymmetricKey& key);

		~this() { delete cipher; }
	private:
		SafeVector!byte buffer;
		StreamCipher* cipher;
};

/**
* Hash Filter.
*/
class Hash_Filter : public Filter
{
	public:
		void write(in byte* input, size_t len) { hash->update(input, len); }
		void end_msg();

		string name() const { return hash->name(); }

		/**
		* Construct a hash filter.
		* @param hash_fun the hash function to use
		* @param len the output length of this filter. Leave the default
		* value 0 if you want to use the full output of the hashfunction
		* hash. Otherwise, specify a smaller value here so that the
		* output of the hash algorithm will be cut off.
		*/
		Hash_Filter(HashFunction* hash_fun, size_t len = 0) :
			OUTPUT_LENGTH(len), hash(hash_fun) {}

		/**
		* Construct a hash filter.
		* @param request the name of the hash algorithm to use
		* @param len the output length of this filter. Leave the default
		* value 0 if you want to use the full output of the hashfunction
		* hash. Otherwise, specify a smaller value here so that the
		* output of the hash algorithm will be cut off.
		*/
		Hash_Filter(in string request, size_t len = 0);

		~this() { delete hash; }
	private:
		const size_t OUTPUT_LENGTH;
		HashFunction* hash;
};

/**
* MessageAuthenticationCode Filter.
*/
class MAC_Filter : public Keyed_Filter
{
	public:
		void write(in byte* input, size_t len) { mac->update(input, len); }
		void end_msg();

		string name() const { return mac->name(); }

		/**
		* Set the key of this filter.
		* @param key the key to set
		*/
		void set_key(in SymmetricKey key) { mac->set_key(key); }

		Key_Length_Specification key_spec() const override { return mac->key_spec(); }

		/**
		* Construct a MAC filter. The MAC key will be left empty.
		* @param mac_obj the MAC to use
		* @param out_len the output length of this filter. Leave the default
		* value 0 if you want to use the full output of the
		* MAC. Otherwise, specify a smaller value here so that the
		* output of the MAC will be cut off.
		*/
		MAC_Filter(MessageAuthenticationCode* mac_obj,
					  size_t out_len = 0) : OUTPUT_LENGTH(out_len)
		{
			mac = mac_obj;
		}

		/**
		* Construct a MAC filter.
		* @param mac_obj the MAC to use
		* @param key the MAC key to use
		* @param out_len the output length of this filter. Leave the default
		* value 0 if you want to use the full output of the
		* MAC. Otherwise, specify a smaller value here so that the
		* output of the MAC will be cut off.
		*/
		MAC_Filter(MessageAuthenticationCode* mac_obj,
					  const SymmetricKey& key,
					  size_t out_len = 0) : OUTPUT_LENGTH(out_len)
		{
			mac = mac_obj;
			mac->set_key(key);
		}

		/**
		* Construct a MAC filter. The MAC key will be left empty.
		* @param mac the name of the MAC to use
		* @param len the output length of this filter. Leave the default
		* value 0 if you want to use the full output of the
		* MAC. Otherwise, specify a smaller value here so that the
		* output of the MAC will be cut off.
		*/
		MAC_Filter(in string mac, size_t len = 0);

		/**
		* Construct a MAC filter.
		* @param mac the name of the MAC to use
		* @param key the MAC key to use
		* @param len the output length of this filter. Leave the default
		* value 0 if you want to use the full output of the
		* MAC. Otherwise, specify a smaller value here so that the
		* output of the MAC will be cut off.
		*/
		MAC_Filter(in string mac, const SymmetricKey& key,
					  size_t len = 0);

		~this() { delete mac; }
	private:
		const size_t OUTPUT_LENGTH;
		MessageAuthenticationCode* mac;
};