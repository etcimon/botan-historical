/*
* Filters
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

import botan.filters;
import botan.libstate;
import std.algorithm;
/*
* StreamCipher_Filter Constructor
*/
StreamCipher_Filter::StreamCipher_Filter(StreamCipher stream_cipher) :
	buffer(DEFAULT_BUFFERSIZE)
{
	cipher = stream_cipher;
}

/*
* StreamCipher_Filter Constructor
*/
StreamCipher_Filter::StreamCipher_Filter(StreamCipher stream_cipher,
													  ref const SymmetricKey key) :
	buffer(DEFAULT_BUFFERSIZE)
{
	cipher = stream_cipher;
	cipher.set_key(key);
}

/*
* StreamCipher_Filter Constructor
*/
StreamCipher_Filter::StreamCipher_Filter(in string sc_name) :
	buffer(DEFAULT_BUFFERSIZE)
{
	Algorithm_Factory af = global_state().algorithm_factory();
	cipher = af.make_stream_cipher(sc_name);
}

/*
* StreamCipher_Filter Constructor
*/
StreamCipher_Filter::StreamCipher_Filter(in string sc_name,
													  ref const SymmetricKey key) :
	buffer(DEFAULT_BUFFERSIZE)
{
	Algorithm_Factory af = global_state().algorithm_factory();
	cipher = af.make_stream_cipher(sc_name);
	cipher.set_key(key);
}

/*
* Set the IV of a stream cipher
*/
void StreamCipher_Filter::set_iv(in InitializationVector iv)
{
	cipher.set_iv(iv.begin(), iv.length());
}

/*
* Write data into a StreamCipher_Filter
*/
void StreamCipher_Filter::write(in ubyte* input, size_t length)
{
	while(length)
	{
		size_t copied = std.algorithm.min(length, buffer.size());
		cipher.cipher(input, &buffer[0], copied);
		send(buffer, copied);
		input += copied;
		length -= copied;
	}
}

/*
* Hash_Filter Constructor
*/
Hash_Filter::Hash_Filter(in string algo_spec,
								 size_t len) :
	OUTPUT_LENGTH(len)
{
	Algorithm_Factory af = global_state().algorithm_factory();
	hash = af.make_hash_function(algo_spec);
}

/*
* Complete a calculation by a Hash_Filter
*/
void Hash_Filter::end_msg()
{
	SafeVector!ubyte output = hash.flush();
	if (OUTPUT_LENGTH)
		send(output, std.algorithm.min(OUTPUT_LENGTH, output.size()));
	else
		send(output);
}

/*
* MAC_Filter Constructor
*/
MAC_Filter::MAC_Filter(in string mac_name, size_t len) :
	OUTPUT_LENGTH(len)
{
	Algorithm_Factory af = global_state().algorithm_factory();
	mac = af.make_mac(mac_name);
}

/*
* MAC_Filter Constructor
*/
MAC_Filter::MAC_Filter(in string mac_name, ref const SymmetricKey key,
							  size_t len) : OUTPUT_LENGTH(len)
{
	Algorithm_Factory af = global_state().algorithm_factory();
	mac = af.make_mac(mac_name);
	mac.set_key(key);
}

/*
* Complete a calculation by a MAC_Filter
*/
void MAC_Filter::end_msg()
{
	SafeVector!ubyte output = mac.flush();
	if (OUTPUT_LENGTH)
		send(output, std.algorithm.min(OUTPUT_LENGTH, output.size()));
	else
		send(output);
}

}
