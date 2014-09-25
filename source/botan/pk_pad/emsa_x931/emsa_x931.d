/*
* EMSA_X931
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/emsa_x931.h>
#include <botan/hash_id.h>
namespace {

SafeVector!byte emsa2_encoding(in SafeVector!byte msg,
											  size_t output_bits,
											  in SafeVector!byte empty_hash,
											  byte hash_id)
{
	const size_t HASH_SIZE = empty_hash.size();

	size_t output_length = (output_bits + 1) / 8;

	if(msg.size() != HASH_SIZE)
		throw new Encoding_Error("EMSA_X931::encoding_of: Bad input length");
	if(output_length < HASH_SIZE + 4)
		throw new Encoding_Error("EMSA_X931::encoding_of: Output length is too small");

	const bool empty_input = (msg == empty_hash);

	SafeVector!byte output(output_length);

	output[0] = (empty_input ? 0x4B : 0x6B);
	output[output_length - 3 - HASH_SIZE] = 0xBA;
	set_mem(&output[1], output_length - 4 - HASH_SIZE, 0xBB);
	buffer_insert(output, output_length - (HASH_SIZE + 2), &msg[0], msg.size());
	output[output_length-2] = hash_id;
	output[output_length-1] = 0xCC;

	return output;
}

}

void EMSA_X931::update(in byte[] input, size_t length)
{
	m_hash->update(input, length);
}

SafeVector!byte EMSA_X931::raw_data()
{
	return m_hash->flush();
}

/*
* EMSA_X931 Encode Operation
*/
SafeVector!byte EMSA_X931::encoding_of(in SafeVector!byte msg,
												  size_t output_bits,
												  RandomNumberGenerator&)
{
	return emsa2_encoding(msg, output_bits, m_empty_hash, m_hash_id);
}

/*
* EMSA_X931 Verify Operation
*/
bool EMSA_X931::verify(in SafeVector!byte coded,
						 in SafeVector!byte raw,
						 size_t key_bits)
{
	try
	{
		return (coded == emsa2_encoding(raw, key_bits,
												  m_empty_hash, m_hash_id));
	}
	catch(...)
	{
		return false;
	}
}

/*
* EMSA_X931 Constructor
*/
EMSA_X931::EMSA_X931(HashFunction* hash) : m_hash(hash)
{
	m_empty_hash = m_hash->flush();

	m_hash_id = ieee1363_hash_id(hash->name());

	if(!m_hash_id)
		throw new Encoding_Error("EMSA_X931 no hash identifier for " + hash->name());
}

}
