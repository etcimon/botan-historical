/*
* PSSR
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/pssr.h>
#include <botan/mgf1.h>
#include <botan/internal/bit_ops.h>
#include <botan/internal/xor_buf.h>
/*
* PSSR Update Operation
*/
void PSSR::update(in byte* input, size_t length)
{
	hash->update(input, length);
}

/*
* Return the raw (unencoded) data
*/
SafeVector!byte PSSR::raw_data()
{
	return hash->flush();
}

/*
* PSSR Encode Operation
*/
SafeVector!byte PSSR::encoding_of(in SafeVector!byte msg,
												  size_t output_bits,
												  RandomNumberGenerator& rng)
{
	const size_t HASH_SIZE = hash->output_length();

	if(msg.size() != HASH_SIZE)
		throw new Encoding_Error("PSSR::encoding_of: Bad input length");
	if(output_bits < 8*HASH_SIZE + 8*SALT_SIZE + 9)
		throw new Encoding_Error("PSSR::encoding_of: Output length is too small");

	const size_t output_length = (output_bits + 7) / 8;

	SafeVector!byte salt = rng.random_vec(SALT_SIZE);

	for(size_t j = 0; j != 8; ++j)
		hash->update(0);
	hash->update(msg);
	hash->update(salt);
	SafeVector!byte H = hash->flush();

	SafeVector!byte EM(output_length);

	EM[output_length - HASH_SIZE - SALT_SIZE - 2] = 0x01;
	buffer_insert(EM, output_length - 1 - HASH_SIZE - SALT_SIZE, salt);
	mgf1_mask(*hash, &H[0], HASH_SIZE, &EM[0], output_length - HASH_SIZE - 1);
	EM[0] &= 0xFF >> (8 * ((output_bits + 7) / 8) - output_bits);
	buffer_insert(EM, output_length - 1 - HASH_SIZE, H);
	EM[output_length-1] = 0xBC;

	return EM;
}

/*
* PSSR Decode/Verify Operation
*/
bool PSSR::verify(in SafeVector!byte const_coded,
						 in SafeVector!byte raw, size_t key_bits)
{
	const size_t HASH_SIZE = hash->output_length();
	const size_t KEY_BYTES = (key_bits + 7) / 8;

	if(key_bits < 8*HASH_SIZE + 9)
		return false;

	if(raw.size() != HASH_SIZE)
		return false;

	if(const_coded.size() > KEY_BYTES || const_coded.size() <= 1)
		return false;

	if(const_coded[const_coded.size()-1] != 0xBC)
		return false;

	SafeVector!byte coded = const_coded;
	if(coded.size() < KEY_BYTES)
	{
		SafeVector!byte temp(KEY_BYTES);
		buffer_insert(temp, KEY_BYTES - coded.size(), coded);
		coded = temp;
	}

	const size_t TOP_BITS = 8 * ((key_bits + 7) / 8) - key_bits;
	if(TOP_BITS > 8 - high_bit(coded[0]))
		return false;

	byte* DB = &coded[0];
	const size_t DB_size = coded.size() - HASH_SIZE - 1;

	const byte* H = &coded[DB_size];
	const size_t H_size = HASH_SIZE;

	mgf1_mask(*hash, &H[0], H_size, &DB[0], DB_size);
	DB[0] &= 0xFF >> TOP_BITS;

	size_t salt_offset = 0;
	for(size_t j = 0; j != DB_size; ++j)
	{
		if(DB[j] == 0x01)
		{ salt_offset = j + 1; break; }
		if(DB[j])
			return false;
	}
	if(salt_offset == 0)
		return false;

	for(size_t j = 0; j != 8; ++j)
		hash->update(0);
	hash->update(raw);
	hash->update(&DB[salt_offset], DB_size - salt_offset);
	SafeVector!byte H2 = hash->flush();

	return same_mem(&H[0], &H2[0], HASH_SIZE);
}

PSSR::PSSR(HashFunction* h) :
	SALT_SIZE(h->output_length()), hash(h)
{
}

PSSR::PSSR(HashFunction* h, size_t salt_size) :
	SALT_SIZE(salt_size), hash(h)
{
}

}
