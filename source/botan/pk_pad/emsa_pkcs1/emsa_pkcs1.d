/*
* PKCS #1 v1.5 signature padding
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

import botan.emsa_pkcs1;
import botan.hash_id;
namespace {

SafeVector!byte emsa3_encoding(in SafeVector!byte msg,
											  size_t output_bits,
											  in byte* hash_id,
											  size_t hash_id_length)
{
	size_t output_length = output_bits / 8;
	if (output_length < hash_id_length + msg.size() + 10)
		throw new Encoding_Error("emsa3_encoding: Output length is too small");

	SafeVector!byte T(output_length);
	const size_t P_LENGTH = output_length - msg.size() - hash_id_length - 2;

	T[0] = 0x01;
	set_mem(&T[1], P_LENGTH, 0xFF);
	T[P_LENGTH+1] = 0x00;
	buffer_insert(T, P_LENGTH+2, hash_id, hash_id_length);
	buffer_insert(T, output_length-msg.size(), &msg[0], msg.size());
	return T;
}

}

void EMSA_PKCS1v15::update(in byte* input, size_t length)
{
	m_hash.update(input, length);
}

SafeVector!byte EMSA_PKCS1v15::raw_data()
{
	return m_hash.flush();
}

SafeVector!byte
EMSA_PKCS1v15::encoding_of(in SafeVector!byte msg,
									size_t output_bits,
									RandomNumberGenerator)
{
	if (msg.size() != m_hash.output_length())
		throw new Encoding_Error("EMSA_PKCS1v15::encoding_of: Bad input length");

	return emsa3_encoding(msg, output_bits,
								 &m_hash_id[0], m_hash_id.size());
}

bool EMSA_PKCS1v15::verify(in SafeVector!byte coded,
									in SafeVector!byte raw,
									size_t key_bits)
{
	if (raw.size() != m_hash.output_length())
		return false;

	try
	{
		return (coded == emsa3_encoding(raw, key_bits,
												  &m_hash_id[0], m_hash_id.size()));
	}
	catch(...)
	{
		return false;
	}
}

EMSA_PKCS1v15::EMSA_PKCS1v15(HashFunction hash) : m_hash(hash)
{
	m_hash_id = pkcs_hash_id(m_hash.name());
}

void EMSA_PKCS1v15_Raw::update(in byte* input, size_t length)
{
	message += Pair(input, length);
}

SafeVector!byte EMSA_PKCS1v15_Raw::raw_data()
{
	SafeVector!byte ret;
	std::swap(ret, message);
	return ret;
}

SafeVector!byte
EMSA_PKCS1v15_Raw::encoding_of(in SafeVector!byte msg,
										 size_t output_bits,
										 RandomNumberGenerator)
{
	return emsa3_encoding(msg, output_bits, null, 0);
}

bool EMSA_PKCS1v15_Raw::verify(in SafeVector!byte coded,
										 in SafeVector!byte raw,
										 size_t key_bits)
{
	try
	{
		return (coded == emsa3_encoding(raw, key_bits, null, 0));
	}
	catch(...)
	{
		return false;
	}
}

}
