/*
* SRP-6a (RFC 5054 compatatible)
* (C) 2011,2012 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

import botan.srp6;
import botan.dl_group;
import botan.libstate;
import botan.numthry;
namespace {

BigInt hash_seq(in string hash_id,
					 size_t pad_to,
					 ref const BigInt in1,
					 ref const BigInt in2)
{
	Unique!HashFunction hash_fn =
		global_state().algorithm_factory().make_hash_function(hash_id);

	hash_fn.update(BigInt::encode_1363(in1, pad_to));
	hash_fn.update(BigInt::encode_1363(in2, pad_to));

	return BigInt::decode(hash_fn.flush());
}

BigInt compute_x(in string hash_id,
					  in string identifier,
					  in string password,
					  in Vector!ubyte salt)
{
	Unique!HashFunction hash_fn(
		global_state().algorithm_factory().make_hash_function(hash_id));

	hash_fn.update(identifier);
	hash_fn.update(":");
	hash_fn.update(password);

	SafeVector!ubyte inner_h = hash_fn.flush();

	hash_fn.update(salt);
	hash_fn.update(inner_h);

	SafeVector!ubyte outer_h = hash_fn.flush();

	return BigInt::decode(outer_h);
}

}

string srp6_group_identifier(in BigInt N, ref const BigInt g)
{
	/*
	This function assumes that only one 'standard' SRP parameter set has
	been defined for a particular bitsize. As of this writing that is the case.
	*/
	try
	{
		const string group_name = "modp/srp/" ~ std.conv.to!string(N.bits());

		DL_Group group(group_name);

		if (group.get_p() == N && group.get_g() == g)
			return group_name;

		throw new Exception("Unknown SRP params");
	}
	catch
	{
		throw new Invalid_Argument("Bad SRP group parameters");
	}
}

Pair!(BigInt, SymmetricKey)
srp6_client_agree(in string identifier,
						in string password,
						in string group_id,
						in string hash_id,
						in Vector!ubyte salt,
						ref const BigInt B,
						RandomNumberGenerator rng)
{
	DL_Group group(group_id);
	ref const BigInt g = group.get_g();
	ref const BigInt p = group.get_p();

	const size_t p_bytes = group.get_p().bytes();

	if (B <= 0 || B >= p)
		throw new Exception("Invalid SRP parameter from server");

	BigInt k = hash_seq(hash_id, p_bytes, p, g);

	BigInt a(rng, 256);

	BigInt A = power_mod(g, a, p);

	BigInt u = hash_seq(hash_id, p_bytes, A, B);

	const BigInt x = compute_x(hash_id, identifier, password, salt);

	BigInt S = power_mod((B - (k * power_mod(g, x, p))) % p, (a + (u * x)), p);

	SymmetricKey Sk(BigInt::encode_1363(S, p_bytes));

	return Pair(A, Sk);
}

BigInt generate_srp6_verifier(in string identifier,
										in string password,
										in Vector!ubyte salt,
										in string group_id,
										in string hash_id)
{
	const BigInt x = compute_x(hash_id, identifier, password, salt);

	DL_Group group(group_id);
	return power_mod(group.get_g(), x, group.get_p());
}

BigInt SRP6_Server_Session::step1(in BigInt v,
											 in string group_id,
											 in string hash_id,
											 RandomNumberGenerator rng)
{
	DL_Group group(group_id);
	ref const BigInt g = group.get_g();
	ref const BigInt p = group.get_p();

	p_bytes = p.bytes();

	BigInt k = hash_seq(hash_id, p_bytes, p, g);

	BigInt b(rng, 256);

	B = (v*k + power_mod(g, b, p)) % p;

	this.v = v;
	this.b = b;
	this.p = p;
	this.hash_id = hash_id;

	return B;
}

SymmetricKey SRP6_Server_Session::step2(in BigInt A)
{
	if (A <= 0 || A >= p)
		throw new Exception("Invalid SRP parameter from client");

	BigInt u = hash_seq(hash_id, p_bytes, A, B);

	BigInt S = power_mod(A * power_mod(v, u, p), b, p);

	return BigInt::encode_1363(S, p_bytes);
}

}
