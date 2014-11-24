/*
* SRP-6a (RFC 5054 compatatible)
* (C) 2011,2012 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.constructs.srp6;

import botan.math.bigint.bigint;
import botan.hash.hash;
import botan.rng.rng;
import botan.algo_base.symkey;
import botan.pubkey.algo.dl_group;
import botan.libstate.libstate;
import botan.math.numbertheory.numthry;
import botan.utils.types;

// import string;

/**
* SRP6a Client side
* @param username the username we are attempting login for
* @param password the password we are attempting to use
* @param group_id specifies the shared SRP group
* @param hash_id specifies a secure hash function
* @param salt is the salt value sent by the server
* @param B is the server's public value
* @param rng is a random number generator
*
* @return (A,K) the client public key and the shared secret key
*/
Pair!(BigInt, SymmetricKey)
    srp6_client_agree(in string identifier,
                      in string password,
                      in string group_id,
                      in string hash_id,
                      in Vector!ubyte salt,
                      in BigInt B,
                      RandomNumberGenerator rng)
{
    DL_Group group = DL_Group(group_id);
    const BigInt g = group.get_g();
    const BigInt p = group.get_p();
    
    const size_t p_bytes = group.get_p().bytes();
    
    if (B <= 0 || B >= p)
        throw new Exception("Invalid SRP parameter from server");
    
    BigInt k = hash_seq(hash_id, p_bytes, p, g);
    
    BigInt a = BigInt(rng, 256);
    
    BigInt A = power_mod(g, a, p);
    
    BigInt u = hash_seq(hash_id, p_bytes, A, B);
    
    const BigInt x = compute_x(hash_id, identifier, password, salt);
    
    BigInt S = power_mod((B - (k * power_mod(g, x, p))) % p, (a + (u * x)), p);
    
    SymmetricKey Sk = SymmetricKey(BigInt.encode_1363(S, p_bytes));
    
    return Pair(A, Sk);
}


/**
* Generate a new SRP-6 verifier
* @param identifier a username or other client identifier
* @param password the secret used to authenticate user
* @param salt a randomly chosen value, at least 128 bits long
* @param group_id specifies the shared SRP group
* @param hash_id specifies a secure hash function
*/
BigInt generate_srp6_verifier(in string identifier,
                              in string password,
                              in Vector!ubyte salt,
                              in string group_id,
                              in string hash_id)
{
    const BigInt x = compute_x(hash_id, identifier, password, salt);
    
    DL_Group group = DL_Group(group_id);
    return power_mod(group.get_g(), x, group.get_p());
}


/**
* Return the group id for this SRP param set, or else thrown an
* exception
* @param N the group modulus
* @param g the group generator
* @return group identifier
*/
string srp6_group_identifier(in BigInt N, in BigInt g)
{
    /*
    This function assumes that only one 'standard' SRP parameter set has
    been defined for a particular bitsize. As of this writing that is the case.
    */
    try
    {
        const string group_name = "modp/srp/" ~ to!string(N.bits());
        
        DL_Group group = DL_Group(group_name);
        
        if (group.get_p() == N && group.get_g() == g)
            return group_name;
        
        throw new Exception("Unknown SRP params");
    }
    catch
    {
        throw new Invalid_Argument("Bad SRP group parameters");
    }
}

/**
* Represents a SRP-6a server session
*/
final class SRP6_Server_Session
{
public:
    /**
    * Server side step 1
    * @param v the verification value saved from client registration
    * @param group_id the SRP group id
    * @param hash_id the SRP hash in use
    * @param rng a random number generator
    * @return SRP-6 B value
    */
    BigInt step1(in BigInt v,
                 in string group_id,
                 in string hash_id,
                 RandomNumberGenerator rng)
    {
        DL_Group group = DL_Group(group_id);
        const BigInt g = group.get_g();
        const BigInt p = group.get_p();
        
        m_p_bytes = p.bytes();
        
        BigInt k = hash_seq(hash_id, p_bytes, p, g);
        
        BigInt b = BigInt(rng, 256);
        
        m_B = (v*k + power_mod(g, b, p)) % p;
        
        m_v = v;
        m_b = b;
        m_p = p;
        m_hash_id = hash_id;
        
        return m_B;
    }

    /**
    * Server side step 2
    * @param A the client's value
    * @return shared symmetric key
    */
    SymmetricKey step2(in BigInt A)
    {
        if (A <= 0 || A >= p)
            throw new Exception("Invalid SRP parameter from client");
        
        BigInt u = hash_seq(m_hash_id, m_p_bytes, A, m_B);
        
        BigInt S = power_mod(A * power_mod(m_v, u, m_p), m_b, m_p);
        
        return BigInt.encode_1363(S, m_p_bytes);
    }

private:
    string m_hash_id;
    BigInt m_B, m_b, m_v, m_p; // m_S
    size_t m_p_bytes;
}

private:
    
BigInt hash_seq(in string hash_id,
                size_t pad_to,
                in BigInt in1,
                in BigInt in2)
{
    Unique!HashFunction hash_fn = global_state().algorithm_factory().make_hash_function(hash_id);
    
    hash_fn.update(BigInt.encode_1363(in1, pad_to));
    hash_fn.update(BigInt.encode_1363(in2, pad_to));
    
    return BigInt.decode(hash_fn.flush());
}

BigInt compute_x(in string hash_id,
                 in string identifier,
                 in string password,
                 in Vector!ubyte salt)
{
    Unique!HashFunction hash_fn = global_state().algorithm_factory().make_hash_function(hash_id);
    
    hash_fn.update(identifier);
    hash_fn.update(":");
    hash_fn.update(password);
    
    Secure_Vector!ubyte inner_h = hash_fn.flush();
    
    hash_fn.update(salt);
    hash_fn.update(inner_h);
    
    Secure_Vector!ubyte outer_h = hash_fn.flush();
    
    return BigInt.decode(outer_h);
}
