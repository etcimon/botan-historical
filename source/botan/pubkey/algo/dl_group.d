/*
* Discrete Logarithm Group
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.pubkey.algo.dl_group;

import botan.math.bigint.bigint;
import botan.filters.data_src;
import botan.libstate.libstate;
import botan.utils.parsing;
import botan.math.numbertheory.numthry;
import botan.asn1.der_enc;
import botan.asn1.ber_dec;
import botan.filters.pipe;
import botan.codec.pem;
import botan.pubkey.workfactor;

/**
* This class represents discrete logarithm groups. It holds a prime p,
* a prime q = (p-1)/2 and g = x^((p-1)/q) mod p.
*/
struct DL_Group
{
public:

	/**
	* Get the prime p.
	* @return prime p
	*/
	const ref BigInt get_p() const
	{
		init_check();
		return p;
	}

	/**
	* Get the prime q.
	* @return prime q
	*/
	const ref BigInt get_q() const
	{
		init_check();
		if (q == 0)
			throw new Invalid_State("DLP group has no q prime specified");
		return q;
	}

	/**
	* Get the base g.
	* @return base g
	*/
	const ref BigInt get_g() const
	{
		init_check();
		return g;
	}

	typedef ubyte format;
	/**
	* The DL group encoding format variants.
	*/
	enum : Format {
		ANSI_X9_42,
		ANSI_X9_57,
		PKCS_3,

		DSA_PARAMETERS = ANSI_X9_57,
		DH_PARAMETERS = ANSI_X9_42,
		X942_DH_PARAMETERS = ANSI_X9_42,
		PKCS3_DH_PARAMETERS = PKCS_3
	};

	/**
	* Determine the prime creation for DL groups.
	*/
	enum PrimeType { Strong, Prime_Subgroup, DSA_Kosherizer };

	/**
	* Perform validity checks on the group.
	* @param rng the rng to use
	* @param strong whether to perform stronger by lengthier tests
	* @return true if the object is consistent, false otherwise
	*/
	bool verify_group(RandomNumberGenerator rng,
	                  bool strong) const
	{
		init_check();
		
		if (g < 2 || p < 3 || q < 0)
			return false;
		if ((q != 0) && ((p - 1) % q != 0))
			return false;
		
		const size_t prob = (strong) ? 56 : 10;
		
		if (!is_prime(p, rng, prob))
			return false;
		if ((q > 0) && !is_prime(q, rng, prob))
			return false;
		return true;
	}

	/**
	* Encode this group into a string using PEM encoding.
	* @param format the encoding format
	* @return string holding the PEM encoded group
	*/
	string PEM_encode(Format format) const
	{
		const Vector!ubyte encoding = DER_encode(format);
		
		if (format == PKCS_3)
			return pem.encode(encoding, "DH PARAMETERS");
		else if (format == ANSI_X9_57)
			return pem.encode(encoding, "DSA PARAMETERS");
		else if (format == ANSI_X9_42)
			return pem.encode(encoding, "X942 DH PARAMETERS");
		else
			throw new Invalid_Argument("Unknown DL_Group encoding " ~ std.conv.to!string(format));
	}

	/**
	* Encode this group into a string using DER encoding.
	* @param format the encoding format
	* @return string holding the DER encoded group
	*/
	Vector!ubyte DER_encode(Format format) const
	{
		init_check();
		
		if ((q == 0) && (format != PKCS_3))
			throw new Encoding_Error("The ANSI DL parameter formats require a subgroup");
		
		if (format == ANSI_X9_57)
		{
			return DER_Encoder()
				.start_cons(ASN1_Tag.SEQUENCE)
					.encode(p)
					.encode(q)
					.encode(g)
					.end_cons()
					.get_contents_unlocked();
		}
		else if (format == ANSI_X9_42)
		{
			return DER_Encoder()
				.start_cons(ASN1_Tag.SEQUENCE)
					.encode(p)
					.encode(g)
					.encode(q)
					.end_cons()
					.get_contents_unlocked();
		}
		else if (format == PKCS_3)
		{
			return DER_Encoder()
				.start_cons(ASN1_Tag.SEQUENCE)
					.encode(p)
					.encode(g)
					.end_cons()
					.get_contents_unlocked();
		}
		
		throw new Invalid_Argument("Unknown DL_Group encoding " ~ std.conv.to!string(format));
	}

	/**
	* Decode a DER/BER encoded group into this instance.
	* @param ber a vector containing the DER/BER encoded group
	* @param format the format of the encoded group
	*/
	void BER_decode(in Vector!ubyte data,
	                Format format)
	{
		BigInt new_p, new_q, new_g;
		
		BER_Decoder decoder(data);
		BER_Decoder ber = decoder.start_cons(ASN1_Tag.SEQUENCE);
		
		if (format == ANSI_X9_57)
		{
			ber.decode(new_p)
				.decode(new_q)
					.decode(new_g)
					.verify_end();
		}
		else if (format == ANSI_X9_42)
		{
			ber.decode(new_p)
				.decode(new_g)
					.decode(new_q)
					.discard_remaining();
		}
		else if (format == PKCS_3)
		{
			ber.decode(new_p)
				.decode(new_g)
					.discard_remaining();
		}
		else
			throw new Invalid_Argument("Unknown DL_Group encoding " ~ std.conv.to!string(format));
		
		initialize(new_p, new_q, new_g);
	}

	/**
	* Decode a PEM encoded group into this instance.
	* @param pem the PEM encoding of the group
	*/
	void PEM_decode(in string pem)
	{
		string label;
		
		auto ber = unlock(pem.decode(pem, label));
		
		if (label == "DH PARAMETERS")
			BER_decode(ber, PKCS_3);
		else if (label == "DSA PARAMETERS")
			BER_decode(ber, ANSI_X9_57);
		else if (label == "X942 DH PARAMETERS")
			BER_decode(ber, ANSI_X9_42);
		else
			throw new Decoding_Error("DL_Group: Invalid PEM label " ~ label);
	}

	/**
	* Construct a DL group with uninitialized internal value.
	* Use this constructor is you wish to set the groups values
	* from a DER or PEM encoded group.
	*/
	this()
	{
		initialized = false;
	}

	/**
	* Construct a DL group that is registered in the configuration.
	* @param name the name that is configured in the global configuration
	* for the desired group. If no configuration file is specified,
	* the default values from the file policy.cpp will be used. For instance,
	* use "modp/ietf/768" as name.
	*/
	this(in string name)
	{
		string pem = PEM_for_named_group(name);
		
		if (!pem)
			throw new Invalid_Argument("DL_Group: Unknown group " ~ name);
		
		PEM_decode(pem);
	}

	/**
	* Create a new group randomly.
	* @param rng the random number generator to use
	* @param type specifies how the creation of primes p and q shall
	* be performed. If type=Strong, then p will be determined as a
	* safe prime, and q will be chosen as (p-1)/2. If
	* type=Prime_Subgroup and qbits = 0, then the size of q will be
	* determined according to the estimated difficulty of the DL
	* problem. If type=DSA_Kosherizer, DSA primes will be created.
	* @param pbits the number of bits of p
	* @param qbits the number of bits of q. Leave it as 0 to have
	* the value determined according to pbits.
	*/
	this(RandomNumberGenerator rng,
	     PrimeType type, size_t pbits, size_t qbits = 0)
	{
		if (pbits < 512)
			throw new Invalid_Argument("DL_Group: prime size " ~ std.conv.to!string(pbits) +
			                           " is too small");
		
		if (type == Strong)
		{
			p = random_safe_prime(rng, pbits);
			q = (p - 1) / 2;
			g = 2;
		}
		else if (type == Prime_Subgroup)
		{
			if (!qbits)
				qbits = 2 * dl_work_factor(pbits);
			
			q = random_prime(rng, qbits);
			BigInt X;
			while(p.bits() != pbits || !is_prime(p, rng))
			{
				X.randomize(rng, pbits);
				p = X - (X % (2*q) - 1);
			}
			
			g = make_dsa_generator(p, q);
		}
		else if (type == DSA_Kosherizer)
		{
			qbits = qbits ? qbits : ((pbits <= 1024) ? 160 : 256);
			
			generate_dsa_primes(rng,
			                    global_state().algorithm_factory(),
			                    p, q,
			                    pbits, qbits);
			
			g = make_dsa_generator(p, q);
		}
		
		initialized = true;
	}

	/**
	* Create a DSA group with a given seed.
	* @param rng the random number generator to use
	* @param seed the seed to use to create the random primes
	* @param pbits the desired bit size of the prime p
	* @param qbits the desired bit size of the prime q.
	*/
	this(RandomNumberGenerator rng,
	     in Vector!ubyte seed,
	     size_t pbits = 1024, size_t qbits = 0)
	{
		if (!generate_dsa_primes(rng,
		                         global_state().algorithm_factory(),
		                         p, q, pbits, qbits, seed))
			throw new Invalid_Argument("DL_Group: The seed given does not "
			                           "generate a DSA group");
		
		g = make_dsa_generator(p, q);
		
		initialized = true;
	}

	/**
	* Create a DL group. The prime q will be determined according to p.
	* @param p1 the prime p
	* @param g1 the base g
	*/
	this(in BigInt p1, const ref BigInt g1)
	{
		initialize(p1, 0, g1);
	}

	/**
	* Create a DL group.
	* @param p1 the prime p
	* @param q1 the prime q
	* @param g1 the base g
	*/
	this(in BigInt p1, const ref BigInt q1, const ref BigInt g1)
	{
		initialize(p1, q1, g1);
	}


	static string PEM_for_named_group(in string name);
private:
	/*
	* Create generator of the q-sized subgroup (DSA style generator)
	*/
	static BigInt make_dsa_generator(in BigInt p, const ref BigInt q)
	{
		const BigInt e = (p - 1) / q;
		
		if (e == 0 || (p - 1) % q > 0)
			throw new Invalid_Argument("make_dsa_generator q does not divide p-1");
		
		for (size_t i = 0; i != PRIME_TABLE_SIZE; ++i)
		{
			BigInt g = power_mod(PRIMES[i], e, p);
			if (g > 1)
				return g;
		}
		
		throw new Internal_Error("DL_Group: Couldn't create a suitable generator");
	}

	void init_check() const
	{
		if (!initialized)
			throw new Invalid_State("DLP group cannot be used uninitialized");
	}

	void initialize(in BigInt p1, const ref BigInt q1, const ref BigInt g1)
	{
		if (p1 < 3)
			throw new Invalid_Argument("DL_Group: Prime invalid");
		if (g1 < 2 || g1 >= p1)
			throw new Invalid_Argument("DL_Group: Generator invalid");
		if (q1 < 0 || q1 >= p1)
			throw new Invalid_Argument("DL_Group: Subgroup invalid");
		
		p = p1;
		g = g1;
		q = q1;
		
		initialized = true;
	}

	bool initialized;
	BigInt p, q, g;

	/**
	* Return PEM representation of named DL group
	*/
	public static string PEM_for_named_group(in string name)
	{
		if (name == "modp/ietf/1024")
			return
				"-----BEGIN X942 DH PARAMETERS-----"
				"MIIBCgKBgQD//////////8kP2qIhaMI0xMZii4DcHNEpAk4IimfMdAILvqY7E5si"
				"UUoIeY40BN3vlRmzzTpDGzArCm3yXxQ3T+E1bW1RwkXkhbV2Yl5+xvRMQummN+1r"
				"C/9ctvQGt+3uOGv7Womfpa6fJBF8Sx/mSShmUezmU4H//////////wIBAgKBgH//"
				"////////5IftURC0YRpiYzFFwG4OaJSBJwRFM+Y6AQXfUx2JzZEopQQ8xxoCbvfK"
				"jNnmnSGNmBWFNvkvihun8Jq2tqjhIvJC2rsxLz9jeiYhdNMb9rWF/65begNb9vcc"
				"Nf2tRM/S10+SCL4lj/MklDMo9nMpwP//////////"
				"-----END X942 DH PARAMETERS-----";
		
		if (name == "modp/srp/1024")
			return
				"-----BEGIN X942 DH PARAMETERS-----"
				"MIIBCgKBgQDurwq5rbON1pwz+Ar6j8XoYHJhh3X/PAueojFMnCVldtZ033SW6oHT"
				"ODtIE9aSxuDg1djiULmL5I5JXB1gidrRXcfXtGFU1rbOjvStabFdSYJVmyl7zxiF"
				"xSn1ZmYOV+xo7bw8BXJswC/Uy/SXbqqa/VE4/oN2Q1ufxh0vwOsG4wIBAgKBgHdX"
				"hVzW2cbrThn8BX1H4vQwOTDDuv+eBc9RGKZOErK7azpvukt1QOmcHaQJ60ljcHBq"
				"7HEoXMXyRySuDrBE7Wiu4+vaMKprW2dHela02K6kwSrNlL3njELilPqzMwcr9jR2"
				"3h4CuTZgF+pl+ku3VU1+qJx/Qbshrc/jDpfgdYNx"
				"-----END X942 DH PARAMETERS-----";
		
		if (name == "modp/ietf/1536")
			return
				"-----BEGIN X942 DH PARAMETERS-----"
				"MIIBigKBwQD//////////8kP2qIhaMI0xMZii4DcHNEpAk4IimfMdAILvqY7E5si"
				"UUoIeY40BN3vlRmzzTpDGzArCm3yXxQ3T+E1bW1RwkXkhbV2Yl5+xvRMQummN+1r"
				"C/9ctvQGt+3uOGv7Womfpa6fJBF8Sx/mSShmUezkWz3CAHy4oWO/BZjaSDYcVdOa"
				"aRY/qP0kz1+DZV0j3KOtlhxi81YghVK7ntUpB3CWlm1nDDVOSryYBPF0bAjKI3Mn"
				"//////////8CAQICgcB//////////+SH7VEQtGEaYmMxRcBuDmiUgScERTPmOgEF"
				"31Mdic2RKKUEPMcaAm73yozZ5p0hjZgVhTb5L4obp/Catrao4SLyQtq7MS8/Y3om"
				"IXTTG/a1hf+uW3oDW/b3HDX9rUTP0tdPkgi+JY/zJJQzKPZyLZ7hAD5cULHfgsxt"
				"JBsOKunNNIsf1H6SZ6/Bsq6R7lHWyw4xeasQQqldz2qUg7hLSzazhhqnJV5MAni6"
				"NgRlEbmT//////////8="
				"-----END X942 DH PARAMETERS-----";
		
		if (name == "modp/srp/1536")
			return
				"-----BEGIN DH PARAMETERS-----"
				"MIHHAoHBAJ3vPK+5OSd6sfEqhheke7vbpR30maxMgL7uqWFLGcxNX09fVW4ny95R"
				"xqlL5GB6KRVYkDug0PhDgLZVu5oi6NzfAop87Gfw0IE0sci5eYkUm2CeC+O6tj1H"
				"VIOB28Wx/HZOP0tT3Z2hFYv9PiucjPVu3wGVOTSWJ9sv1T0kt8SGZXcuQ31sf4zk"
				"QnNK98y3roN8Jkrjqb64f4ov6bi1KS5aAh//XpFHnoznoowkQsbzFRgPk0maI03P"
				"duP+0TX5uwIBAg=="
				"-----END DH PARAMETERS-----";
		
		if (name == "modp/ietf/2048")
			return
				"-----BEGIN X942 DH PARAMETERS-----"
				"MIICDAKCAQEA///////////JD9qiIWjCNMTGYouA3BzRKQJOCIpnzHQCC76mOxOb"
				"IlFKCHmONATd75UZs806QxswKwpt8l8UN0/hNW1tUcJF5IW1dmJefsb0TELppjft"
				"awv/XLb0Brft7jhr+1qJn6WunyQRfEsf5kkoZlHs5Fs9wgB8uKFjvwWY2kg2HFXT"
				"mmkWP6j9JM9fg2VdI9yjrZYcYvNWIIVSu57VKQdwlpZtZww1Tkq8mATxdGwIyhgh"
				"fDKQXkYuNs474553LBgOhgObJ4Oi7Aeij7XFXfBvTFLJ3ivL9pVYFxg5lUl86pVq"
				"5RXSJhiY+gUQFXKOWoqsqmj//////////wIBAgKCAQB//////////+SH7VEQtGEa"
				"YmMxRcBuDmiUgScERTPmOgEF31Mdic2RKKUEPMcaAm73yozZ5p0hjZgVhTb5L4ob"
				"p/Catrao4SLyQtq7MS8/Y3omIXTTG/a1hf+uW3oDW/b3HDX9rUTP0tdPkgi+JY/z"
				"JJQzKPZyLZ7hAD5cULHfgsxtJBsOKunNNIsf1H6SZ6/Bsq6R7lHWyw4xeasQQqld"
				"z2qUg7hLSzazhhqnJV5MAni6NgRlDBC+GUgvIxcbZx3xzzuWDAdDAc2TwdF2A9FH"
				"2uKu+DemKWTvFeX7SqwLjBzKpL51SrVyiukTDEx9AogKuUctRVZVNH//////////"
				"-----END X942 DH PARAMETERS-----";
		
		if (name == "modp/srp/2048")
			return
				"-----BEGIN X942 DH PARAMETERS-----"
				"MIICDAKCAQEArGvbQTJKmpvxZt5eE4lYL69ytmUZh+4H/DGSlD21YFCjcynLtKCZ"
				"7YGT4HV3Z6E91SMSq0sDMQ3Nf0ip2gT9UOgIOWntt2ewz2CVF5oWOrNmGgX71fqq"
				"6CkYqZYvC5O4Vfl5k+yXXuqoDXQK2/T/dHNZ0EHVwz6nHSgeRGsUdzvKl7Q6I/uA"
				"Fna9IHpDbGSB8dK5B4cXRhpbnTLmiPh3SFRFI7UksNV9Xqd6J3XS7PoDLPvb9S+z"
				"eGFgJ5AE5Xrmr4dOcwPOUymczAQce8MI2CpWmPOo0MOCca41+Onb+7aUtcgD2J96"
				"5DXeI21SX1R1m2XjcvzWjvIPpxEfnkr/cwIBAgKCAQBWNe2gmSVNTfizby8JxKwX"
				"17lbMozD9wP+GMlKHtqwKFG5lOXaUEz2wMnwOruz0J7qkYlVpYGYhua/pFTtAn6o"
				"dAQctPbbs9hnsEqLzQsdWbMNAv3q/VV0FIxUyxeFydwq/LzJ9kuvdVQGugVt+n+6"
				"OazoIOrhn1OOlA8iNYo7neVL2h0R/cALO16QPSG2MkD46VyDw4ujDS3OmXNEfDuk"
				"KiKR2pJYar6vU70Tuul2fQGWfe36l9m8MLATyAJyvXNXw6c5gecplM5mAg494YRs"
				"FStMedRoYcE41xr8dO3920pa5AHsT71yGu8RtqkvqjrNsvG5fmtHeQfTiI/PJX+5"
				"-----END X942 DH PARAMETERS-----";
		
		if (name == "modp/ietf/3072")
			return
				"-----BEGIN X942 DH PARAMETERS-----"
				"MIIDDAKCAYEA///////////JD9qiIWjCNMTGYouA3BzRKQJOCIpnzHQCC76mOxOb"
				"IlFKCHmONATd75UZs806QxswKwpt8l8UN0/hNW1tUcJF5IW1dmJefsb0TELppjft"
				"awv/XLb0Brft7jhr+1qJn6WunyQRfEsf5kkoZlHs5Fs9wgB8uKFjvwWY2kg2HFXT"
				"mmkWP6j9JM9fg2VdI9yjrZYcYvNWIIVSu57VKQdwlpZtZww1Tkq8mATxdGwIyhgh"
				"fDKQXkYuNs474553LBgOhgObJ4Oi7Aeij7XFXfBvTFLJ3ivL9pVYFxg5lUl86pVq"
				"5RXSJhiY+gUQFXKOWoqqxC2tMxcNBFB6M6hVIavfHLpk7PuFBFjb7wqK6nFXXQYM"
				"fbOXD4Wm4eTHq/WujNsJM9cejJTgSiVhnc7j0iYa0u5r8S/6BtmKCGTYdgJzPshq"
				"ZFIfKxgXeyAMu+EXV3phXWx3CYjAutlG4gjiT6B05asxQ9tb/OD9EI5LgtEgqTrS"
				"yv//////////AgECAoIBgH//////////5IftURC0YRpiYzFFwG4OaJSBJwRFM+Y6"
				"AQXfUx2JzZEopQQ8xxoCbvfKjNnmnSGNmBWFNvkvihun8Jq2tqjhIvJC2rsxLz9j"
				"eiYhdNMb9rWF/65begNb9vccNf2tRM/S10+SCL4lj/MklDMo9nItnuEAPlxQsd+C"
				"zG0kGw4q6c00ix/UfpJnr8GyrpHuUdbLDjF5qxBCqV3PapSDuEtLNrOGGqclXkwC"
				"eLo2BGUMEL4ZSC8jFxtnHfHPO5YMB0MBzZPB0XYD0Ufa4q74N6YpZO8V5ftKrAuM"
				"HMqkvnVKtXKK6RMMTH0CiAq5Ry1FVWIW1pmLhoIoPRnUKpDV745dMnZ9woIsbfeF"
				"RXU4q66DBj7Zy4fC03DyY9X610ZthJnrj0ZKcCUSsM7ncekTDWl3NfiX/QNsxQQy"
				"bDsBOZ9kNTIpD5WMC72QBl3wi6u9MK62O4TEYF1so3EEcSfQOnLVmKHtrf5wfohH"
				"JcFokFSdaWV//////////w=="
				"-----END X942 DH PARAMETERS-----";
		
		if (name == "modp/srp/3072")
			return
				"-----BEGIN DH PARAMETERS-----"
				"MIIBiAKCAYEA///////////JD9qiIWjCNMTGYouA3BzRKQJOCIpnzHQCC76mOxOb"
				"IlFKCHmONATd75UZs806QxswKwpt8l8UN0/hNW1tUcJF5IW1dmJefsb0TELppjft"
				"awv/XLb0Brft7jhr+1qJn6WunyQRfEsf5kkoZlHs5Fs9wgB8uKFjvwWY2kg2HFXT"
				"mmkWP6j9JM9fg2VdI9yjrZYcYvNWIIVSu57VKQdwlpZtZww1Tkq8mATxdGwIyhgh"
				"fDKQXkYuNs474553LBgOhgObJ4Oi7Aeij7XFXfBvTFLJ3ivL9pVYFxg5lUl86pVq"
				"5RXSJhiY+gUQFXKOWoqqxC2tMxcNBFB6M6hVIavfHLpk7PuFBFjb7wqK6nFXXQYM"
				"fbOXD4Wm4eTHq/WujNsJM9cejJTgSiVhnc7j0iYa0u5r8S/6BtmKCGTYdgJzPshq"
				"ZFIfKxgXeyAMu+EXV3phXWx3CYjAutlG4gjiT6B05asxQ9tb/OD9EI5LgtEgqTrS"
				"yv//////////AgEF"
				"-----END DH PARAMETERS-----";
		
		if (name == "modp/ietf/4096")
			return
				"-----BEGIN X942 DH PARAMETERS-----"
				"MIIEDAKCAgEA///////////JD9qiIWjCNMTGYouA3BzRKQJOCIpnzHQCC76mOxOb"
				"IlFKCHmONATd75UZs806QxswKwpt8l8UN0/hNW1tUcJF5IW1dmJefsb0TELppjft"
				"awv/XLb0Brft7jhr+1qJn6WunyQRfEsf5kkoZlHs5Fs9wgB8uKFjvwWY2kg2HFXT"
				"mmkWP6j9JM9fg2VdI9yjrZYcYvNWIIVSu57VKQdwlpZtZww1Tkq8mATxdGwIyhgh"
				"fDKQXkYuNs474553LBgOhgObJ4Oi7Aeij7XFXfBvTFLJ3ivL9pVYFxg5lUl86pVq"
				"5RXSJhiY+gUQFXKOWoqqxC2tMxcNBFB6M6hVIavfHLpk7PuFBFjb7wqK6nFXXQYM"
				"fbOXD4Wm4eTHq/WujNsJM9cejJTgSiVhnc7j0iYa0u5r8S/6BtmKCGTYdgJzPshq"
				"ZFIfKxgXeyAMu+EXV3phXWx3CYjAutlG4gjiT6B05asxQ9tb/OD9EI5LgtEgqSEI"
				"ARpyPBKnh+bXiHGaEL26WyaZwycYavTiPBqUaDS2FQvaJYPpyirUTOjbu8LbBN6O"
				"+S6O/BQfvsqmKHxZR05rwF2ZspZPoJDDoiM7oYZRW+ftH2EpcM7i16+4G912IXBI"
				"HNAGkSfVsFqpk7TqmI2P3cGG/7fckKbAj030Nck0BjGZ//////////8CAQICggIA"
				"f//////////kh+1RELRhGmJjMUXAbg5olIEnBEUz5joBBd9THYnNkSilBDzHGgJu"
				"98qM2eadIY2YFYU2+S+KG6fwmra2qOEi8kLauzEvP2N6JiF00xv2tYX/rlt6A1v2"
				"9xw1/a1Ez9LXT5IIviWP8ySUMyj2ci2e4QA+XFCx34LMbSQbDirpzTSLH9R+kmev"
				"wbKuke5R1ssOMXmrEEKpXc9qlIO4S0s2s4YapyVeTAJ4ujYEZQwQvhlILyMXG2cd"
				"8c87lgwHQwHNk8HRdgPRR9rirvg3pilk7xXl+0qsC4wcyqS+dUq1corpEwxMfQKI"
				"CrlHLUVVYhbWmYuGgig9GdQqkNXvjl0ydn3Cgixt94VFdTirroMGPtnLh8LTcPJj"
				"1frXRm2EmeuPRkpwJRKwzudx6RMNaXc1+Jf9A2zFBDJsOwE5n2Q1MikPlYwLvZAG"
				"XfCLq70wrrY7hMRgXWyjcQRxJ9A6ctWYoe2t/nB+iEclwWiQVJCEAI05HglTw/Nr"
				"xDjNCF7dLZNM4ZOMNXpxHg1KNBpbCoXtEsH05RVqJnRt3eFtgm9HfJdHfgoP32VT"
				"FD4so6c14C7M2Usn0Ehh0RGd0MMorfP2j7CUuGdxa9fcDe67ELgkDmgDSJPq2C1U"
				"ydp1TEbH7uDDf9vuSFNgR6b6GuSaAxjM//////////8="
				"-----END X942 DH PARAMETERS-----";
		
		if (name == "modp/srp/4096")
			return
				"-----BEGIN DH PARAMETERS-----"
				"MIICCAKCAgEA///////////JD9qiIWjCNMTGYouA3BzRKQJOCIpnzHQCC76mOxOb"
				"IlFKCHmONATd75UZs806QxswKwpt8l8UN0/hNW1tUcJF5IW1dmJefsb0TELppjft"
				"awv/XLb0Brft7jhr+1qJn6WunyQRfEsf5kkoZlHs5Fs9wgB8uKFjvwWY2kg2HFXT"
				"mmkWP6j9JM9fg2VdI9yjrZYcYvNWIIVSu57VKQdwlpZtZww1Tkq8mATxdGwIyhgh"
				"fDKQXkYuNs474553LBgOhgObJ4Oi7Aeij7XFXfBvTFLJ3ivL9pVYFxg5lUl86pVq"
				"5RXSJhiY+gUQFXKOWoqqxC2tMxcNBFB6M6hVIavfHLpk7PuFBFjb7wqK6nFXXQYM"
				"fbOXD4Wm4eTHq/WujNsJM9cejJTgSiVhnc7j0iYa0u5r8S/6BtmKCGTYdgJzPshq"
				"ZFIfKxgXeyAMu+EXV3phXWx3CYjAutlG4gjiT6B05asxQ9tb/OD9EI5LgtEgqSEI"
				"ARpyPBKnh+bXiHGaEL26WyaZwycYavTiPBqUaDS2FQvaJYPpyirUTOjbu8LbBN6O"
				"+S6O/BQfvsqmKHxZR05rwF2ZspZPoJDDoiM7oYZRW+ftH2EpcM7i16+4G912IXBI"
				"HNAGkSfVsFqpk7TqmI2P3cGG/7fckKbAj030Nck0BjGZ//////////8CAQU="
				"-----END DH PARAMETERS-----";
		
		if (name == "modp/ietf/6144")
			return
				"-----BEGIN X942 DH PARAMETERS-----"
				"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"
				"jzbmIBJ//////////wIBAg=="
				"-----END X942 DH PARAMETERS-----";
		
		if (name == "modp/srp/6144")
			return
				"-----BEGIN DH PARAMETERS-----"
				"MIIDCAKCAwEA///////////JD9qiIWjCNMTGYouA3BzRKQJOCIpnzHQCC76mOxOb"
				"IlFKCHmONATd75UZs806QxswKwpt8l8UN0/hNW1tUcJF5IW1dmJefsb0TELppjft"
				"awv/XLb0Brft7jhr+1qJn6WunyQRfEsf5kkoZlHs5Fs9wgB8uKFjvwWY2kg2HFXT"
				"mmkWP6j9JM9fg2VdI9yjrZYcYvNWIIVSu57VKQdwlpZtZww1Tkq8mATxdGwIyhgh"
				"fDKQXkYuNs474553LBgOhgObJ4Oi7Aeij7XFXfBvTFLJ3ivL9pVYFxg5lUl86pVq"
				"5RXSJhiY+gUQFXKOWoqqxC2tMxcNBFB6M6hVIavfHLpk7PuFBFjb7wqK6nFXXQYM"
				"fbOXD4Wm4eTHq/WujNsJM9cejJTgSiVhnc7j0iYa0u5r8S/6BtmKCGTYdgJzPshq"
				"ZFIfKxgXeyAMu+EXV3phXWx3CYjAutlG4gjiT6B05asxQ9tb/OD9EI5LgtEgqSEI"
				"ARpyPBKnh+bXiHGaEL26WyaZwycYavTiPBqUaDS2FQvaJYPpyirUTOjbu8LbBN6O"
				"+S6O/BQfvsqmKHxZR05rwF2ZspZPoJDDoiM7oYZRW+ftH2EpcM7i16+4G912IXBI"
				"HNAGkSfVsFqpk7TqmI2P3cGG/7fckKbAj030Nck0AoSSNsP6tNJ8cCbB1NyyYCZG"
				"3sl1HnY9uje9+P+UBq2eUw7l2zgvQTABrrBqU+2QJ9gxF5cnsIZaiRjaPtvrz5sU"
				"7UTObLrO1Lsb238UR+bMJUszIFFRK9evQm+49AE3jNK/WYPKAcZLkuzwMuoV0XId"
				"A/SC185udP721V5wL0aYDIK1qEAxkAscnlnnyX++x+jzI6l6fjbMiL4PHUW3/1ha"
				"xUvUB7IrQVSqzI9tfr9I4dgUzF7SD4A34KeXFe7ym+MoBqHVi7fF2nb1UKo9ih+/"
				"8OsZzLGjE9Vc2lbJ7C7yljI4f+jXbjwEaAQ+j2Y/SGDuEr8tWwt0dNbmlPkebcxA"
				"JP//////////AgEF"
				"-----END DH PARAMETERS-----";
		
		if (name == "modp/ietf/8192")
			return
				"-----BEGIN X942 DH PARAMETERS-----"
				"MIIIDAKCBAEA///////////JD9qiIWjCNMTGYouA3BzRKQJOCIpnzHQCC76mOxOb"
				"IlFKCHmONATd75UZs806QxswKwpt8l8UN0/hNW1tUcJF5IW1dmJefsb0TELppjft"
				"awv/XLb0Brft7jhr+1qJn6WunyQRfEsf5kkoZlHs5Fs9wgB8uKFjvwWY2kg2HFXT"
				"mmkWP6j9JM9fg2VdI9yjrZYcYvNWIIVSu57VKQdwlpZtZww1Tkq8mATxdGwIyhgh"
				"fDKQXkYuNs474553LBgOhgObJ4Oi7Aeij7XFXfBvTFLJ3ivL9pVYFxg5lUl86pVq"
				"5RXSJhiY+gUQFXKOWoqqxC2tMxcNBFB6M6hVIavfHLpk7PuFBFjb7wqK6nFXXQYM"
				"fbOXD4Wm4eTHq/WujNsJM9cejJTgSiVhnc7j0iYa0u5r8S/6BtmKCGTYdgJzPshq"
				"ZFIfKxgXeyAMu+EXV3phXWx3CYjAutlG4gjiT6B05asxQ9tb/OD9EI5LgtEgqSEI"
				"ARpyPBKnh+bXiHGaEL26WyaZwycYavTiPBqUaDS2FQvaJYPpyirUTOjbu8LbBN6O"
				"+S6O/BQfvsqmKHxZR05rwF2ZspZPoJDDoiM7oYZRW+ftH2EpcM7i16+4G912IXBI"
				"HNAGkSfVsFqpk7TqmI2P3cGG/7fckKbAj030Nck0AoSSNsP6tNJ8cCbB1NyyYCZG"
				"3sl1HnY9uje9+P+UBq2eUw7l2zgvQTABrrBqU+2QJ9gxF5cnsIZaiRjaPtvrz5sU"
				"7UTObLrO1Lsb238UR+bMJUszIFFRK9evQm+49AE3jNK/WYPKAcZLkuzwMuoV0XId"
				"A/SC185udP721V5wL0aYDIK1qEAxkAscnlnnyX++x+jzI6l6fjbMiL4PHUW3/1ha"
				"xUvUB7IrQVSqzI9tfr9I4dgUzF7SD4A34KeXFe7ym+MoBqHVi7fF2nb1UKo9ih+/"
				"8OsZzLGjE9Vc2lbJ7C7yljI4f+jXbjwEaAQ+j2Y/SGDuEr8tWwt0dNbmlPkebb4R"
				"WXSjkm8S/uXkOHd8tqky34zYvsTQc7kxujvIMraNndMAdB+nv4r8R+0ldvaTa6Qk"
				"ZjqrY5xa5PVoNCO0dCvxyXgjjxbL451lLeP9uL78hIrZIiIuBKQDfAcT61eoGiPw"
				"xzRz/GRs6jBrS8vIhi+Dhd36nUt/osCH6HloMwPtW906Bis89bOieKZtKhP4P0T4"
				"Ld8xDuB0q2o2RZfomaAlXcFk8xzFCEaFHfmrSBld7X6hsdUQvX7nTXP682vDHs+i"
				"aDWQRvTrh5+SQAlDi0gcbNeImgAu1e44K8kZDab8Am5HlVjkR1Z36aqeMFDidlaU"
				"38gfVuiAuW5xYMmA3Zjt09///////////wKCBAB//////////+SH7VEQtGEaYmMx"
				"RcBuDmiUgScERTPmOgEF31Mdic2RKKUEPMcaAm73yozZ5p0hjZgVhTb5L4obp/Ca"
				"trao4SLyQtq7MS8/Y3omIXTTG/a1hf+uW3oDW/b3HDX9rUTP0tdPkgi+JY/zJJQz"
				"KPZyLZ7hAD5cULHfgsxtJBsOKunNNIsf1H6SZ6/Bsq6R7lHWyw4xeasQQqldz2qU"
				"g7hLSzazhhqnJV5MAni6NgRlDBC+GUgvIxcbZx3xzzuWDAdDAc2TwdF2A9FH2uKu"
				"+DemKWTvFeX7SqwLjBzKpL51SrVyiukTDEx9AogKuUctRVViFtaZi4aCKD0Z1CqQ"
				"1e+OXTJ2fcKCLG33hUV1OKuugwY+2cuHwtNw8mPV+tdGbYSZ649GSnAlErDO53Hp"
				"Ew1pdzX4l/0DbMUEMmw7ATmfZDUyKQ+VjAu9kAZd8IurvTCutjuExGBdbKNxBHEn"
				"0Dpy1Zih7a3+cH6IRyXBaJBUkIQAjTkeCVPD82vEOM0IXt0tk0zhk4w1enEeDUo0"
				"GlsKhe0SwfTlFWomdG3d4W2Cb0d8l0d+Cg/fZVMUPiyjpzXgLszZSyfQSGHREZ3Q"
				"wyit8/aPsJS4Z3Fr19wN7rsQuCQOaANIk+rYLVTJ2nVMRsfu4MN/2+5IU2BHpvoa"
				"5JoBQkkbYf1aaT44E2DqblkwEyNvZLqPOx7dG978f8oDVs8ph3LtnBegmADXWDUp"
				"9sgT7BiLy5PYQy1EjG0fbfXnzYp2omc2XWdqXY3tv4oj82YSpZmQKKiV69ehN9x6"
				"AJvGaV+sweUA4yXJdngZdQrouQ6B+kFr5zc6f3tqrzgXo0wGQVrUIBjIBY5PLPPk"
				"v99j9HmR1L0/G2ZEXweOotv/rC1ipeoD2RWgqlVmR7a/X6Rw7ApmL2kHwBvwU8uK"
				"93lN8ZQDUOrF2+LtO3qoVR7FD9/4dYzmWNGJ6q5tK2T2F3lLGRw/9Gu3HgI0Ah9H"
				"sx+kMHcJX5athbo6a3NKfI823wisulHJN4l/cvIcO75bVJlvxmxfYmg53JjdHeQZ"
				"W0bO6YA6D9PfxX4j9pK7e0m10hIzHVWxzi1yerQaEdo6FfjkvBHHi2XxzrKW8f7c"
				"X35CRWyRERcCUgG+A4n1q9QNEfhjmjn+MjZ1GDWl5eRDF8HC7v1Opb/RYEP0PLQZ"
				"gfat7p0DFZ562dE8UzaVCfwfonwW75iHcDpVtRsiy/RM0BKu4LJ5jmKEI0KO/NWk"
				"DK72v1DY6ohev3Omuf15teGPZ9E0GsgjenXDz8kgBKHFpA42a8RNABdq9xwV5IyG"
				"034BNyPKrHIjqzv01U8YKHE7K0pv5A+rdEBctziwZMBuzHbp7///////////AgEC"
				"-----END X942 DH PARAMETERS-----";
		
		if (name == "modp/srp/8192")
			return
				"-----BEGIN DH PARAMETERS-----"
				"MIIECAKCBAEA///////////JD9qiIWjCNMTGYouA3BzRKQJOCIpnzHQCC76mOxOb"
				"IlFKCHmONATd75UZs806QxswKwpt8l8UN0/hNW1tUcJF5IW1dmJefsb0TELppjft"
				"awv/XLb0Brft7jhr+1qJn6WunyQRfEsf5kkoZlHs5Fs9wgB8uKFjvwWY2kg2HFXT"
				"mmkWP6j9JM9fg2VdI9yjrZYcYvNWIIVSu57VKQdwlpZtZww1Tkq8mATxdGwIyhgh"
				"fDKQXkYuNs474553LBgOhgObJ4Oi7Aeij7XFXfBvTFLJ3ivL9pVYFxg5lUl86pVq"
				"5RXSJhiY+gUQFXKOWoqqxC2tMxcNBFB6M6hVIavfHLpk7PuFBFjb7wqK6nFXXQYM"
				"fbOXD4Wm4eTHq/WujNsJM9cejJTgSiVhnc7j0iYa0u5r8S/6BtmKCGTYdgJzPshq"
				"ZFIfKxgXeyAMu+EXV3phXWx3CYjAutlG4gjiT6B05asxQ9tb/OD9EI5LgtEgqSEI"
				"ARpyPBKnh+bXiHGaEL26WyaZwycYavTiPBqUaDS2FQvaJYPpyirUTOjbu8LbBN6O"
				"+S6O/BQfvsqmKHxZR05rwF2ZspZPoJDDoiM7oYZRW+ftH2EpcM7i16+4G912IXBI"
				"HNAGkSfVsFqpk7TqmI2P3cGG/7fckKbAj030Nck0AoSSNsP6tNJ8cCbB1NyyYCZG"
				"3sl1HnY9uje9+P+UBq2eUw7l2zgvQTABrrBqU+2QJ9gxF5cnsIZaiRjaPtvrz5sU"
				"7UTObLrO1Lsb238UR+bMJUszIFFRK9evQm+49AE3jNK/WYPKAcZLkuzwMuoV0XId"
				"A/SC185udP721V5wL0aYDIK1qEAxkAscnlnnyX++x+jzI6l6fjbMiL4PHUW3/1ha"
				"xUvUB7IrQVSqzI9tfr9I4dgUzF7SD4A34KeXFe7ym+MoBqHVi7fF2nb1UKo9ih+/"
				"8OsZzLGjE9Vc2lbJ7C7yljI4f+jXbjwEaAQ+j2Y/SGDuEr8tWwt0dNbmlPkebb4R"
				"WXSjkm8S/uXkOHd8tqky34zYvsTQc7kxujvIMraNndMAdB+nv4r8R+0ldvaTa6Qk"
				"ZjqrY5xa5PVoNCO0dCvxyXgjjxbL451lLeP9uL78hIrZIiIuBKQDfAcT61eoGiPw"
				"xzRz/GRs6jBrS8vIhi+Dhd36nUt/osCH6HloMwPtW906Bis89bOieKZtKhP4P0T4"
				"Ld8xDuB0q2o2RZfomaAlXcFk8xzFCEaFHfmrSBld7X6hsdUQvX7nTXP682vDHs+i"
				"aDWQRvTrh5+SQAlDi0gcbNeImgAu1e44K8kZDab8Am5HlVjkR1Z36aqeMFDidlaU"
				"38gfVuiAuW5xYMmA3Zjt09///////////wIBEw=="
				"-----END DH PARAMETERS-----";
		
		if (name == "dsa/jce/1024")
			return
				"-----BEGIN DSA PARAMETERS-----"
				"MIIBHgKBgQD9f1OBHXUSKVLfSpwu7OTn9hG3UjzvRADDHj+AtlEmaUVdQCJR+1k9"
				"jVj6v8X1ujD2y5tVbNeBO4AdNG/yZmC3a5lQpaSfn+gEexAiwk+7qdf+t8Yb+DtX"
				"58aophUPBPuD9tPFHsMCNVQTWhaRMvZ1864rYdcq7/IiAxmd0UgBxwIVAJdgUI8V"
				"IwvMspK5gqLrhAvwWBz1AoGARpYDUS4wJ4zTlHWV2yLuyYJqYyKtyXNE9B10DDJX"
				"JMj577qn1NgD/4xgnc0QDrxb38+tfGpCX66nhuogUOvpg1HqH9of3yTWlHqmuaoj"
				"dmlTgC9NfUqOy6BtGXaKJJH/sW0O+cQ6mbX3FnL/bwoktETQc20E04oaEyLa9s3Y"
				"jJ0="
				"-----END DSA PARAMETERS-----";
		
		if (name == "dsa/botan/2048")
			return
				"-----BEGIN DSA PARAMETERS-----"
				"MIICLAKCAQEAkcSKT9+898Aq6V59oSYSK13Shk9Vm4fo50oobVL1m9HeaN/WRdDg"
				"DGDAgAMYkZgDdO61lKUyv9Z7mgnqxLhmOgeRDmjzlGX7cEDSXfE5MuusQ0elMOy6"
				"YchU+biA08DDZgCAWHxFVm2t4mvVo5S+CTtMDyS1r/747GxbPlf7iQJam8FnaZMh"
				"MeFtPJTvyrGNDfBhIDzFPmEDvHLVWUv9QMplOA9EqahR3LB1SV/AM6ilgHGhvXj+"
				"BS9mVVZI60txnSr+i0iA+NrW8VgYuhePiSdMhwvpuW6wjEbEAEDMLv4d+xsYaN0x"
				"nePDSjKmOrbrEiQgmkGWgMx5AtFyjU354QIhAIzX1FD4bwrZTu5M5GmodW0evRBY"
				"JBlD6v+ws1RYXpJNAoIBAA2fXgdhtNvRgz1qsalhoJlsXyIwP3LYTBQPZ8Qx2Uq1"
				"cVvqgaDJjTnOS8941rnryJXTT+idlAkdWEhhXvFfXobxHZb2yWniA936WDVkIKSc"
				"tES1lbkBqTPP4HZ7WU8YoHt/kd7NukRriJkPePL/kfL+fNQ/0uRtGOraH3u2YCxh"
				"f27zpLKE8v2boQo2BC3o+oeiyjZZf+yBFXoUheRAQd8CgwERy4gLvm7UlIFIhvll"
				"zcMTX1zPE4Nyi/ZbgG+WksCxDWxMCcdabKO0ATyxarLBBfa+I66pAA6rIXiYX5cs"
				"mAV+HIbkTnIYaI6krg82NtzKdFydzU5q/7Z8y8E9YTE="
				"-----END DSA PARAMETERS-----";
		
		if (name == "dsa/botan/3072")
			return
				"-----BEGIN DSA PARAMETERS-----"
				"MIIDLAKCAYEA5LUIgHWWY1heFCRgyi2d/xMviuTIQN2jomZoiRJP5WOLhOiim3rz"
				"+hIJvmv8S1By7Tsrc4e68/hX9HioAijvNgC3az3Pth0g00RlslBtLK+H3259wM6R"
				"vS0Wekb2rcwxxTHk+cervbkq3fNbCoBsZikqX14X6WTdCZkDczrEKKs12A6m9oW/"
				"uovkBo5UGK5eytno/wc94rY+Tn6tNciptwtb1Hz7iNNztm83kxk5sKtxvVWVgJCG"
				"2gFVM30YWg5Ps2pRmxtiArhZHmACRJzxzTpmOE9tIHOxzXO+ypO68eGmEX0COPIi"
				"rh7X/tGFqJDn9n+rj+uXU8wTSlGD3+h64llfe1wtn7tCJJ/dWVE+HTOWs+sv2GaE"
				"8oWoRI/nV6ApiBxAdguU75Gb35dAw4OJWZ7FGm6btRmo4GhJHpzgovz+PLYNZs8N"
				"+tIKjsaEBIaEphREV1vRck1zUrRKdgB3s71r04XOWwpyUMwL92jagpI4Buuc+7E4"
				"hDcxthggjHWbAiEAs+vTZOxp74zzuvZDt1c0sWM5suSeXN4bWcHp+0DuDFsCggGA"
				"K+0h7vg5ZKIwrom7px2ffDnFL8gim047x+WUTTKdoQ8BDqyee69sAJ/E6ylgcj4r"
				"Vt9GY+TDrIAOkljeL3ZJ0gZ4KJP4Ze/KSY0u7zAHTqXop6smJxKk2UovOwuaku5A"
				"D7OKPMWaXcfkNtXABLIuNQKDgbUck0B+sy1K4P1Cy0XhLQ7O6KJiOO3iCCp7FSIR"
				"PGbO+NdFxs88uUX4TS9N4W1Epx3hmCcOE/A1U8iLjTI60LlIob8hA6lJl5tu0W+1"
				"88lT2Vt8jojKZ9z1pjb7nKOdkkIV96iE7Wx+48ltjZcVQnl0t8Q1EoLhPTdz99KL"
				"RS8QiSoTx1hzKN6kgntrNpsqjcFyrcWD9R8qZZjFSD5bxGewL5HQWcQC0Y4sJoD3"
				"dqoG9JKAoscsF8xC1bbnQMXEsas8UcLtCSviotiwU65Xc9FCXtKwjwbi3VBZLfGk"
				"eMFVkc39EVZP+I/zi3IdQjkv2kcyEtz9jS2IqXagCv/m//tDCjWeZMorNRyiQSOU"
				"-----END DSA PARAMETERS-----";
		
		return null;
	}
};


