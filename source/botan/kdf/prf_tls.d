/*
* TLS v1.0 and v1.2 PRFs
* (C) 2004-2010 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.kdf.prf_tls;
import botan.kdf.kdf;
import botan.mac.mac;
import botan.utils.xor_buf;
import botan.mac.hmac;
import botan.hash.md5;
import botan.hash.sha160;

/**
* PRF used in TLS 1.0/1.1
*/
class TLS_PRF : KDF
{
public:
	/*
	* TLS PRF
	*/
	Secure_Vector!ubyte derive(size_t key_len,
	                        in ubyte* secret, size_t secret_len,
	                        in ubyte* seed, size_t seed_len) const
	{
		Secure_Vector!ubyte output = Secure_Vector!ubyte(key_len);
		
		size_t S1_len = (secret_len + 1) / 2,
			S2_len = (secret_len + 1) / 2;
		const ubyte* S1 = secret;
		const ubyte* S2 = secret + (secret_len - S2_len);
		
		P_hash(output, *hmac_md5,  S1, S1_len, seed, seed_len);
		P_hash(output, *hmac_sha1, S2, S2_len, seed, seed_len);
		
		return output;
	}

	@property string name() const { return "TLS-PRF"; }
	KDF clone() const { return new TLS_PRF; }

	/*
	* TLS PRF Constructor and Destructor
	*/
	this()
	{
		hmac_md5 = new HMAC(new MD5);
		hmac_sha1= new HMAC(new SHA_160);
	}

private:
	Unique!MessageAuthenticationCode hmac_md5;
	Unique!MessageAuthenticationCode hmac_sha1;
}

/**
* PRF used in TLS 1.2
*/
class TLS_12_PRF : KDF
{
public:
	Secure_Vector!ubyte derive(size_t key_len,
	                               in ubyte* secret, size_t secret_len,
	                               in ubyte* seed, size_t seed_len) const
	{
		Secure_Vector!ubyte output = Secure_Vector!ubyte(key_len);
		
		P_hash(output, *hmac, secret, secret_len, seed, seed_len);
		
		return output;
	}

	@property string name() const { return "TLSv12-PRF(" ~ hmac.name ~ ")"; }
	KDF clone() const { return new TLS_12_PRF(hmac.clone()); }

	/*
	* TLS v1.2 PRF Constructor and Destructor
	*/
	this(MessageAuthenticationCode mac)
	{
		hmac = mac;
	}
private:
	Unique!MessageAuthenticationCode hmac;
}


private:
/*
* TLS PRF P_hash function
*/
void P_hash(Secure_Vector!ubyte output,
            MessageAuthenticationCode mac,
            in ubyte* secret, size_t secret_len,
            in ubyte* seed, size_t seed_len) pure
{
	try
	{
		mac.set_key(secret, secret_len);
	}
	catch(Invalid_Key_Length)
	{
		throw new Internal_Error("The premaster secret of " ~
		                         std.conv.to!string(secret_len) +
		                         " bytes is too long for the PRF");
	}
	
	Secure_Vector!ubyte A = Secure_Vector!ubyte(seed, seed + seed_len);
	
	size_t offset = 0;
	
	while(offset != output.length)
	{
		const size_t this_block_len =
			std.algorithm.min(mac.output_length, output.length - offset);
		
		A = mac.process(A);
		
		mac.update(A);
		mac.update(seed, seed_len);
		Secure_Vector!ubyte block = mac.flush();
		
		xor_buf(&output[offset], &block[0], this_block_len);
		offset += this_block_len;
	}
}