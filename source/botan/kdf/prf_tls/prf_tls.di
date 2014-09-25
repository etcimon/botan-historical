/*
* TLS v1.0 and v1.2 PRFs
* (C) 2004-2010 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

#include <botan/kdf.h>
#include <botan/mac.h>
/**
* PRF used in TLS 1.0/1.1
*/
class TLS_PRF : public KDF
{
	public:
		SafeVector!byte derive(size_t key_len,
										  in byte[] secret, size_t secret_len,
										  in byte[] seed, size_t seed_len) const;

		string name() const { return "TLS-PRF"; }
		KDF* clone() const { return new TLS_PRF; }

		TLS_PRF();
	private:
		std::unique_ptr<MessageAuthenticationCode> hmac_md5;
		std::unique_ptr<MessageAuthenticationCode> hmac_sha1;
};

/**
* PRF used in TLS 1.2
*/
class TLS_12_PRF : public KDF
{
	public:
		SafeVector!byte derive(size_t key_len,
										  in byte[] secret, size_t secret_len,
										  in byte[] seed, size_t seed_len) const;

		string name() const { return "TLSv12-PRF(" + hmac->name() + ")"; }
		KDF* clone() const { return new TLS_12_PRF(hmac->clone()); }

		TLS_12_PRF(MessageAuthenticationCode* hmac);
	private:
		std::unique_ptr<MessageAuthenticationCode> hmac;
};