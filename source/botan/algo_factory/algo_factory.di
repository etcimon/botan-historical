/*
* Algorithm Factory
* (C) 2008 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

#include <botan/types.h>
#include <string>
#include <vector>
/**
* Forward declarations (don't need full definitions here)
*/
class BlockCipher;
class StreamCipher;
class HashFunction;
class MessageAuthenticationCode;
class PBKDF;

class Algorithm_Cache(T);

class Engine;

/**
* Algorithm Factory
*/
class Algorithm_Factory
{
	public:
		/**
		* Constructor
		*/
		Algorithm_Factory();

		/**
		* Destructor
		*/
		~Algorithm_Factory();

		/**
		* @param engine to add (Algorithm_Factory takes ownership)
		*/
		void add_engine(Engine* engine);

		/**
		* Clear out any cached objects
		*/
		void clear_caches();

		/**
		* @param algo_spec the algorithm we are querying
		* @returns list of providers of this algorithm
		*/
		Vector!( string ) providers_of(in string algo_spec);

		/**
		* @param algo_spec the algorithm we are setting a provider for
		* @param provider the provider we would like to use
		*/
		void set_preferred_provider(in string algo_spec,
											 in string provider);

		/**
		* @param algo_spec the algorithm we want
		* @param provider the provider we would like to use
		* @returns pointer to const prototype object, ready to clone(), or NULL
		*/
		const BlockCipher*
			prototype_block_cipher(in string algo_spec,
										  in string provider = "");

		/**
		* @param algo_spec the algorithm we want
		* @param provider the provider we would like to use
		* @returns pointer to freshly created instance of the request algorithm
		*/
		BlockCipher* make_block_cipher(in string algo_spec,
												 in string provider = "");

		/**
		* @param algo the algorithm to add
		* @param provider the provider of this algorithm
		*/
		void add_block_cipher(BlockCipher* algo, in string provider);

		/**
		* @param algo_spec the algorithm we want
		* @param provider the provider we would like to use
		* @returns pointer to const prototype object, ready to clone(), or NULL
		*/
		const StreamCipher*
			prototype_stream_cipher(in string algo_spec,
											in string provider = "");

		/**
		* @param algo_spec the algorithm we want
		* @param provider the provider we would like to use
		* @returns pointer to freshly created instance of the request algorithm
		*/
		StreamCipher* make_stream_cipher(in string algo_spec,
													in string provider = "");

		/**
		* @param algo the algorithm to add
		* @param provider the provider of this algorithm
		*/
		void add_stream_cipher(StreamCipher* algo, in string provider);

		/**
		* @param algo_spec the algorithm we want
		* @param provider the provider we would like to use
		* @returns pointer to const prototype object, ready to clone(), or NULL
		*/
		const HashFunction*
			prototype_hash_function(in string algo_spec,
											in string provider = "");

		/**
		* @param algo_spec the algorithm we want
		* @param provider the provider we would like to use
		* @returns pointer to freshly created instance of the request algorithm
		*/
		HashFunction* make_hash_function(in string algo_spec,
													in string provider = "");

		/**
		* @param algo the algorithm to add
		* @param provider the provider of this algorithm
		*/
		void add_hash_function(HashFunction* algo, in string provider);

		/**
		* @param algo_spec the algorithm we want
		* @param provider the provider we would like to use
		* @returns pointer to const prototype object, ready to clone(), or NULL
		*/
		const MessageAuthenticationCode*
			prototype_mac(in string algo_spec,
							  in string provider = "");

		/**
		* @param algo_spec the algorithm we want
		* @param provider the provider we would like to use
		* @returns pointer to freshly created instance of the request algorithm
		*/
		MessageAuthenticationCode* make_mac(in string algo_spec,
														in string provider = "");

		/**
		* @param algo the algorithm to add
		* @param provider the provider of this algorithm
		*/
		void add_mac(MessageAuthenticationCode* algo,
						 in string provider);

		/**
		* @param algo_spec the algorithm we want
		* @param provider the provider we would like to use
		* @returns pointer to const prototype object, ready to clone(), or NULL
		*/
		const PBKDF* prototype_pbkdf(in string algo_spec,
											  in string provider = "");

		/**
		* @param algo_spec the algorithm we want
		* @param provider the provider we would like to use
		* @returns pointer to freshly created instance of the request algorithm
		*/
		PBKDF* make_pbkdf(in string algo_spec,
								in string provider = "");

		/**
		* @param algo the algorithm to add
		* @param provider the provider of this algorithm
		*/
		void add_pbkdf(PBKDF* algo, in string provider);

		/**
		* An iterator for the engines in this factory
		* @deprecated Avoid in new code
		*/
		class Engine_Iterator
		{
			public:
				/**
				* @return next engine in the sequence
				*/
				Engine* next() { return af.get_engine_n(n++); }

				/**
				* @param a an algorithm factory
				*/
				Engine_Iterator(in Algorithm_Factory a) :
					af(a) { n = 0; }
			private:
				const Algorithm_Factory& af;
				size_t n;
		};
		friend class Engine_Iterator;

	private:
		Engine* get_engine_n(size_t n) const;

		Vector!( Engine* ) engines;

		std::unique_ptr<Algorithm_Cache<BlockCipher>> block_cipher_cache;
		std::unique_ptr<Algorithm_Cache<StreamCipher>> stream_cipher_cache;
		std::unique_ptr<Algorithm_Cache<HashFunction>> hash_cache;
		std::unique_ptr<Algorithm_Cache<MessageAuthenticationCode>> mac_cache;
		std::unique_ptr<Algorithm_Cache<PBKDF>> pbkdf_cache;
};