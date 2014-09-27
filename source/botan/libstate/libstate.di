/*
* Library Internal/Global State
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.global_state;
import botan.algo_factory;
import botan.rng;
import mutex;
import string;
import vector;
import map;
/**
* Global Library State
*/
class Library_State
{
	public:
		Library_State() {}

		Library_State(in Library_State);
		Library_State& operator=(in Library_State);

		void initialize();

		/**
		* @return global Algorithm_Factory
		*/
		Algorithm_Factory& algorithm_factory() const;

		/**
		* @return global RandomNumberGenerator
		*/
		RandomNumberGenerator& global_rng();

		void poll_available_sources(class Entropy_Accumulator& accum);

	private:
		static Vector!( std::unique_ptr<EntropySource )> entropy_sources();

		std::unique_ptr<Serialized_RNG> m_global_prng;

		std::mutex m_entropy_src_mutex;
		Vector!( std::unique_ptr<EntropySource )> m_sources;

		std::unique_ptr<Algorithm_Factory> m_algorithm_factory;
};