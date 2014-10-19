/*
* RandomNumberGenerator
* (C) 1999-2009 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.entropy.entropy_src;
import botan.utils.exceptn;
import string;
import core.sync.mutex;
/**
* This class represents a random number (RNG) generator object.
*/
class RandomNumberGenerator
{
	public:
		/**
		* Create a seeded and active RNG object for general application use
		* Added in 1.8.0
		*/
		static RandomNumberGenerator* make_rng();

		/**
		* Create a seeded and active RNG object for general application use
		* Added in 1.11.5
		*/
		static Unique!RandomNumberGenerator make_rng(class Algorithm_Factory af);

		/**
		* Randomize a ubyte array.
		* @param output the ubyte array to hold the random output.
		* @param length the length of the ubyte array output.
		*/
		abstract void randomize(ubyte* output, size_t length);

		/**
		* Return a random vector
		* @param bytes number of bytes in the result
		* @return randomized vector of length bytes
		*/
		abstract SafeVector!ubyte random_vec(size_t bytes)
		{
			SafeVector!ubyte output = SafeVector!ubyte(bytes);
			randomize(&output[0], output.length);
			return output;
		}

		/**
		* Return a random ubyte
		* @return random ubyte
		*/
		ubyte next_byte()
		{
			ubyte output;
			this.randomize(&output, 1);
			return output;
		}

		/**
		* Check whether this RNG is seeded.
		* @return true if this RNG was already seeded, false otherwise.
		*/
		abstract bool is_seeded() const;

		/**
		* Clear all internally held values of this RNG.
		*/
		abstract void clear();

		/**
		* Return the name of this object
		*/
		abstract string name() const;

		/**
		* Seed this RNG using the entropy sources it contains.
		* @param bits_to_collect is the number of bits of entropy to
					attempt to gather from the entropy sources
		*/
		abstract void reseed(size_t bits_to_collect);

		/**
		* Add entropy to this RNG.
		* @param input a ubyte array containg the entropy to be added
		* @param length the length of the ubyte array in
		*/
		abstract void add_entropy(in ubyte* input, size_t length);

		/*
		* Never copy a RNG, create a new one
		*/
		RandomNumberGenerator(in RandomNumberGenerator rng);
		RandomNumberGenerator operator=(in RandomNumberGenerator rng);

		RandomNumberGenerator() {}
		~this() {}
};

/**
* Null/stub RNG - fails if you try to use it for anything
*/
class Null_RNG : RandomNumberGenerator
{
	public:
		override void randomize(ubyte[], size_t) { throw new PRNG_Unseeded("Null_RNG"); }

		override void clear() {}

		override string name() const { return "Null_RNG"; }

		override void reseed(size_t) {}
		override bool is_seeded() const { return false; }
		override void add_entropy(const ubyte[], size_t) {}
};

/**
* Wraps access to a RNG in a mutex
*/
class Serialized_RNG : RandomNumberGenerator
{
	public:
		void randomize(ubyte* output)
		{
			size_t len = output.length;
			m_mutex.lock(); scope(exit) m_mutex.unlock();
			m_rng.randomize(output, len);
		}

		bool is_seeded() const
		{
			m_mutex.lock(); scope(exit) m_mutex.unlock();
			return m_rng.is_seeded();
		}

		void clear()
		{
			m_mutex.lock(); scope(exit) m_mutex.unlock();
			m_rng.clear();
		}

		string name() const
		{
			m_mutex.lock(); scope(exit) m_mutex.unlock();
			return m_rng.name();
		}

		void reseed(size_t poll_bits)
		{
			m_mutex.lock(); scope(exit) m_mutex.unlock();
			m_rng.reseed(poll_bits);
		}

		void add_entropy(in ubyte* input, size_t len)
		{
			m_mutex.lock(); scope(exit) m_mutex.unlock();
			m_rng.add_entropy(input, len);
		}

		Serialized_RNG() : m_rng(RandomNumberGenerator::make_rng()) {}
	private:
		mutable Mutex m_mutex;
		Unique!RandomNumberGenerator m_rng;
};