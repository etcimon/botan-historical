/*
* RandomNumberGenerator
* (C) 1999-2009 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.entropy_src;
import botan.exceptn;
import string;
import mutex;
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
		static Unique!RandomNumberGenerator make_rng(class Algorithm_Factory& af);

		/**
		* Randomize a byte array.
		* @param output the byte array to hold the random output.
		* @param length the length of the byte array output.
		*/
		abstract void randomize(byte* output, size_t length);

		/**
		* Return a random vector
		* @param bytes number of bytes in the result
		* @return randomized vector of length bytes
		*/
		abstract SafeVector!byte random_vec(size_t bytes)
		{
			SafeVector!byte output(bytes);
			randomize(&output[0], output.size());
			return output;
		}

		/**
		* Return a random byte
		* @return random byte
		*/
		byte next_byte()
		{
			byte output;
			this->randomize(&output, 1);
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
		* @param in a byte array containg the entropy to be added
		* @param length the length of the byte array in
		*/
		abstract void add_entropy(in byte* input, size_t length);

		/*
		* Never copy a RNG, create a new one
		*/
		RandomNumberGenerator(in RandomNumberGenerator rng);
		RandomNumberGenerator& operator=(in RandomNumberGenerator rng);

		RandomNumberGenerator() {}
		~this() {}
};

/**
* Null/stub RNG - fails if you try to use it for anything
*/
class Null_RNG : public RandomNumberGenerator
{
	public:
		void randomize(byte[], size_t) override { throw new PRNG_Unseeded("Null_RNG"); }

		void clear() override {}

		string name() const override { return "Null_RNG"; }

		void reseed(size_t) override {}
		bool is_seeded() const override { return false; }
		void add_entropy(const byte[], size_t) override {}
};

/**
* Wraps access to a RNG in a mutex
*/
class Serialized_RNG : public RandomNumberGenerator
{
	public:
		void randomize(byte* output)
		{
			size_t len = output.length;
			std::lock_guard<std::mutex> lock(m_mutex);
			m_rng->randomize(output, len);
		}

		bool is_seeded() const
		{
			std::lock_guard<std::mutex> lock(m_mutex);
			return m_rng->is_seeded();
		}

		void clear()
		{
			std::lock_guard<std::mutex> lock(m_mutex);
			m_rng->clear();
		}

		string name() const
		{
			std::lock_guard<std::mutex> lock(m_mutex);
			return m_rng->name();
		}

		void reseed(size_t poll_bits)
		{
			std::lock_guard<std::mutex> lock(m_mutex);
			m_rng->reseed(poll_bits);
		}

		void add_entropy(in byte* input, size_t len)
		{
			std::lock_guard<std::mutex> lock(m_mutex);
			m_rng->add_entropy(input, len);
		}

		Serialized_RNG() : m_rng(RandomNumberGenerator::make_rng()) {}
	private:
		mutable std::mutex m_mutex;
		Unique!RandomNumberGenerator m_rng;
};