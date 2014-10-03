/*
* Basic Filters
* (C) 1999-2007 Jack Lloyd
* (C) 2013 Joel Low
*
* Distributed under the terms of the botan license.
*/

import botan.filter;
import thread;
/**
* BitBucket is a filter which simply discards all inputs
*/
struct BitBucket : public Filter
{
	void write(in byte*, size_t) {}

	string name() const { return "BitBucket"; }
};

/**
* This class represents Filter chains. A Filter chain is an ordered
* concatenation of Filters, the input to a Chain sequentially passes
* through all the Filters contained in the Chain.
*/

class Chain : public Fanout_Filter
{
	public:
		void write(in byte* input, size_t length) { send(input, length); }

		string name() const;

		/**
		* Construct a chain of up to four filters. The filters are set
		* up in the same order as the arguments.
		*/
		Chain(Filter* = null, Filter* = null,
				Filter* = null, Filter* = null);

		/**
		* Construct a chain from range of filters
		* @param filter_arr the list of filters
		* @param length how many filters
		*/
		Chain(Filter* filter_arr[], size_t length);
};

/**
* This class represents a fork filter, whose purpose is to fork the
* flow of data. It causes an input message to result in n messages at
* the end of the filter, where n is the number of forks.
*/
class Fork : public Fanout_Filter
{
	public:
		void write(in byte* input, size_t length) { send(input, length); }
		void set_port(size_t n) { Fanout_Filter::set_port(n); }

		string name() const;

		/**
		* Construct a Fork filter with up to four forks.
		*/
		Fork(Filter*, Filter*, Filter* = null, Filter* = null);

		/**
		* Construct a Fork from range of filters
		* @param filter_arr the list of filters
		* @param length how many filters
		*/
		Fork(Filter* filter_arr[], size_t length);
};

/**
* This class is a threaded version of the Fork filter. While this uses
* threads, the class itself is NOT thread-safe. This is meant as a drop-
* in replacement for Fork where performance gains are possible.
*/
class Threaded_Fork : public Fork
{
	public:
		string name() const;

		/**
		* Construct a Threaded_Fork filter with up to four forks.
		*/
		Threaded_Fork(Filter*, Filter*, Filter* = null, Filter* = null);

		/**
		* Construct a Threaded_Fork from range of filters
		* @param filter_arr the list of filters
		* @param length how many filters
		*/
		Threaded_Fork(Filter* filter_arr[], size_t length);

		~this();

	package:
		void set_next(Filter* f[], size_t n);
		void send(in byte* input, size_t length);

	private:
		void thread_delegate_work(in byte* input, size_t length);
		void thread_entry(Filter* filter);

		Vector!( std::shared_ptr<std::thread )> m_threads;
		Unique!struct Threaded_Fork_Data m_thread_data;
};