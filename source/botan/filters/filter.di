/*
* Filter
* (C) 1999-2007 Jack Lloyd
* (C) 2013 Joel Low
*
* Distributed under the terms of the botan license.
*/

import botan.secmem;
import vector;
import string;
/**
* This class represents general abstract filter objects.
*/
class Filter
{
	public:
		/**
		* @return descriptive name for this filter
		*/
		abstract string name() const;

		/**
		* Write a portion of a message to this filter.
		* @param input the input as a byte array
		* @param length the length of the byte array input
		*/
		abstract void write(in byte* input, size_t length);

		/**
		* Start a new message. Must be closed by end_msg() before another
		* message can be started.
		*/
		abstract void start_msg() {}

		/**
		* Notify that the current message is finished; flush buffers and
		* do end-of-message processing (if any).
		*/
		abstract void end_msg() {}

		/**
		* Check whether this filter is an attachable filter.
		* @return true if this filter is attachable, false otherwise
		*/
		abstract bool attachable() { return true; }

		abstract ~Filter() {}
	protected:
		/**
		* @param in some input for the filter
		* @param length the length of in
		*/
		abstract void send(in byte* input, size_t length);

		/**
		* @param in some input for the filter
		*/
		void send(byte input) { send(&input, 1); }

		/**
		* @param in some input for the filter
		*/
		void send(in SafeVector!byte input) { send(&input[0], input.size()); }

		/**
		* @param in some input for the filter
		*/
		void send(in Vector!byte input) { send(&input[0], input.size()); }

		/**
		* @param in some input for the filter
		* @param length the number of bytes of in to send
		*/
		void send(in SafeVector!byte input)
		{
			send(&input[0], length);
		}

		/**
		* @param in some input for the filter
		* @param length the number of bytes of in to send
		*/
		void send(in Vector!byte input)
		{
			send(&input[0], length);
		}

		Filter();

		Filter(in Filter);

		Filter& operator=(in Filter);

	private:
		/**
		* Start a new message in *this and all following filters. Only for
		* internal use, not intended for use in client applications.
		*/
		void new_msg();

		/**
		* End a new message in *this and all following filters. Only for
		* internal use, not intended for use in client applications.
		*/
		void finish_msg();

		friend class Pipe;
		friend class Fanout_Filter;

		size_t total_ports() const;
		size_t current_port() const { return port_num; }

		/**
		* Set the active port
		* @param new_port the new value
		*/
		void set_port(size_t new_port);

		size_t owns() const { return filter_owns; }

		/**
		* Attach another filter to this one
		* @param f filter to attach
		*/
		void attach(Filter* f);

		/**
		* @param filters the filters to set
		* @param count number of items in filters
		*/
		void set_next(Filter* filters[], size_t count);
		Filter* get_next() const;

		SafeVector!byte write_queue;
		Vector!( Filter* ) next;
		size_t port_num, filter_owns;

		// true if filter belongs to a pipe --> prohibit filter sharing!
		bool owned;
};

/**
* This is the abstract Fanout_Filter base class.
**/
class Fanout_Filter : public Filter
{
	protected:
		/**
		* Increment the number of filters past us that we own
		*/
		void incr_owns() { ++filter_owns; }

		void set_port(size_t n) { Filter::set_port(n); }

		void set_next(Filter* f[], size_t n) { Filter::set_next(f, n); }

		void attach(Filter* f) { Filter::attach(f); }

	private:
		friend class Threaded_Fork;
		using Filter::write_queue;
		using Filter::total_ports;
		using Filter::next;
};

/**
* The type of checking to be performed by decoders:
* NONE - no checks, IGNORE_WS - perform checks, but ignore
* whitespaces, FULL_CHECK - perform checks, also complain
* about white spaces.
*/
enum Decoder_Checking { NONE, IGNORE_WS, FULL_CHECK };