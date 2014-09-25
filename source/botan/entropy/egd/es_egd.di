/*
* EGD EntropySource
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

#include <botan/entropy_src.h>
#include <string>
#include <vector>
/**
* EGD Entropy Source
*/
class EGD_EntropySource : public EntropySource
{
	public:
		string name() const { return "EGD/PRNGD"; }

		void poll(Entropy_Accumulator& accum);

		EGD_EntropySource(in Vector!( string ));
		~EGD_EntropySource();
	private:
		class EGD_Socket
		{
			public:
				EGD_Socket(in string path);

				void close();
				size_t read(byte outbuf[], size_t length);
			private:
				static int open_socket(in string path);

				string socket_path;
				int m_fd; // cached fd
		};

		Vector!( EGD_Socket ) sockets;
};