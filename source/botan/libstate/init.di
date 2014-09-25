/*
* Library Initialization
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#define BOTAN_LIBRARY_INITIALIZER_H__

#include <botan/build.h>
#include <string>
/**
* This class represents the Library Initialization/Shutdown Object. It
* has to exceed the lifetime of any Botan object used in an
* application.  You can call initialize/deinitialize or use
* LibraryInitializer in the RAII style.
*/
class LibraryInitializer
{
	public:
		/**
		* Initialize the library
		* @param options a string listing initialization options
		*/
		static void initialize(in string options = "");

		/**
		* Shutdown the library
		*/
		static void deinitialize();

		/**
		* Initialize the library
		* @param options a string listing initialization options
		*/
		LibraryInitializer(in string options = "")
		{ LibraryInitializer::initialize(options); }

		~LibraryInitializer() { LibraryInitializer::deinitialize(); }
};