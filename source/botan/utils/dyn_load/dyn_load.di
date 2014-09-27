/*
* Dynamically Loaded Object
* (C) 2010 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import string;
/**
* Represents a DLL or shared object
*/
class Dynamically_Loaded_Library
{
	public:
		/**
		* Load a DLL (or fail with an exception)
		* @param lib_name name or path to a library
		*
		* If you don't use a full path, the search order will be defined
		* by whatever the system linker does by default. Always using fully
		* qualified pathnames can help prevent code injection attacks (eg
		* via manipulation of LD_LIBRARY_PATH on Linux)
		*/
		Dynamically_Loaded_Library(in string lib_name);

		/**
		* Unload the DLL
		* @warning Any pointers returned by resolve()/resolve_symbol()
		* should not be used after this destructor runs.
		*/
		~Dynamically_Loaded_Library();

		/**
		* Load a symbol (or fail with an exception)
		* @param symbol names the symbol to load
		* @return address of the loaded symbol
		*/
		void* resolve_symbol(in string symbol);

		/**
		* Convenience function for casting symbol to the right type
		* @param symbol names the symbol to load
		* @return address of the loaded symbol
		*/
		template<typename T>
		T resolve(in string symbol)
		{
			return cast(T)(resolve_symbol(symbol));
		}

	private:
		Dynamically_Loaded_Library(in Dynamically_Loaded_Library);
		Dynamically_Loaded_Library& operator=(in Dynamically_Loaded_Library);

		string lib_name;
		void* lib;
};