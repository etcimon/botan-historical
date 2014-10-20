/*
* Library Initialization
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.libstate.init;

import botan.build;
import botan.libstate.libstate;
import botan.libstate.global_state;
import string;
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
	static void initialize(in string options = "")
	{
		
		try
		{
			/*
			This two stage initialization process is because LibraryState's
			constructor will implicitly refer to global state through the
			allocators and so forth, so global_state() has to be a valid
			reference before initialize() can be called. Yeah, gross.
			*/
			Global_State_Management.set_global_state(new LibraryState);
			
			global_state().initialize();
		}
		catch
		{
			deinitialize();
			throw new Exception("Library initialization failed");
		}
	}

	/**
	* Shutdown the library
	*/
	static void deinitialize() {
		Global_State_Management.set_global_state(null);
	}

	/**
	* Initialize the library
	* @param options a string listing initialization options
	*/
	this(in string options = "")
	{ LibraryInitializer.initialize(options); }

	~this() { LibraryInitializer.deinitialize(); }
};
