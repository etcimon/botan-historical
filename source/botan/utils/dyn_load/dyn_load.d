/*
* Dynamically Loaded Object
* (C) 2010 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.utils.dyn_load.dyn_load;
// import string;
//todo : Mac OSX
import botan.build;
import std.exception;

version(linux){
	import core.sys.linux.dlfcn;
}
else version(Windows)
	import std.c.windows.windows;

void raise_runtime_loader_exception(in string lib_name,
                                    string msg)
{
	throw new Exception("Failed to load " ~ lib_name ~ ": " ~
	                    (msg ? msg : "Unknown error"));
}

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
	this(in string library)
	{
		lib_name = library;
		
		version(linux) {
			lib = dlopen(lib_name.toStringz, RTLD_LAZY);
			
			if (!lib)
				raise_runtime_loader_exception(lib_name, dlerror());
			
		}
		version(Windows) {
			
			lib = LoadLibraryA(lib_name.toStringz);
			
			if (!lib)
				raise_runtime_loader_exception(lib_name, "LoadLibrary failed");
		}
		
		if (!lib)
			raise_runtime_loader_exception(lib_name, "Dynamic load not supported");
	}

	/**
	* Unload the DLL
	* @warning Any pointers returned by resolve()/resolve_symbol()
	* should not be used after this destructor runs.
	*/
	~this()
	{
		version(linux)
			dlclose(lib);
		version(Windows)
			FreeLibrary(cast(HMODULE)lib);
	}

	/**
	* Load a symbol (or fail with an exception)
	* @param symbol names the symbol to load
	* @return address of the loaded symbol
	*/
	void* resolve_symbol(in string symbol)
	{
		void* addr = null;
		
		version(linux)
			addr = ::dlsym(lib, symbol.toStringz);
		version(Windows)
			addr = cast(void*)(GetProcAddress((HMODULE)lib, symbol.toStringz));
		if (!addr)
			throw new Exception("Failed to resolve symbol " ~ symbol +
			                    " in " ~ lib_name);
		
		return addr;
	}

	/**
	* Convenience function for casting symbol to the right type
	* @param symbol names the symbol to load
	* @return address of the loaded symbol
	*/
	T resolve(T)(in string symbol)
	{
		return cast(T)(resolve_symbol(symbol));
	}

private:
	string lib_name;
	void* lib;
}