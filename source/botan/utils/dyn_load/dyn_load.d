/**
* Dynamically Loaded Object
* (C) 2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

import botan.internal.dyn_load;
import botan.build;
import stdexcept;

#if defined(BOTAN_TARGET_OS_HAS_DLOPEN)
  import dlfcn.h;
#elif defined(BOTAN_TARGET_OS_HAS_LOADLIBRARY)
  import windows.h;
#endif
namespace {

void raise_runtime_loader_exception(in string lib_name,
												string msg)
{
	throw new Exception("Failed to load " ~ lib_name ~ ": " ~
									 (msg ? msg : "Unknown error"));
}

}

Dynamically_Loaded_Library::Dynamically_Loaded_Library(
	in string library) :
	lib_name(library), lib(null)
{
#if defined(BOTAN_TARGET_OS_HAS_DLOPEN)
	lib = ::dlopen(lib_name.toStringz, RTLD_LAZY);

	if (!lib)
		raise_runtime_loader_exception(lib_name, dlerror());

#elif defined(BOTAN_TARGET_OS_HAS_LOADLIBRARY)
	lib = ::LoadLibraryA(lib_name.toStringz);

	if (!lib)
		raise_runtime_loader_exception(lib_name, "LoadLibrary failed");
#endif

	if (!lib)
		raise_runtime_loader_exception(lib_name, "Dynamic load not supported");
}

Dynamically_Loaded_Library::~this()
{
#if defined(BOTAN_TARGET_OS_HAS_DLOPEN)
	::dlclose(lib);
#elif defined(BOTAN_TARGET_OS_HAS_LOADLIBRARY)
	::FreeLibrary((HMODULE)lib);
#endif
}

void* Dynamically_Loaded_Library::resolve_symbol(in string symbol)
{
	void* addr = null;

#if defined(BOTAN_TARGET_OS_HAS_DLOPEN)
	addr = ::dlsym(lib, symbol.toStringz);
#elif defined(BOTAN_TARGET_OS_HAS_LOADLIBRARY)
	addr = cast(void*)(::GetProcAddress((HMODULE)lib,
																	symbol.toStringz));
#endif

	if (!addr)
		throw new Exception("Failed to resolve symbol " ~ symbol +
										 " in " ~ lib_name);

	return addr;
}

}