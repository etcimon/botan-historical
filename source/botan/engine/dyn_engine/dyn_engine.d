/**
* Dynamically Loaded Engine
* (C) 2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

import botan.dyn_engine;
import botan.internal.dyn_load;
namespace {

extern "C" {
	typedef Engine (*creator_func)(void);
	typedef uint (*module_version_func)(void);
}

}

Dynamically_Loaded_Engine::Dynamically_Loaded_Engine(
	in string library_path) :
	engine(null)
{
	lib = new Dynamically_Loaded_Library(library_path);

	try
	{
		module_version_func get_version =
			lib.resolve<module_version_func>("module_version");

		const uint mod_version = get_version();

		if (mod_version != 20101003)
			throw new Exception("Incompatible version in " ~
											 library_path ~ " of " ~
											 std.conv.to!string(mod_version));

		creator_func creator =
			lib.resolve<creator_func>("create_engine");

		engine = creator();

		if (!engine)
			throw new Exception("Creator function in " ~
											 library_path ~ " failed");
	}
	catch
	{
		delete lib;
		lib = null;
		throw;
	}
}

Dynamically_Loaded_Engine::~this()
{
	delete engine;
	delete lib;
}

}
