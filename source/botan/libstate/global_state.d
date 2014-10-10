/*
* Global State Management
* (C) 2010 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.libstate.global_state;
import botan.build;
import botan.libstate.libstate;

/*
* @todo There should probably be a lock to avoid racy manipulation
* of the state among different threads
*/

private Library_State* global_lib_state = null;

/**
* Access the global library state
* @return reference to the global library state
*/
Library_State global_state()
{
	/* Lazy initialization. Botan still needs to be deinitialized later
		on or memory might leak.
	*/
	if (!global_lib_state)
	{
		global_lib_state = new Library_State;
		global_lib_state.initialize();
	}
	
	return global_lib_state;
}

/**
* Set the global state object
* @param state the new global state to use
*/
void set_global_state(Library_State new_state)
{
	delete swap_global_state(new_state);
}


/**
* Set the global state object unless it is already set
* @param state the new global state to use
* @return true if the state parameter is now being used as the global
*			state, or false if one was already set, in which case the
*			parameter was deleted immediately
*/
bool set_global_state_unless_set(Library_State new_state)
{
	if (global_lib_state)
	{
		delete new_state;
		return false;
	}
	else
	{
		delete swap_global_state(new_state);
		return true;
	}
}


/**
* Swap the current state for another
* @param new_state the new state object to use
* @return previous state (or NULL if none)
*/
Library_State* swap_global_state(Library_State* new_state)
{
	Library_State* old_state = global_lib_state;
	global_lib_state = new_state;
	return old_state;
}
/**
* Query if the library is currently initialized
* @return true iff the library is initialized
*/
bool global_state_exists()
{
	return (global_lib_state != null);
}

