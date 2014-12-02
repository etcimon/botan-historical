/*
* Global State Management
* (C) 2010 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.libstate.global_state;
import botan.build;
import botan.libstate.libstate;

/// Thread-Local, no locks needed.
private LibraryState g_lib_state;

/**
* Access the global library state
* @return reference to the global library state
*/
LibraryState global_state()
{
    /* Lazy initialization. Botan still needs to be deinitialized later
        on or memory might leak.
    */
    g_lib_state.initialize();
    return g_lib_state;
}

/**
* Set the global state object
* @param state = the new global state to use
*/
void set_global_state(LibraryState new_state)
{
    g_lib_state = new_state;
}


/**
* Set the global state object unless it is already set
* @param state = the new global state to use
* @return true if the state parameter is now being used as the global
*            state, or false if one was already set, in which case the
*            parameter was deleted immediately
*/
bool set_global_state_unless_set(LibraryState new_state)
{
    if (g_lib_state)
    {
        return false;
    }
    else
    {
        g_lib_state = new_state;
        return true;
    }
}

/**
* Query if the library is currently initialized
* @return true iff the library is initialized
*/
bool global_state_exists()
{
    return (g_lib_state !is LibraryState.init);
}

