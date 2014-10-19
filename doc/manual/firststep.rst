
Getting Started
========================================

All declarations in the library are contained within the namespace
``Botan``, so you need to either prefix types with ```` or add
a ``using`` declaration in your code. All examples will assume a
``using`` declaration.

All library headers are included like so::

  #include <botan/auto_rng.h>

Initializing the Library
----------------------------------------

There is a set of core services that the library needs access to while
it is performing requests. To ensure these are set up, you must create
an object of type

.. cpp:class:: LibraryInitializer

prior to making any other library calls. Typically this will be named
something like ``init`` or ``botan_init``. The object lifetime must
exceed that of all other Botan objects your application creates; for
this reason the best place to create the ``LibraryInitializer`` is at
the start of your ``main`` function, since this guarantees that it
will be created first and destroyed last (via standard C++ RAII
rules). The initializer does things like setting up the memory
allocation system and algorithm lookup tables, finding out if there is
a high resolution timer available to use, and similar such
matters. With no arguments, the library is initialized with various
default settings. So (unless you are writing threaded code; see
below), all you need is::

   LibraryInitializer init;

at the start of your ``main``.

If you do not create a ``LibraryInitializer`` object, all library
operations will fail, because it will be unable to do basic things
like allocate memory or get random bits. You should never create more
than one ``LibraryInitializer``.

Pitfalls
----------------------------------------

There are a few things to watch out for to prevent problems when using
the library.

Never allocate any kind of Botan object globally. The problem with
doing this is that the constructor for such an object will be called
before the library is initialized. Many Botan objects will, in their
constructor, make one or more calls into the library global state
object. Access to this object is checked, so an exception should be
thrown (rather than a memory access violation or undetected
uninitialized object access). A rough equivalent that will work is to
keep a global pointer to the object, initializing it after creating
your ``LibraryInitializer``. Merely making the
``LibraryInitializer`` also global will probably not help, because
C++ does not make very strong guarantees about the order that such
objects will be created.

The same rule applies for making sure the destructors of all your
Botan objects are called before the ``LibraryInitializer`` is
destroyed. This implies you can't have static variables that are Botan
objects inside functions or classes; in many C++ runtimes, these
objects will be destroyed after main has returned.

Use a ``try``/``catch`` block inside your ``main`` function, and catch
any ``std::exception`` throws (remember to catch by reference, as
``std::exception::what`` is polymorphic)::

  int main()
     {
     try
        {
        LibraryInitializer init;

        // ...
        }
     catch(std::exception& e)
        {
        std::cerr << e.what() << "\n";
        }
     }

This is not strictly required, but if you don't, and Botan throws an
exception, the runtime will call ``std::terminate``, which usually
calls ``abort`` or something like it, leaving you (or worse, a user of
your application) wondering what went wrong.
