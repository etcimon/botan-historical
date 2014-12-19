/*
* Low Level Types
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.utils.types;

public import botan.utils.memory.memory;
public import botan.utils.memory.zeroise;
public import botan.utils.containers.vector;
public import botan.utils.exceptn;
public import std.typecons : scoped;

alias Scoped(T) = typeof(scoped!T());

__gshared immutable size_t DEFAULT_BUFFERSIZE = 4096;

/**
* The two possible directions for cipher filters, determining whether they
* actually perform encryption or decryption.
*/
alias CipherDir = bool;
enum : CipherDir { ENCRYPTION, DECRYPTION }

struct Pair(T, U) {
    import std.typecons : Tuple;
    private Tuple!(T,U) m_obj;

    @property inout(T) first() inout {
        return m_obj[0];
    }

    @property inout(U) second() inout {
        return m_obj[1];
    }

    this(T a, U b) {
        m_obj = Tuple!(T,U)(a, b);
    }

    this(in T a, in U b) {
        m_obj = Tuple!(T,U)(cast(T) a,cast(U) b);
    }

    alias m_obj this;
}

Pair!(T, U) makePair(T, U)(const T first, const U second)
{
    return Pair!(UnConst!T, UnConst!U)(first, second);
}

Pair!(T, U) makePair(T, U)(T first, U second)
{
    return Pair!(T, U)(first, second);
}

private template UnConst(T) {
    static if (is(T U == const(U))) {
        alias UnConst = U;
    } else static if (is(T V == immutable(V))) {
        alias UnConst = V;
    } else alias UnConst = T;
}

struct Unique(T)
{
    /** Represents a reference to $(D T). Resolves to $(D T*) if $(D T) is a value type. */
    static if (is(T:Object))
        alias RefT = T;
    else static if (__traits(isAbstractClass, T))
        alias RefT = T;
    else
        alias RefT = T*;
    
public:
    /**
    Constructor that takes an rvalue.
    It will ensure uniqueness, as long as the rvalue
    isn't just a view on an lvalue (e.g., a cast).
    Typical usage:
    ----
    Unique!Foo f = new Foo;
    ----
    */
    this(RefT p)
    {
        debug(Unique) writeln("Unique constructor with rvalue");
        _p = p;
    }
    /**
    Constructor that takes an lvalue. It nulls its source.
    The nulling will ensure uniqueness as long as there
    are no previous aliases to the source.
    */
    this(ref RefT p)
    {
        _p = p;
        debug(Unique) writeln("Unique constructor nulling source");
        p = null;
        assert(p is null);
    }

    /**
    Constructor that takes a $(D Unique) of a type that is convertible to our type.

    Typically used to transfer a $(D Unique) rvalue of derived type to
    a $(D Unique) of base type.
    Example:
    ---
    class C : Object {}

    Unique!C uc = new C;
    Unique!Object uo = uc.release;
    ---
    */
    this(U)(Unique!U u)
        if (is(u.RefT:RefT))
    {
        debug(Unique) writeln("Unique constructor converting from ", U.stringof);
        _p = u._p;
        u._p = null;
    }

    void clear()
    {
        RefT p = null;
        opAssign(p);
    }

    void opAssign(ref RefT p)
    {
        destroy(this);
        _p = p;
        p = null;
        assert(p is null);
    }
    /*
    void opAssign(U)(in Unique!U p)
    {
        debug(Unique) writeln("Unique opAssign converting from ", U.stringof);
        // first delete any resource we own
        destroy(this);
        _p = cast(RefT)u._p;
        cast(RefT)u._p = null;
    }*/

    /// Transfer ownership from a $(D Unique) of a type that is convertible to our type.
    void opAssign(U)(Unique!U u)
        if (is(u.RefT:RefT))
    {
        debug(Unique) writeln("Unique opAssign converting from ", U.stringof);
        // first delete any resource we own
        destroy(this);
        _p = u._p;
        u._p = null;
    }
    
    ~this()
    {
        debug(Unique) writeln("Unique destructor of ", (_p is null)? null: _p);
        if (_p !is null) delete _p;
        _p = null;
    }
    /** Returns whether the resource exists. */
    @property bool isEmpty() const
    {
        return _p is null;
    }

    /** Transfer ownership to a $(D Unique) rvalue. Nullifies the current contents. */
    Unique release()
    {
        debug(Unique) writeln("Release");
        auto u = Unique(_p);
        assert(_p is null);
        debug(Unique) writeln("return from Release");
        return u;
    }

    void drop()
    {
        _p = null;
    }

    /** Forwards member access to contents. */
    RefT opDot() { return _p; }
    const(RefT) opDot() const { return _p; }

	RefT opUnary(string op)() if (op == "*") { return _p; }
	const(RefT) opUnary(string op)() const if (op == "*") { return _p; }

    RefT get() { return _p; }

    bool opCast(T : bool)() const {
        return !isEmpty;
    }


    /**
    Postblit operator is undefined to prevent the cloning of $(D Unique) objects.
    */
    @disable this(this);
    
private:
    RefT _p;
}
