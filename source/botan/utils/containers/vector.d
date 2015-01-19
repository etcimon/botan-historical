module botan.utils.containers.vector;

import core.exception, core.memory, core.stdc.stdlib, core.stdc.string,
    std.algorithm, std.conv, std.exception, std.range,
    std.traits, std.typecons;
import botan.utils.memory.memory;

void TRACE(T...)(T t) {
    //import std.stdio : writeln;
    //writeln(t);
}
/**
* Existence check for values
*/
bool valueExists(T, int Alloc)(in FreeListRef!(VectorImpl!(T, Alloc)) vec, in T val)
{
    for (size_t i = 0; i != vec.length; ++i)
        if (vec[i] == val)
            return true;
    return false;
}

template Vector(T, int ALLOCATOR = VulnerableAllocator) 
    if (!is (T == FreeListRef!(VectorImpl!(T, ALLOCATOR))))
{
    alias Vector = FreeListRef!(VectorImpl!(T, ALLOCATOR));
}

/// An array that uses a custom allocator.
struct VectorImpl(T, int ALLOCATOR)
{
    @disable this(this);

    // Payload cannot be copied
    private struct Payload
    {
        size_t _capacity;
        T[] _payload;
        
        // Convenience constructor
        this(T[] p) 
        { 
            _capacity = p.length; 
            _payload = allocArray!(T, ALLOCATOR, true)(p.length);
            _payload[0 .. p.length] = p[0 .. $];
        }
        
        // Destructor releases array memory
        ~this()
        {
            T[] data = _payload.ptr[0 .. capacity];
            if (data.ptr !is null)
                freeArray!(T, ALLOCATOR, true)(data, length); // calls destructors and frees memory
        }

        void opAssign(Payload rhs)
        {
            assert(false);
            /* Done already, just in case the FreeListRef requires it
            // shorten
            static if (hasElaborateDestructor!T) {
                foreach (ref e; _payload.ptr[newLength .. _payload.length])
                    .destroy(e);
                
                
                // Zero out unused capacity to prevent gc from seeing
                // false pointers
                static if (hasIndirections!T)
                    memset(_payload.ptr + newLength, 0, (elements - oldLength) * T.sizeof);
            }

            freeArray!(T, false)(getAllocator!ALLOCATOR(), _payload.ptr[0 .. capacity]);

            static if ( hasIndirections!T )
                GC.removeRange(_payload.ptr, T.sizeof * _capacity);

            _capacity = rhs._capacity;
            _payload = rhs._payload; */
        }
        
        // Duplicate data
        // @property Payload dup()
        // {
        //     Payload result;
        //     result._payload = _payload.dup;
        //     // Conservatively assume initial capacity == length
        //     result._capacity = result._payload.length;
        //     return result;
        // }
        
        // length
        @property size_t length() const
        {
            return _payload.length;
        }
        
        // length
        @property void length(size_t newLength)
        {
            if (length > 0 && length >= newLength)
            {
                // shorten
                static if (hasElaborateDestructor!T) {
                    foreach (ref e; _payload.ptr[newLength .. _payload.length])
                        .destroy(e);

                    // Zero out unused capacity to prevent gc from seeing
                    // false pointers
                    static if (hasIndirections!T)
                        memset(_payload.ptr + newLength, 0, (_payload.length - newLength) * T.sizeof);
                }
                _payload = _payload.ptr[0 .. newLength];
                return;
            }

            if (newLength > 0) {
                // enlarge
                auto startEmplace = length;
                reserve(newLength);
                _payload = _payload.ptr[0 .. newLength];
                initializeAll(_payload.ptr[startEmplace .. length]);
            }
        }
        
        // capacity
        @property size_t capacity() const
        {
            return _capacity;
        }
        
        // reserve
        void reserve(size_t elements)
        {
            if (elements <= capacity) return;
            immutable sz = elements * T.sizeof;
            /* Because of the transactional nature of this
             * relative to the garbage collector, ensure no
             * threading bugs by using malloc/copy/free rather
             * than realloc.
             */
            immutable oldLength = length;
            TRACE("Oldlength = ", oldLength);
            auto newPayload = allocArray!(T, ALLOCATOR, false)(elements)[0 .. oldLength];
            static if ( hasIndirections!T ) {
                // Zero out unused capacity to prevent gc from seeing
                // false pointers
                TRACE("Zeroing from ", newPayload.ptr + oldLength, "length: ", (elements - oldLength) * T.sizeof);
                memset(newPayload.ptr + oldLength, 0, (elements - oldLength) * T.sizeof);
                GC.addRange(newPayload.ptr, sz);
            }

            // copy old data over to new array
            if (_payload) {
                TRACE("Copying from : ", _payload.ptr, " to: ", newPayload.ptr, " length: ", T.sizeof * oldLength);
                memcpy(newPayload.ptr, _payload.ptr, T.sizeof * oldLength);
            }

            TRACE("New payload: ", newPayload);
            auto ub = _payload.ptr[0 .. _capacity];
            if (ub) {
                TRACE("Freeing old payload");
                freeArray!(T, ALLOCATOR, false, false)(ub);

                static if ( hasIndirections!T )
                    GC.removeRange(cast(void*) _payload.ptr);
            }
            TRACE("Reservation done. ");
            _payload = newPayload;
            _capacity = elements;
        }
        
        // Insert one item
        size_t pushBack(Stuff)(Stuff stuff)
            if (isImplicitlyConvertible!(Stuff, T))
        {
            TRACE("Vector.append");
            if (_capacity == length)
            {
                reserve(1 + capacity * 3 / 2);
            }
            assert(capacity > length && _payload.ptr);
            emplace(_payload.ptr + _payload.length, stuff);
            _payload = _payload.ptr[0 .. _payload.length + 1];
            return 1;
        }
        
        /// Insert a range of items
        size_t pushBack(Stuff)(Stuff stuff)
            if (isInputRange!Stuff && isImplicitlyConvertible!(ElementType!Stuff, T))
        {
            TRACE("Vector.append 2");
            static if (hasLength!Stuff)
            {
                immutable oldLength = length;
                reserve(oldLength + stuff.length);
            }
            size_t result;
            foreach (item; stuff)
            {
                pushBack(item);
                ++result;
            }
            static if (hasLength!Stuff)
            {
                assert(length == oldLength + stuff.length);
            }
            return result;
        }
    }

    private alias Data = Payload;
    private Data _data;

    this(size_t elms) {
        resize(elms);
    }

    /**
        Constructor taking a number of items
     */
    this(U)(U[] values...) if (isImplicitlyConvertible!(U, T))
    {
        _data = Data(cast(T[])values);
    }
    
    /**
        Constructor taking an input range
     */
    this(Stuff)(Stuff stuff)
        if (isInputRange!Stuff && isImplicitlyConvertible!(ElementType!Stuff, T) && !is(Stuff == T[]))
    {
        insertBack(stuff);
    }
        
    /**
        Defines the container's primary range, which is a random-access range.
    */
    static struct Range
    {
        private VectorImpl!(T, ALLOCATOR)* _outer;
        private size_t _a, _b;
        import std.traits : isNarrowString;

        private this(ref VectorImpl!(T, ALLOCATOR) data, size_t a, size_t b)
        {
            _outer = &data;
            _a = a;
            _b = b;
        }

        @property Range save()
        {
            return this;
        }
        
        @property bool empty() @safe pure nothrow const
        {
            return _a >= _b;
        }
        
        @property size_t length() @safe pure nothrow const
        {
            return _b - _a;
        }
        alias opDollar = length;
        
        @property ref T front()
        {
            version (assert) if (empty) throw new RangeError();
            return (*_outer)[_a];
        }
        
        @property ref T back()
        {
            version (assert) if (empty) throw new RangeError();
            return (*_outer)[_b - 1];
        }

        void popFront() @safe pure nothrow
        {
            version (assert) if (empty) throw new RangeError();
            ++_a;
        }
        
        void popBack() @safe pure nothrow
        {
            version (assert) if (empty) throw new RangeError();
            --_b;
        }
        
        T moveFront()
        {
            version (assert) if (empty || _a >= _outer.length) throw new RangeError();
            return move(_outer._data._payload[_a]);
        }
        
        T moveBack()
        {
            version (assert) if (empty || _b  > _outer.length) throw new RangeError();
            return move(_outer._data._payload[_b - 1]);
        }
        
        T moveAt(size_t i)
        {
            version (assert) if (_a + i >= _b || _a + i >= _outer.length) throw new RangeError();
            return move(_outer._data._payload[_a + i]);
        }
        
        ref T opIndex(size_t i)
        {
            version (assert) if (_a + i >= _b) throw new RangeError();
            return (*_outer)[_a + i];
        }
        
        typeof(this) opSlice()
        {
            return typeof(this)(*_outer, _a, _b);
        }
        
        typeof(this) opSlice(size_t i, size_t j)
        {
            version (assert) if (i > j || _a + j > _b) throw new RangeError();
            return typeof(this)(*_outer, _a + i, _a + j);
        }
        
        void opSliceAssign(T value)
        {
            version (assert) if (_b > _outer.length) throw new RangeError();
            (*_outer)[_a .. _b] = value;
        }
        
        void opSliceAssign(T value, size_t i, size_t j)
        {
            version (assert) if (_a + j > _b) throw new RangeError();
            (*_outer)[_a + i .. _a + j] = value;
        }
        
        void opSliceUnary(string op)()
            if(op == "++" || op == "--")
        {
            version (assert) if (_b > _outer.length) throw new RangeError();
            mixin(op~"_outer[_a .. _b];");
        }
        
        void opSliceUnary(string op)(size_t i, size_t j)
            if(op == "++" || op == "--")
        {
            version (assert) if (_a + j > _b) throw new RangeError();
            mixin(op~"_outer[_a + i .. _a + j];");
        }
        
        void opSliceOpAssign(string op)(T value)
        {
            version (assert) if (_b > _outer.length) throw new RangeError();
            mixin("_outer[_a .. _b] "~op~"= value;");
        }
        
        void opSliceOpAssign(string op)(T value, size_t i, size_t j)
        {
            version (assert) if (_a + j > _b) throw new RangeError();
            mixin("_outer[_a + i .. _a + j] "~op~"= value;");
        }
    }

    /**
        Duplicates the container. The elements themselves are not transitively
        duplicated.

        Complexity: $(BIGOH n).
     */
    @property FreeListRef!(VectorImpl!(T, ALLOCATOR)) dup() const
    {
        return FreeListRef!(VectorImpl!(T, ALLOCATOR))(cast(T[])_data._payload);
    }
    
    /**
        Property returning $(D true) if and only if the container has no
        elements.

        Complexity: $(BIGOH 1)
     */
    @property bool empty() const
    {
        return _data._payload.empty;
    }
    
    /**
        Returns the number of elements in the container.

        Complexity: $(BIGOH 1).
     */
    @property size_t length() const
    {
        return _data._payload.length;
    }
    
    /// ditto
    size_t opDollar() const
    {
        return length;
    }

    @property T* ptr() inout {
        return cast(T*) _data._payload.ptr;
    }

    @property T* end() inout {
        return this.ptr + this.length;
    }

    /**
        Returns the maximum number of elements the container can store without
           (a) allocating memory, (b) invalidating iterators upon insertion.

        Complexity: $(BIGOH 1)
     */
    @property size_t capacity() const
    {
        return _data._capacity;
    }

    @property Range range() {
        return Range(this, 0, length);
    }

    /**
        Ensures sufficient capacity to accommodate $(D e) elements.

        Postcondition: $(D capacity >= e)

        Complexity: $(BIGOH 1)
     */
    void reserve(size_t elements)
    {
        _data.reserve(elements);
    }
    
    /**
        Returns a range that iterates over elements of the container, in
        forward order.

        Complexity: $(BIGOH 1)
     */
    static if (!is(T == ubyte))
    Range opSlice()
    {
        return Range(this, 0, length);
    }
    
    static if (!is(T == ubyte))
    Range opSlice() const
    {
        UnConst!(typeof(this)) _ref = cast(UnConst!(typeof(this))) this;
        return Range(_ref, 0UL, length);
    }

    static if (is(T == ubyte))
    string opSlice() const
    {
        return cast(string) _data._payload;
    }

    /**
        Returns a range that iterates over elements of the container from
        index $(D a) up to (excluding) index $(D b).

        Precondition: $(D a <= b && b <= length)

        Complexity: $(BIGOH 1)
     */
    static if (!is(T == ubyte))
    Range opSlice(size_t i, size_t j)
    {
        version (assert) if (i > j || j > length) throw new RangeError();
        return Range(this, i, j);
    }

    static if (is(T == ubyte))
    string opSlice(size_t i, size_t j)
    {
        version (assert) if (i > j || j > length) throw new RangeError();
        return cast(string) _data._payload[i .. j];
    }

    /**
        Forward to $(D opSlice().front) and $(D opSlice().back), respectively.

        Precondition: $(D !empty)

        Complexity: $(BIGOH 1)
     */
    @property ref T front()
    {
        return _data._payload[0];
    }
    
    /// ditto
    @property ref T back()
    {
        return _data._payload[$ - 1];
    }
    
    /**
        Indexing operators yield or modify the value at a specified index.

        Precondition: $(D i < length)

        Complexity: $(BIGOH 1)
     */
    ref T opIndex(size_t i)
    {
        return _data._payload[i];
    }

    void opIndexAssign(U)(U val, size_t i)
    {
        _data._payload[i] = cast(T) val;
    }

    ref const(T) opIndex(size_t i) const
    {
        return _data._payload[i];
    }
    /**
        Slicing operations execute an operation on an entire slice.

        Precondition: $(D i < j && j < length)

        Complexity: $(BIGOH slice.length)
     */
    void opSliceAssign(Stuff)(Stuff value)
    {
        static if (isRandomAccessRange!Stuff)
        {
            _data.length = value.length;
            _data._payload.ptr[0 .. value.length] = value[0 .. $];
        } else static if (is (Stuff == FreeListRef!(VectorImpl!(T, ALLOCATOR)))) {
            _data.length = value._data.length;
            _data._payload[] = value._data._payload[];
        }
        else {
            _data.length = value.length;
            _data._payload[] = value;
        }
    }
    
    /// ditto
    void opSliceAssign(Stuff)(Stuff value, size_t i, size_t j)
    {
        auto slice = _data._payload;
        slice[i .. j] = value;
    }
    
    /// ditto
    void opSliceUnary(string op)()
        if(op == "++" || op == "--")
    {
        mixin(op~"_data._payload[];");
    }
    
    /// ditto
    void opSliceUnary(string op)(size_t i, size_t j)
        if(op == "++" || op == "--")
    {
        mixin(op~"slice[i .. j];");
    }
    
    /// ditto
    void opSliceOpAssign(string op)(T value)
    {
        mixin("_data._payload[] "~op~"= value;");
    }
    
    /// ditto
    void opSliceOpAssign(string op)(T value, size_t i, size_t j)
    {
        mixin("slice[i .. j] "~op~"= value;");
    }
    
    /**
        Returns a new container that's the concatenation of $(D this) and its
        argument. $(D opBinaryRight) is only defined if $(D Stuff) does not
        define $(D opBinary).

        Complexity: $(BIGOH n + m), where m is the number of elements in $(D
        stuff)
     */
    auto opBinary(string op, Stuff)(Stuff stuff)
        if (op == "~")
    {
        TRACE("Appending stuff");
        FreeListRef!(VectorImpl!(T, ALLOCATOR)) result;
        // @@@BUG@@ result ~= this[] doesn't work
        auto r = this[];
        result ~= r;
        assert(result.length == length);
        result ~= stuff[];
        return result;
    }

    /**
        Forwards to $(D pushBack(stuff)).
     */
    void opOpAssign(string op, Stuff)(Stuff stuff)
        if (op == "~")
    {
        static if (is (Stuff == FreeListRef!(typeof(this)))) {
            insertBack(cast(T[]) stuff[]);
        }
        else
        {
            insertBack(stuff);
        }
    }

    void swap(ref FreeListRef!(VectorImpl!(T, ALLOCATOR)) other) {
        this._data._payload[0 .. $] = other._data._payload[0  .. $];
        other.clear();
    }

    /**
        Removes all contents from the container. The container decides how $(D
        capacity) is affected.

        Postcondition: $(D empty)

        Complexity: $(BIGOH n)
     */
    void clear()
    {
        TRACE("Vector.clear()");
        _data.length = 0;
    }
    
    /**
        Sets the number of elements in the container to $(D newSize). If $(D
        newSize) is greater than $(D length), the added elements are added to
        unspecified positions in the container and initialized with $(D
        T.init).

        Complexity: $(BIGOH abs(n - newLength))

        Postcondition: $(D length == newLength)
     */
    @property void length(size_t newLength)
    {
        _data.length = newLength;
    }

    void resize(size_t newLength)
    {
        this.length = newLength;
    }

    import std.traits : isNumeric;

    int opCmp(int Alloc)(FreeListRef!(VectorImpl!(T, Alloc)) other) const 
    {
        if (this[] == other[])
            return 0;
        else if (this[] < other[])
            return -1;
        else
            return 0;
    }

    size_t pushBack(Stuff...)(Stuff stuff) 
        if (!isNumeric!Stuff || !is ( T == ubyte ))
    {
        return insertBack(stuff);
    }

    size_t pushBack(Stuff...)(Stuff stuff) 
        if (isNumeric!Stuff && is(T == ubyte))
    {
        return insertBack(cast(T) stuff);
    }

    size_t insert(Stuff...)(Stuff stuff) {
        return insertBack(stuff);
    }

    /**
        Inserts $(D value) to the front or back of the container. $(D stuff)
        can be a value convertible to $(D T) or a range of objects convertible
        to $(D T). The stable version behaves the same, but guarantees that
        ranges iterating over the container are never invalidated.

        Returns: The number of elements inserted

        Complexity: $(BIGOH m * log(n)), where $(D m) is the number of
        elements in $(D stuff)
    */
    size_t insertBack(Stuff)(Stuff stuff)
        if (isImplicitlyConvertible!(Stuff, T) ||
            isInputRange!Stuff && isImplicitlyConvertible!(ElementType!Stuff, T))
    {
        return _data.pushBack(stuff);
    }

    static if (is (T == ubyte))
    size_t insertBack(string stuff) {
        return _data.pushBack(cast(ubyte[]) stuff);
    }

    size_t pushBack(ref FreeListRef!(VectorImpl!(T, ALLOCATOR)) rhs)
    {
        return pushBack(rhs[]);
    }

    alias popBack = removeBack;
    /**
        Removes the value at the back of the container. The stable version
        behaves the same, but guarantees that ranges iterating over the
        container are never invalidated.

        Precondition: $(D !empty)

        Complexity: $(BIGOH log(n)).
    */
    void removeBack()
    {
        enforce(!empty);
        static if (hasElaborateDestructor!T)
            .destroy(_data._payload[$ - 1]);
        
        _data._payload = _data._payload[0 .. $ - 1];
    }

    void removeFront() { this.length = this.length - 1; }
    /// ditto
    alias stableRemoveBack = removeBack;
    
    /**
        Removes $(D howMany) values at the front or back of the
        container. Unlike the unparameterized versions above, these functions
        do not throw if they could not remove $(D howMany) elements. Instead,
        if $(D howMany > n), all elements are removed. The returned value is
        the effective number of elements removed. The stable version behaves
        the same, but guarantees that ranges iterating over the container are
        never invalidated.

        Returns: The number of elements removed

        Complexity: $(BIGOH howMany).
    */
    size_t removeBack(size_t howMany)
    {
        if (howMany > length) howMany = length;
        static if (hasElaborateDestructor!T)
            foreach (ref e; _data._payload[$ - howMany .. $])
                .destroy(e);
        
        _data._payload = _data._payload[0 .. $ - howMany];
        return howMany;
    }
    /// ditto
    alias stableRemoveBack = removeBack;
    alias insert_before = insertBefore;
    /**
        Inserts $(D stuff) before, after, or instead range $(D r), which must
        be a valid range previously extracted from this container. $(D stuff)
        can be a value convertible to $(D T) or a range of objects convertible
        to $(D T). The stable version behaves the same, but guarantees that
        ranges iterating over the container are never invalidated.

        Returns: The number of values inserted.

        Complexity: $(BIGOH n + m), where $(D m) is the length of $(D stuff)
     */
    size_t insertBefore(Stuff)(Range r, Stuff stuff)
        if (isImplicitlyConvertible!(Stuff, T))
    {
        enforce(r._outer._data is _data && r._a <= length);
        reserve(length + 1);
        // Move elements over by one slot
        memmove(_data._payload.ptr + r._a + 1,
                _data._payload.ptr + r._a,
                T.sizeof * (length - r._a));
        emplace(_data._payload.ptr + r._a, stuff);
        _data._payload = _data._payload.ptr[0 .. _data._payload.length + 1];
        return 1;
    }
    
    /// ditto
    size_t insertBefore(Stuff)(Range r, Stuff stuff)
        if (isInputRange!Stuff && isImplicitlyConvertible!(ElementType!Stuff, T))
    {
        enforce(r._outer._data is _data && r._a <= length);
        static if (isForwardRange!Stuff)
        {
            // Can find the length in advance
            auto extra = walkLength(stuff);
            if (!extra) return 0;
            reserve(length + extra);
            // Move elements over by extra slots
            memmove(_data._payload.ptr + r._a + extra,
                    _data._payload.ptr + r._a,
                    T.sizeof * (length - r._a));
            foreach (p; _data._payload.ptr + r._a ..
                     _data._payload.ptr + r._a + extra)
            {
                emplace(p, stuff.front);
                stuff.popFront();
            }
            _data._payload = _data._payload.ptr[0 .. _data._payload.length + extra];
            return extra;
        }
        else
        {
            enforce(_data);
            immutable offset = r._a;
            enforce(offset <= length);
            auto result = pushBack(stuff);
            bringToFront(this[offset .. length - result],
            this[length - result .. length]);
            return result;
        }
    }
    
    /// ditto
    size_t insertAfter(Stuff)(Range r, Stuff stuff)
    {
        enforce(r._outer._data is _data);
        // TODO: optimize
        immutable offset = r._b;
        enforce(offset <= length);
        auto result = pushBack(stuff);
        bringToFront(this[offset .. length - result],
        this[length - result .. length]);
        return result;
    }
    
    /// ditto
    size_t replace(Stuff)(Range r, Stuff stuff)
        if (isInputRange!Stuff && isImplicitlyConvertible!(ElementType!Stuff, T))
    {
        enforce(r._outer._data is _data);
        size_t result;
        for (; !stuff.empty; stuff.popFront())
        {
            if (r.empty)
            {
                // insert the rest
                return result + insertBefore(r, stuff);
            }
            r.front = stuff.front;
            r.popFront();
            ++result;
        }
        // Remove remaining stuff in r
        linearRemove(r);
        return result;
    }
    
    /// ditto
    size_t replace(Stuff)(Range r, Stuff stuff)
        if (isImplicitlyConvertible!(Stuff, T))
    {
        enforce(r._outer._data is _data);
        if (r.empty)
        {
            insertBefore(r, stuff);
        }
        else
        {
            r.front = stuff;
            r.popFront();
            linearRemove(r);
        }
        return 1;
    }

    bool opEquals(in FreeListRef!(VectorImpl!(T, ALLOCATOR)) other_) const {
        import botan.constants : logTrace;
        if (other_ is null && _data._payload.length == 0)
            return true;
        else if (other_ is null)
            return false;
        if (other_.length != length)
            return false;
        foreach  (const size_t i, const ref T t; _data._payload) {
            if (t != other_[i])
            {
                return false;
            }
        }
        return true;
    }
    
}

private template UnConst(T) {
    static if (is(T U == const(U))) {
        alias UnConst = U;
    } else static if (is(T V == immutable(V))) {
        alias UnConst = V;
    } else alias UnConst = T;
}