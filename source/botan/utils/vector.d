module botan.utils.vector;

import core.exception, core.memory, core.stdc.stdlib, core.stdc.string,
	std.algorithm, std.conv, std.exception, std.range,
	std.traits, std.typecons;
public import std.container.util;
import botan.utils.memory;

/**
* Existence check for values
*/
bool value_exists(T)(in Vector!T vec,
                     const ref T val)
{
	for (size_t i = 0; i != vec.length; ++i)
		if (vec[i] == val)
			return true;
	return false;
}

/// An array that uses a custom allocator.
struct Vector(T, ALLOCATOR)
{
	// Payload cannot be copied
	private struct Payload
	{
		size_t _capacity;
		T[] _payload;
		
		// Convenience constructor
		this(T[] p) { _capacity = p.length; _payload = allocArray(getAllocator!ALLOCATOR(), p.length); }
		
		// Destructor releases array memory
		~this()
		{
			//Warning: destroy will also destroy class instances.
			//The hasElaborateDestructor protects us here.
			static if (hasElaborateDestructor!T)
				foreach (ref e; _payload)
					.destroy(e);
			
			freeArray(_payload);
		}
		
		@disable this(this);
		
		void opAssign(Payload rhs)
		{
			assert(false);
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
			if (length >= newLength)
			{
				// shorten
				static if (hasElaborateDestructor!T)
					foreach (ref e; _payload.ptr[newLength .. _payload.length])
						.destroy(e);
				
				_payload = _payload.ptr[0 .. newLength];
				return;
			}
			// enlarge
			auto startEmplace = length;
			_payload = (cast(T*) realloc(_payload.ptr,
			                             T.sizeof * newLength))[0 .. newLength];
			initializeAll(_payload.ptr[startEmplace .. length]);
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
			static if (hasIndirections!T)       // should use hasPointers instead
			{
				/* Because of the transactional nature of this
                 * relative to the garbage collector, ensure no
                 * threading bugs by using malloc/copy/free rather
                 * than realloc.
                 */
				immutable oldLength = length;
				auto newPayload = enforce(cast(T*) malloc(sz))[0 .. oldLength];
				// copy old data over to new array
				memcpy(newPayload.ptr, _payload.ptr, T.sizeof * oldLength);
				// Zero out unused capacity to prevent gc from seeing
				// false pointers
				memset(newPayload.ptr + oldLength,
				       0,
				       (elements - oldLength) * T.sizeof);
				GC.addRange(newPayload.ptr, sz);
				GC.removeRange(_payload.ptr);
				free(_payload.ptr);
				_payload = newPayload;
			}
			else
			{
				/* These can't have pointers, so no need to zero
                 * unused region
                 */
				auto newPayload = enforce(cast(T*) realloc(_payload.ptr, sz))[0 .. length];
				_payload = newPayload;
			}
			_capacity = elements;
		}
		
		// Insert one item
		size_t push_back(Stuff)(Stuff stuff)
			if (isImplicitlyConvertible!(Stuff, T))
		{
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
		size_t push_back(Stuff)(Stuff stuff)
			if (isInputRange!Stuff && isImplicitlyConvertible!(ElementType!Stuff, T))
		{
			static if (hasLength!Stuff)
			{
				immutable oldLength = length;
				reserve(oldLength + stuff.length);
			}
			size_t result;
			foreach (item; stuff)
			{
				push_back(item);
				++result;
			}
			static if (hasLength!Stuff)
			{
				assert(length == oldLength + stuff.length);
			}
			return result;
		}
	}

	private alias Data = FreeListRef!Payload;
	private Data _data;
	
	/**
		Constructor taking a number of items
     */
	this(U)(U[] values...) if (isImplicitlyConvertible!(U, T))
	{
		auto p = cast(T*) malloc(T.sizeof * values.length);
		static if (hasIndirections!T)
		{
			if (p)
				GC.addRange(p, T.sizeof * values.length);
		}
		
		foreach (i, e; values)
		{
			emplace(p + i, e);
			assert(p[i] == e);
		}
		_data = Data(p[0 .. values.length]);
	}
	
	/**
		Constructor taking an input range
     */
	this(Stuff)(Stuff stuff)
		if (isInputRange!Stuff && isImplicitlyConvertible!(ElementType!Stuff, T) && !is(Stuff == T[]))
	{
		push_back(stuff);
	}
	
	
	/**
		Comparison for equality.
     */
	bool opEquals(const Array rhs) const
	{
		return opEquals(rhs);
	}
	
	/// ditto
	bool opEquals(ref const Array rhs) const
	{
		if (empty) return rhs.empty;
		if (rhs.empty) return false;
		return _data._payload == rhs._data._payload;
	}
	
	/**
		Defines the container's primary range, which is a random-access range.
    */
	static struct Range
	{
		private Array _outer;
		private size_t _a, _b;
		
		private this(ref Array data, size_t a, size_t b)
		{
			_outer = data;
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
			return _outer[_a];
		}
		
		@property ref T back()
		{
			version (assert) if (empty) throw new RangeError();
			return _outer[_b - 1];
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
			return _outer[_a + i];
		}
		
		typeof(this) opSlice()
		{
			return typeof(this)(_outer, _a, _b);
		}
		
		typeof(this) opSlice(size_t i, size_t j)
		{
			version (assert) if (i > j || _a + j > _b) throw new RangeError();
			return typeof(this)(_outer, _a + i, _a + j);
		}
		
		void opSliceAssign(T value)
		{
			version (assert) if (_b > _outer.length) throw new RangeError();
			_outer[_a .. _b] = value;
		}
		
		void opSliceAssign(T value, size_t i, size_t j)
		{
			version (assert) if (_a + j > _b) throw new RangeError();
			_outer[_a + i .. _a + j] = value;
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
	@property Array dup()
	{
		if (!_data.refCountedStore.isInitialized) return this;
		return Array(_data._payload);
	}
	
	/**
		Property returning $(D true) if and only if the container has no
		elements.

		Complexity: $(BIGOH 1)
     */
	@property bool empty() const
	{
		return !_data.refCountedStore.isInitialized || _data._payload.empty;
	}
	
	/**
		Returns the number of elements in the container.

		Complexity: $(BIGOH 1).
     */
	@property size_t length() const
	{
		return _data.refCountedStore.isInitialized ? _data._payload.length : 0;
	}
	
	/// ditto
	size_t opDollar() const
	{
		return length;
	}

	@property T* ptr() {
		return _data._payload.ptr;
	}

	@property T* end() {
		return this.ptr + this.length;
	}

	/**
		Returns the maximum number of elements the container can store without
		   (a) allocating memory, (b) invalidating iterators upon insertion.

		Complexity: $(BIGOH 1)
     */
	@property size_t capacity()
	{
		return _data.refCountedStore.isInitialized ? _data._capacity : 0;
	}
	
	/**
		Ensures sufficient capacity to accommodate $(D e) elements.

		Postcondition: $(D capacity >= e)

		Complexity: $(BIGOH 1)
     */
	void reserve(size_t elements)
	{
		if (!_data.refCountedStore.isInitialized)
		{
			if (!elements) return;
			immutable sz = elements * T.sizeof;
			auto p = enforce(malloc(sz));
			static if (hasIndirections!T)
			{
				GC.addRange(p, sz);
			}
			_data = Data(cast(T[]) p[0 .. 0]);
			_data._capacity = elements;
		}
		else
		{
			_data.reserve(elements);
		}
	}
	
	/**
		Returns a range that iterates over elements of the container, in
		forward order.

		Complexity: $(BIGOH 1)
     */
	Range opSlice()
	{
		return Range(this, 0, length);
	}
	
	/**
		Returns a range that iterates over elements of the container from
		index $(D a) up to (excluding) index $(D b).

		Precondition: $(D a <= b && b <= length)

		Complexity: $(BIGOH 1)
     */
	Range opSlice(size_t i, size_t j)
	{
		version (assert) if (i > j || j > length) throw new RangeError();
		return Range(this, i, j);
	}
	
	/**
		Forward to $(D opSlice().front) and $(D opSlice().back), respectively.

		Precondition: $(D !empty)

		Complexity: $(BIGOH 1)
     */
	@property ref T front()
	{
		version (assert) if (!_data.refCountedStore.isInitialized) throw new RangeError();
		return _data._payload[0];
	}
	
	/// ditto
	@property ref T back()
	{
		version (assert) if (!_data.refCountedStore.isInitialized) throw new RangeError();
		return _data._payload[$ - 1];
	}
	
	/**
		Indexing operators yield or modify the value at a specified index.

		Precondition: $(D i < length)

		Complexity: $(BIGOH 1)
     */
	ref T opIndex(size_t i)
	{
		version (assert) if (!_data.refCountedStore.isInitialized) throw new RangeError();
		return _data._payload[i];
	}
	
	/**
		Slicing operations execute an operation on an entire slice.

		Precondition: $(D i < j && j < length)

		Complexity: $(BIGOH slice.length)
     */
	void opSliceAssign(T value)
	{
		if (!_data.refCountedStore.isInitialized) return;
		_data._payload[] = value;
	}
	
	/// ditto
	void opSliceAssign(T value, size_t i, size_t j)
	{
		auto slice = _data.refCountedStore.isInitialized ?
			_data._payload :
				T[].init;
		slice[i .. j] = value;
	}
	
	/// ditto
	void opSliceUnary(string op)()
		if(op == "++" || op == "--")
	{
		if(!_data.refCountedStore.isInitialized) return;
		mixin(op~"_data._payload[];");
	}
	
	/// ditto
	void opSliceUnary(string op)(size_t i, size_t j)
		if(op == "++" || op == "--")
	{
		auto slice = _data.refCountedStore.isInitialized ? _data._payload : T[].init;
		mixin(op~"slice[i .. j];");
	}
	
	/// ditto
	void opSliceOpAssign(string op)(T value)
	{
		if(!_data.refCountedStore.isInitialized) return;
		mixin("_data._payload[] "~op~"= value;");
	}
	
	/// ditto
	void opSliceOpAssign(string op)(T value, size_t i, size_t j)
	{
		auto slice = _data.refCountedStore.isInitialized ? _data._payload : T[].init;
		mixin("slice[i .. j] "~op~"= value;");
	}
	
	/**
		Returns a new container that's the concatenation of $(D this) and its
		argument. $(D opBinaryRight) is only defined if $(D Stuff) does not
		define $(D opBinary).

		Complexity: $(BIGOH n + m), where m is the number of elements in $(D
		stuff)
     */
	Array opBinary(string op, Stuff)(Stuff stuff)
		if (op == "~")
	{
		// TODO: optimize
		Array result;
		// @@@BUG@@ result ~= this[] doesn't work
		auto r = this[];
		result ~= r;
		assert(result.length == length);
		result ~= stuff[];
		return result;
	}
	
	/**
		Forwards to $(D push_back(stuff)).
     */
	void opOpAssign(string op, Stuff)(Stuff stuff)
		if (op == "~")
	{
		static if (is(typeof(stuff[])))
		{
			push_back(stuff[]);
		}
		else
		{
			push_back(stuff);
		}
	}
	
	/**
		Removes all contents from the container. The container decides how $(D
		capacity) is affected.

		Postcondition: $(D empty)

		Complexity: $(BIGOH n)
     */
	void clear()
	{
		_data = Data.init;
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
		_data.refCountedStore.ensureInitialized();
		_data.length = newLength;
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
	size_t push_back(Stuff)(Stuff stuff)
		if (isImplicitlyConvertible!(Stuff, T) ||
		    isInputRange!Stuff && isImplicitlyConvertible!(ElementType!Stuff, T))
	{
		_data.refCountedStore.ensureInitialized();
		return _data.push_back(stuff);
	}
	/// ditto
	alias insert = push_back;
	
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
		assert(_data.refCountedStore.isInitialized);
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
			assert(_data.refCountedStore.isInitialized);
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
			auto result = push_back(stuff);
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
		auto result = push_back(stuff);
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
	
	/**
	Removes all elements belonging to $(D r), which must be a range
	obtained originally from this container. The stable version behaves
	the same, but guarantees that ranges iterating over the container are
	never invalidated.

	Returns: A range spanning the remaining elements in the container that
	initially were right after $(D r).

	Complexity: $(BIGOH n - m), where $(D m) is the number of elements in
	$(D r)
     */
	Range linearRemove(Range r)
	{
		enforce(r._outer._data is _data);
		enforce(_data.refCountedStore.isInitialized);
		enforce(r._a <= r._b && r._b <= length);
		immutable offset1 = r._a;
		immutable offset2 = r._b;
		immutable tailLength = length - offset2;
		// Use copy here, not a[] = b[] because the ranges may overlap
		copy(this[offset2 .. length], this[offset1 .. offset1 + tailLength]);
		length = offset1 + tailLength;
		return this[length - tailLength .. length];
	}
}
