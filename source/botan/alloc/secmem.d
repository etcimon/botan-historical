/*
* Secure Memory Buffers
* (C) 1999-2007,2012 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.alloc.secmem;

import botan.utils.mem_ops;
import std.algorithm;
import vector;

static if (BOTAN_HAS_LOCKING_ALLOCATOR)
  import botan.alloc.locking_allocator;

// todo: Manual Memory Management, freelist backend
struct secure_allocator(T)
{
	this() nothrow {}

	~this() nothrow {}

	T* address(ref x) const nothrow
	{ return &x; }

	const T* address(const ref x) const nothrow
	{ return &x; }

	T* allocate(size_t n, const void* = 0)
	{
		static if (BOTAN_HAS_LOCKING_ALLOCATOR) {
			if (pointer p = cast(pointer)(mlock_allocator.instance().allocate(n, sizeof(T))))
				return p;
		}
		pointer p = new T[n];
		clear_mem(p, n);
		return p;
	}

	void deallocate(T* p, size_t n)
	{
		clear_mem(p, n);

		static if (BOTAN_HAS_LOCKING_ALLOCATOR) {
			if (mlock_allocator.instance().deallocate(p, n, sizeof(T)))
				return;
		}
		.destroy(p);
	}

	size_t max_size() const nothrow
	{
		return cast(size_type)(-1) / sizeof(T);
	}

	void construct(U, Args...)(ref U* p, Args args)
	{
		p = new U(args);
	}

	void destroy(U)(in U* p) { .destroy(p); }

	bool opEquals(T)(in secure_allocator!T)
	{ return true; }

	bool opCmp(T)(in secure_allocator!T)
	{ return false; }
};

alias SafeVector(T) = Vector!(T, secure_allocator!T);

Vector!T unlock(T)(in SafeVector!T input)
{
	Vector!T output = Vector!T(input.length);
	copy_mem(&output[0], &input[0], input.length);
	return output;
}


size_t buffer_insert(T, Alloc)(Vector!(T, Alloc) buf,
							size_t buf_offset,
							in T* input,
							size_t input_length)
{
	const size_t to_copy = std.algorithm.min(input_length, buf.length - buf_offset);
	copy_mem(&buf[buf_offset], input, to_copy);
	return to_copy;
}

size_t buffer_insert(T, Alloc, Alloc2)(Vector!(T, Alloc) buf,
										size_t buf_offset,
										const Vector!( T, Alloc2 ) input)
{
	const size_t to_copy = std.algorithm.min(input.length, buf.length - buf_offset);
	copy_mem(&buf[buf_offset], &input[0], to_copy);
	return to_copy;
}

Vector!(T, Alloc)
	opOpAssign(string op, T, Alloc)(Vector!(T, Alloc) output,
			  const Vector!( T, Alloc2 ) input)
		if (op == "+=")
{
	const size_t copy_offset = output.length;
	output.resize(output.length + input.length);
	copy_mem(&output[copy_offset], &input[0], input.length);
	return output;
}

Vector!(T, Alloc) 
	opOpAssign(string op, T, Alloc)(Vector!(T, Alloc) output, T input)
	if (op == "+=")
{
	output.push_back(input);
	return output;
}

Vector!(T, Alloc) 
	opOpAssign(string op, T, Alloc)(Vector!(T, Alloc) output,
										const Pair!(const T*, L) input)
		if (op == "+=")
{
	const size_t copy_offset = output.length;
	output.resize(output.length + input.second);
	copy_mem(&output[copy_offset], input.first, input.second);
	return output;
}

Vector!(T, Alloc) 
		opOpAssign(string op, T, Alloc, L)(Vector!(T, Alloc) output,
											 const Pair!(T*, L) input)
		if (op == "+=")
{
	const size_t copy_offset = output.length;
	output.resize(output.length + input.second);
	copy_mem(&output[copy_offset], input.first, input.second);
	return output;
}

/**
* Zeroise the values; length remains unchanged
* @param vec the vector to zeroise
*/
void zeroise(T, Alloc)(Vector!(T, Alloc) vec)
{
	clear_mem(&vec[0], vec.length);
}

/**
* Zeroise the values then free the memory
* @param vec the vector to zeroise and free
*/
void zap(T, Alloc)(Vector!(T, Alloc) vec)
{
	zeroise(vec);
	vec.clear();
	vec.shrink_to_fit();
}