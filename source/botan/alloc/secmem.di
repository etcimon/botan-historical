/*
* Secure Memory Buffers
* (C) 1999-2007,2012 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

#include <botan/mem_ops.h>
#include <algorithm>
#include <vector>

#if defined(BOTAN_HAS_LOCKING_ALLOCATOR)
  #include <botan/locking_allocator.h>
#endif
template<typename T>
class secure_allocator
{
	public:
		typedef T			 value_type;

		typedef T*			pointer;
		typedef const T*	const_pointer;

		typedef T&			reference;
		typedef const T&	const_reference;

		typedef std::size_t	  size_type;
		typedef std::ptrdiff_t  difference_type;

		secure_allocator() noexcept {}

		~secure_allocator() noexcept {}

		pointer address(reference x) const noexcept
		{ return std::addressof(x); }

		const_pointer address(const_reference x) const noexcept
		{ return std::addressof(x); }

		pointer allocate(size_type n, const void* = 0)
		{
#if defined(BOTAN_HAS_LOCKING_ALLOCATOR)
			if(pointer p = cast(pointer)(mlock_allocator::instance().allocate(n, sizeof(T))))
				return p;
#endif

			pointer p = new T[n];
			clear_mem(p, n);
			return p;
		}

		void deallocate(pointer p, size_type n)
		{
			clear_mem(p, n);

#if defined(BOTAN_HAS_LOCKING_ALLOCATOR)
			if(mlock_allocator::instance().deallocate(p, n, sizeof(T)))
				return;
#endif

			delete [] p;
		}

		size_type max_size() const noexcept
		{
			return cast(size_type)(-1) / sizeof(T);
		}

		template<typename U, typename... Args>
		void construct(U* p, Args&&... args)
		{
			::new(cast(void*)(p)) U(std::forward<Args>(args)...);
		}

		template<typename U> void destroy(U* p) { p->~U(); }
};

template<typename T> inline bool
operator==(in secure_allocator<T>, const secure_allocator<T>&)
{ return true; }

template<typename T> inline bool
operator!=(in secure_allocator<T>, const secure_allocator<T>&)
{ return false; }

template<typename T> using secure_vector = Vector!( T, secure_allocator<T )>;

template<typename T>
Vector!( T ) unlock(in secure_vector<T> input)
{
	Vector!( T ) out(in.size());
	copy_mem(&out[0], &in[0], in.size());
	return out;
}

template<typename T, typename Alloc>
size_t buffer_insert(Vector!( T, Alloc )& buf,
							size_t buf_offset,
							const T input[],
							size_t input_length)
{
	const size_t to_copy = std::min(input_length, buf.size() - buf_offset);
	copy_mem(&buf[buf_offset], input, to_copy);
	return to_copy;
}

template<typename T, typename Alloc, typename Alloc2>
size_t buffer_insert(Vector!( T, Alloc )& buf,
							size_t buf_offset,
							const Vector!( T, Alloc2 )& input)
{
	const size_t to_copy = std::min(input.size(), buf.size() - buf_offset);
	copy_mem(&buf[buf_offset], &input[0], to_copy);
	return to_copy;
}

template<typename T, typename Alloc, typename Alloc2>
Vector!( T, Alloc )&
operator+=(Vector!( T, Alloc )& out,
			  const Vector!( T, Alloc2 )& input)
{
	const size_t copy_offset = out.size();
	out.resize(out.size() + in.size());
	copy_mem(&out[copy_offset], &in[0], in.size());
	return out;
}

template<typename T, typename Alloc>
Vector!( T, Alloc )& operator+=(Vector!( T, Alloc )& out, T input)
{
	out.push_back(input);
	return out;
}

template<typename T, typename Alloc, typename L>
Vector!( T, Alloc )& operator+=(Vector!( T, Alloc )& out,
											 const Pair!(in T*, L) input)
{
	const size_t copy_offset = out.size();
	out.resize(out.size() + in.second);
	copy_mem(&out[copy_offset], in.first, in.second);
	return out;
}

template<typename T, typename Alloc, typename L>
Vector!( T, Alloc )& operator+=(Vector!( T, Alloc )& out,
											 const Pair!(T*, L)& input)
{
	const size_t copy_offset = out.size();
	out.resize(out.size() + in.second);
	copy_mem(&out[copy_offset], in.first, in.second);
	return out;
}

/**
* Zeroise the values; length remains unchanged
* @param vec the vector to zeroise
*/
template<typename T, typename Alloc>
void zeroise(Vector!( T, Alloc )& vec)
{
	clear_mem(&vec[0], vec.size());
}

/**
* Zeroise the values then free the memory
* @param vec the vector to zeroise and free
*/
template<typename T, typename Alloc>
void zap(Vector!( T, Alloc )& vec)
{
	zeroise(vec);
	vec.clear();
	vec.shrink_to_fit();
}