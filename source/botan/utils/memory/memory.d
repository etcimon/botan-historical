/**
    Utility functions for memory management

    Note that this module currently is a big sand box for testing allocation related stuff.
    Nothing here, including the interfaces, is final but rather a lot of experimentation.

    Copyright: Â© 2012-2013 RejectedSoftware e.K.
    License: Subject to the terms of the MIT license, as written in the included LICENSE.txt file.
    Authors: SÃ¶nke Ludwig
*/
module botan.utils.memory.memory;

import botan.constants;
import core.exception : OutOfMemoryError;
import core.stdc.stdlib;
import core.memory;
import std.conv;
import std.exception : enforceEx;
import std.traits;
import std.algorithm;
import botan.utils.containers.hashmap : HashMapImpl;
import botan.utils.memory.zeroise;

enum {
    SimpleAllocator = 0,
    VulnerableAllocator = 1
}

alias VulnerableAllocatorImpl = AutoFreeListAllocator!(MallocAllocator);

R getAllocator(R)() {
    static __gshared R alloc;
    if (!alloc)
        alloc = new R;
    return alloc;
}

auto allocObject(T, int ALLOCATOR = VulnerableAllocator, bool MANAGED = true, ARGS...)(ARGS args)
{
    static if (ALLOCATOR == VulnerableAllocator)
        auto allocator = getAllocator!VulnerableAllocatorImpl();
    else static if (ALLOCATOR == SimpleAllocator)
        auto allocator = getAllocator!MallocAllocator();
    else
        auto allocator = getAllocator!SecureAllocatorImpl;

    auto mem = allocator.alloc(AllocSize!T);
    static if( MANAGED ){
        static if( hasIndirections!T )
            GC.addRange(mem.ptr, mem.length);
        return emplace!T(mem, args);
    }
    else static if( is(T == class) ) return cast(T)mem.ptr;
    else return cast(T*)mem.ptr;
}

T[] allocArray(T, int ALLOCATOR = VulnerableAllocator, bool MANAGED = true)(size_t n)
{
    static if (ALLOCATOR == VulnerableAllocator)
        auto allocator = getAllocator!VulnerableAllocatorImpl();
    else static if (ALLOCATOR == SimpleAllocator)
        auto allocator = getAllocator!MallocAllocator();
    else
        auto allocator = getAllocator!SecureAllocatorImpl();
    auto mem = allocator.alloc(T.sizeof * n);
    auto ret = cast(T[])mem;
    static if ( MANAGED )
    {
		static if (__traits(hasMember, T, "NOGC")) enum NOGC = T.NOGC;
		else enum NOGC = false;

        static if( hasIndirections!T && !NOGC )
            GC.addRange(mem.ptr, mem.length);
        // TODO: use memset for class, pointers and scalars
        foreach (ref el; ret) { // calls constructors
            emplace!T(cast(void[])((&el)[0 .. 1]));
        }
    }
    return ret;
}

void freeArray(T, int ALLOCATOR = VulnerableAllocator, bool MANAGED = true, bool DESTROY = true)(ref T[] array, size_t max_destroy = size_t.max)
{
    static if (ALLOCATOR == VulnerableAllocator)
        auto allocator = getAllocator!VulnerableAllocatorImpl();
    else static if (ALLOCATOR == SimpleAllocator)
        auto allocator = getAllocator!MallocAllocator();
    else
        auto allocator = getAllocator!SecureAllocatorImpl();

	static if (__traits(hasMember, T, "NOGC")) enum NOGC = T.NOGC;
	else enum NOGC = false;

	static if (MANAGED && hasIndirections!T && !NOGC) {
        GC.removeRange(array.ptr);
	}
    static if (DESTROY && hasElaborateDestructor!T) { // calls destructors
        size_t i;
        foreach (e; array) {
			static if (is(T == struct) && isPointer!T) .destroy(*e);
			else .destroy(e);
            if (++i == max_destroy) break;
        }
    }
    allocator.free(cast(void[])array);
    array = null;
}


interface Allocator {
    enum size_t alignment = 0x10;
    enum size_t alignmentMask = alignment-1;
    
    void[] alloc(size_t sz)
    out { assert((cast(size_t)__result.ptr & alignmentMask) == 0, "alloc() returned misaligned data."); }

    void free(void[] mem)
    in {
        assert(mem.ptr !is null, "free() called with null array.");
        assert((cast(size_t)mem.ptr & alignmentMask) == 0, "misaligned pointer passed to free().");
    }
}

/**
    Simple proxy allocator protecting its base allocator with a mutex.
*/
final class LockAllocator(Base) : Allocator {
    private {
        Base m_base;
    }
    this() { m_base = getAllocator!Base(); }
    void[] alloc(size_t sz) { synchronized(this) return m_base.alloc(sz); }
    void free(void[] mem)
    in {
        assert(mem.ptr !is null, "free() called with null array.");
        assert((cast(size_t)mem.ptr & alignmentMask) == 0, "misaligned pointer passed to free().");
    }
    body { synchronized(this) m_base.free(mem); }
}

final class DebugAllocator(Base) : Allocator {
    private {
        Base m_baseAlloc;
        HashMapImpl!(void*, size_t, SimpleAllocator) m_blocks;
        size_t m_bytes;
        size_t m_maxBytes;
    }
    
    this()
    {
        m_baseAlloc = getAllocator!Base();
        m_blocks = HashMapImpl!(void*, size_t, SimpleAllocator)();
    }
    
    @property size_t allocatedBlockCount() const { return m_blocks.length; }
    @property size_t bytesAllocated() const { return m_bytes; }
    @property size_t maxBytesAllocated() const { return m_maxBytes; }
    
    void[] alloc(size_t sz)
    {
        auto ret = m_baseAlloc.alloc(sz);
        assert(ret.length == sz, "base.alloc() returned block with wrong size.");
        assert(m_blocks.get(cast(const)ret.ptr, size_t.max) == size_t.max, "base.alloc() returned block that is already allocated.");
        m_blocks[ret.ptr] = sz;
        m_bytes += sz;
        if( m_bytes > m_maxBytes ){
            m_maxBytes = m_bytes;
            //logDebug("New allocation maximum: %d (%d blocks)", m_maxBytes, m_blocks.length);
        }
        return ret;
    }

    void free(void[] mem)
    {
        auto sz = m_blocks.get(cast(const)mem.ptr, size_t.max);
        assert(sz != size_t.max, "free() called with non-allocated object.");
        assert(sz == mem.length, "free() called with block of wrong size.");
        m_baseAlloc.free(mem);
        m_bytes -= sz;
        m_blocks.remove(mem.ptr);
    }
}

final class MallocAllocator : Allocator {
    void[] alloc(size_t sz)
    {
        static err = new immutable OutOfMemoryError;
        auto ptr = .malloc(sz + Allocator.alignment);
        if (ptr is null) throw err;
        return adjustPointerAlignment(ptr)[0 .. sz];
    }
    
    void free(void[] mem)
    {
        .free(extractUnalignedPointer(mem.ptr));
    }
}

final class AutoFreeListAllocator(Base) : Allocator {
    import std.typetuple;
    
    private {
        enum minExponent = 3;
        enum freeListCount = 12;
        FreeListAlloc!Base[freeListCount] m_freeLists;
        Base m_baseAlloc;
    }
    
    this()
    {
        m_baseAlloc = getAllocator!Base();
        foreach (i; iotaTuple!freeListCount)
            m_freeLists[i] = new FreeListAlloc!Base(nthFreeListSize!(i), m_baseAlloc);
    }
    
    void[] alloc(size_t sz)
    {
        if (sz > nthFreeListSize!(freeListCount-1)) return m_baseAlloc.alloc(sz);
        foreach (i; iotaTuple!freeListCount)
            if (sz <= nthFreeListSize!(i))
                return m_freeLists[i].alloc().ptr[0 .. sz];
        //logTrace("AFL alloc %08X(%d)", ret.ptr, sz);
        assert(false);
    }
        
    void free(void[] data)
    {
        //logTrace("AFL free %08X(%s)", data.ptr, data.length);
        if (data.length > nthFreeListSize!(freeListCount-1)) {
            m_baseAlloc.free(data);
            return;
        }
        foreach(i; iotaTuple!freeListCount) {
            if (data.length <= nthFreeListSize!i) {
                m_freeLists[i].free(data.ptr[0 .. nthFreeListSize!i]);
                return;
            }
        }
        assert(false);
    }
    
    private static pure size_t nthFreeListSize(size_t i)() { return 1 << (i + minExponent); }
    private template iotaTuple(size_t i) {
        static if (i > 1) alias iotaTuple = TypeTuple!(iotaTuple!(i-1), i-1);
        else alias iotaTuple = TypeTuple!(0);
    }
}

final class FreeListAlloc(Base) : Allocator
{
    private static struct FreeListSlot { FreeListSlot* next; }
    private {
        immutable size_t m_elemSize;
        Base m_baseAlloc;
        FreeListSlot* m_firstFree = null;
        size_t m_nalloc = 0;
        size_t m_nfree = 0;
    }
    
    this(size_t elem_size, Base base_allocator)
    {
        assert(elem_size >= size_t.sizeof);
        m_elemSize = elem_size;
        m_baseAlloc = base_allocator;
        //logDebug("Create FreeListAlloc %d", m_elemSize);
    }
    
    @property size_t elementSize() const { return m_elemSize; }
    
    void[] alloc(size_t sz)
    {
        assert(sz == m_elemSize, "Invalid allocation size.");
        return alloc();
    }
    
    void[] alloc()
    {
        void[] mem;
        if( m_firstFree ){
            auto slot = m_firstFree;
            m_firstFree = slot.next;
            slot.next = null;
            mem = (cast(void*)slot)[0 .. m_elemSize];
            m_nfree--;
        } else {
            mem = m_baseAlloc.alloc(m_elemSize);
            //logInfo("Alloc %d bytes: alloc: %d, free: %d", SZ, s_nalloc, s_nfree);
        }
        m_nalloc++;
        //logInfo("Alloc %d bytes: alloc: %d, free: %d", SZ, s_nalloc, s_nfree);
        return mem;
    }

    void free(void[] mem)
    {
        assert(mem.length == m_elemSize, "Memory block passed to free has wrong size.");
        auto s = cast(FreeListSlot*)mem.ptr;
        s.next = m_firstFree;
        m_firstFree = s;
        m_nalloc--;
        m_nfree++;
    }
}

template FreeListObjectAlloc(T, bool USE_GC = true, bool INIT = true)
{
    enum ElemSize = AllocSize!T;
    
	static if (__traits(hasMember, T, "NOGC")) enum NOGC = T.NOGC;
	else enum NOGC = false;

	static if( is(T == class) ){
		alias TR = T;
	} else static if (__traits(isAbstractClass, T)) {
		alias TR = T;
	} else static if (is(T == interface)) {
		alias TR = T;
	} else {
		alias TR = T*;
	}

    TR alloc(ARGS...)(ARGS args)
    {
        //logInfo("alloc %s/%d", T.stringof, ElemSize);
        auto mem = getAllocator!VulnerableAllocatorImpl().alloc(ElemSize);
        static if( hasIndirections!T && !NOGC ) GC.addRange(mem.ptr, ElemSize);
        static if( INIT ) return emplace!T(mem, args);
        else return cast(TR)mem.ptr;
    }
    
    void free(TR obj)
    {
        static if( INIT ){
			auto objc = obj;
			static if (is(TR == T*)) .destroy(*objc);
			else .destroy(objc);
        }
        static if( hasIndirections!T && !NOGC ) GC.removeRange(cast(void*)obj);
        getAllocator!VulnerableAllocatorImpl().free((cast(void*)obj)[0 .. ElemSize]);
    }
}

struct FreeListRef(T, bool INIT = true)
{
    enum isFreeListRef = true;
	static if (__traits(hasMember, T, "NOGC")) enum NOGC = T.NOGC;
	else enum NOGC = false;
    enum ElemSize = AllocSize!T;
    
    static if( is(T == class) ){
        alias TR = T;
    } else static if (__traits(isAbstractClass, T)) {
        alias TR = T;
    } else static if (is(T == interface)) {
        alias TR = T;
    } else {
        alias TR = T*;
    }
    
    private TR m_object;
    private ulong* m_refCount;
    private void function(void*) m_free;
    private size_t m_magic = 0x1EE75817; // workaround for compiler bug
    
    static FreeListRef opCall(ARGS...)(ARGS args)
    {
        FreeListRef ret;
        auto mem = getAllocator!VulnerableAllocatorImpl().alloc(ElemSize);
        ret.m_refCount = cast(ulong*)getAllocator!VulnerableAllocatorImpl().alloc(ulong.sizeof).ptr;
        (*ret.m_refCount) = 1;
		static if( hasIndirections!T && !NOGC) GC.addRange(mem.ptr, ElemSize);
        static if( INIT ) ret.m_object = cast(TR)emplace!(Unqual!T)(mem, args);
        else ret.m_object = cast(TR)mem.ptr;
        return ret;
    }
    
    const ~this()
    {
        dtor((cast(FreeListRef*)&this));
        (cast(FreeListRef*)&this).m_magic = 0;
    }

    static void dtor(U)(U* ctxt) {
        static if (!is (U == typeof(this))) {
            typeof(this)* this_ = cast(typeof(this)*)ctxt;
            this_.m_object = cast(typeof(this.m_object)) ctxt.m_object;
            this_._deinit();
        }
        else {
            ctxt._clear();
        }
    }

    const this(this)
    {
        (cast(FreeListRef*)&this).copyctor();
    }

    void copyctor() {

        if (!m_object) {
            defaultInit();
            import backtrace.backtrace;
            import std.stdio : stdout;
            static if (T.stringof.countUntil("OIDImpl") == -1 &&
                       T.stringof.countUntil("HashMapImpl!(string,") == -1)
                printPrettyTrace(stdout, PrintOptions.init, 3); 
        }
        checkInvariants();
        if (m_object) (*m_refCount)++; 
        
    }

    void opAssign(U)(in U other) const
    {
        if (other.m_object is this.m_object) return;
        static if (is(U == FreeListRef))
            (cast(FreeListRef*)&this).opAssignImpl(*cast(U*)&other);
    }

    ref typeof(this) opAssign(U)(in U other) const
    {
        if (other.m_object is this.m_object) return;
        static if (is(U == FreeListRef))
            (cast(FreeListRef*)&this).opAssignImpl(*cast(U*)&other);
        return this;
    }

    private void opAssignImpl(U)(U other) {
        _clear();
        m_object = cast(typeof(this.m_object))other.m_object;
        m_refCount = other.m_refCount;
        static if (!is (U == typeof(this))) {
            static void destr(void* ptr) {
                U.dtor(cast(typeof(&this))ptr);
            }
            m_free = &destr;
        } else
            m_free = other.m_free;
        if( m_object )
            (*m_refCount)++;
    }

    private void _clear()
    {
        checkInvariants();
        if( m_object ){
            if( --(*m_refCount) == 0 ){
                if (m_free)
                    m_free(cast(void*)&this);
                else {
                    _deinit();
                }
            }
        }
        
        m_object = null;
        m_refCount = null;
        m_free = null;
        m_magic = 0x1EE75817;
    }
    
    private void _deinit() {
        static if( INIT ){
            auto objc = m_object;
            static if (is(TR == T*)) .destroy(*objc);
            else .destroy(objc);
        }
		static if( hasIndirections!T && !NOGC ) GC.removeRange(cast(void*)m_object);
        getAllocator!VulnerableAllocatorImpl().free((cast(void*)m_object)[0 .. ElemSize]);
        getAllocator!VulnerableAllocatorImpl().free((cast(void*)m_refCount)[0 .. ulong.sizeof]);
    }

    @property const(TR) opStar() const
    {
        (cast(FreeListRef*)&this).defaultInit();
        checkInvariants();
        return m_object;
    }

    @property TR opStar() {
        defaultInit();
        checkInvariants();
        return m_object; 
    }
    
    alias opStar this;

    auto opBinaryRight(string op, Key)(Key key)
    inout if (op == "in" && __traits(hasMember, typeof(m_object), "opBinaryRight")) {
        defaultInit();
        static if (is(T == class) || __traits(isAbstractClass, T))
            return m_object.opBinaryRight!("in")(key);
        else
            return (*m_object).opBinaryRight!("in")(key);
    }

    bool opCast(U : bool)() const {
        return m_object !is null;
    }

    bool opEquals(U)(U other) const
    {
        defaultInit();
        static if (__traits(compiles, (cast(TR)m_object).opEquals(cast(T) other.m_object)))
            return (cast(TR)m_object).opEquals(cast(T) other.m_object);
        else
            return (cast(TR)m_object).opEquals(other);
    }

    int opCmp(U)(U other) const
    {
        defaultInit();
        return (cast(TR)m_object).opCmp(other);
    }

    U opCast(U)() const nothrow
        if (!is ( U == bool ))
    {
        assert(U.sizeof == typeof(this).sizeof, "Error, U: "~ U.sizeof.to!string~ " != this: " ~ typeof(this).sizeof.to!string);
        try { 
            U ret = U.init;
            ret.m_object = cast(U.TR)this.m_object;

            static if (!is (U == typeof(this))) {
                if (!m_free) {
                    static void destr(void* ptr) {
                        dtor(cast(U*)ptr);
                    }
                    ret.m_free = &destr;
                }
                else
                    ret.m_free = m_free;
            }
            else ret.m_free = m_free;

            ret.m_refCount = cast(ulong*)this.m_refCount;
            (*ret.m_refCount) += 1;
            return ret;
        } catch(Throwable e) { try logError("Error in catch: ", e.toString()); catch {} }
        return U.init;
    }

    int opApply(U...)(U args)
        if (__traits(hasMember, typeof(m_object), "opApply"))
    {
        defaultInit();
        return m_object.opApply(args);
    }

    int opApply(U...)(U args) const
        if (__traits(hasMember, typeof(m_object), "opApply"))
    {
        defaultInit();
        return m_object.opApply(args);
    }

    void opSliceAssign(U...)(U args)
        if (__traits(hasMember, typeof(m_object), "opSliceAssign"))
    {
        defaultInit();
        m_object.opSliceAssign(args);
    }

    void defaultInit() inout {
        static if (is(TR == T*)) {
            if (!m_object) {
                auto newObj = this.opCall();
                (cast(FreeListRef*)&this).m_object = newObj.m_object;
                (cast(FreeListRef*)&this).m_refCount = newObj.m_refCount;
                //(cast(FreeListRef*)&this).m_magic = 0x1EE75817;
                newObj.m_object = null;
            }
        }

    }

    auto opSlice(U...)(U args) const
        if (__traits(hasMember, typeof(m_object), "opSlice"))
    {
        defaultInit();
        static if (is(U == void))
            return (cast(TR)m_object).opSlice();
        else
            return (cast(TR)m_object).opSlice(args);

    }

    size_t opDollar() const
    {
        static if (__traits(hasMember, typeof(m_object), "opDollar"))
            return m_object.opDollar();
        else assert(false, "Cannot call opDollar on object: " ~ T.stringof);
    }

    void opOpAssign(string op, U...)(U args)
        if (__traits(compiles, m_object.opOpAssign!op(args)))
    {
        defaultInit();
        m_object.opOpAssign!op(args);
    }

    //pragma(msg, T.stringof);
    static if (T.stringof == `VectorImpl!(ubyte, 2)`) {
        void opOpAssign(string op, U)(U input)
            if (op == "^")
        {
            import botan.utils.xor_buf;
            if (m_object.length < input.length)
                m_object.resize(input.length);
            
            xorBuf(m_object.ptr, input.ptr, input.length);
        }
    }
    auto opBinary(string op, U...)(U args)
        if (__traits(compiles, m_object.opBinary!op(args)))
    {
        defaultInit();
        return m_object.opBinary!op(args);
    }

    void opIndexAssign(U, V)(in U arg1, in V arg2)
        if (__traits(hasMember, typeof(m_object), "opIndexAssign"))
    {
        
        defaultInit();
        m_object.opIndexAssign(arg1, arg2);
    }

    auto ref opIndex(U...)(U args) inout
        if (__traits(hasMember, typeof(m_object), "opIndex"))
    {
        return (cast(TR)m_object).opIndex(args);
    }

    static if (__traits(compiles, m_object.opBinaryRight!("in")(ReturnType!(m_object.front).init)))
    bool opBinaryRight(string op, U)(U e) const if (op == "in") 
    {
        defaultInit();
        return m_object.opBinaryRight!("in")(e);
    }

    private @property ulong refCount() const {
        return *m_refCount;
    }
    
    private void checkInvariants()
    const {
        assert(m_magic == 0x1EE75817, "Magic number of " ~ T.stringof ~ " expected 0x1EE75817, set to: " ~ m_magic.to!string);
        assert(!m_object || refCount > 0, (!m_object) ? "No m_object" : "Zero Refcount: " ~ refCount.to!string);
    }

    private template UnConst(T) {
        static if (is(T U == const(U))) {
            alias UnConst = U;
        } else static if (is(T V == immutable(V))) {
            alias UnConst = V;
        } else alias UnConst = T;
    }
}

private void* extractUnalignedPointer(void* base)
{
    ubyte misalign = *(cast(const(ubyte)*)base-1);
    assert(misalign <= Allocator.alignment);
    return base - misalign;
}

private void* adjustPointerAlignment(void* base)
{
    ubyte misalign = Allocator.alignment - (cast(size_t)base & Allocator.alignmentMask);
    base += misalign;
    *(cast(ubyte*)base-1) = misalign;
    return base;
}

unittest {
    logTrace("Testing memory/memory.d ...");
    void testAlign(void* p, size_t adjustment) {
        void* pa = adjustPointerAlignment(p);
        assert((cast(size_t)pa & Allocator.alignmentMask) == 0, "Non-aligned pointer.");
        assert(*(cast(const(ubyte)*)pa-1) == adjustment, "Invalid adjustment "~to!string(p)~": "~to!string(*(cast(const(ubyte)*)pa-1)));
        void* pr = extractUnalignedPointer(pa);
        assert(pr == p, "Recovered base != original");
    }
    void* ptr = .malloc(0x40);
    ptr += Allocator.alignment - (cast(size_t)ptr & Allocator.alignmentMask);
    testAlign(ptr++, 0x10);
    testAlign(ptr++, 0x0F);
    testAlign(ptr++, 0x0E);
    testAlign(ptr++, 0x0D);
    testAlign(ptr++, 0x0C);
    testAlign(ptr++, 0x0B);
    testAlign(ptr++, 0x0A);
    testAlign(ptr++, 0x09);
    testAlign(ptr++, 0x08);
    testAlign(ptr++, 0x07);
    testAlign(ptr++, 0x06);
    testAlign(ptr++, 0x05);
    testAlign(ptr++, 0x04);
    testAlign(ptr++, 0x03);
    testAlign(ptr++, 0x02);
    testAlign(ptr++, 0x01);
    testAlign(ptr++, 0x10);
}

private size_t alignedSize(size_t sz)
{
    return ((sz + Allocator.alignment - 1) / Allocator.alignment) * Allocator.alignment;
}

unittest {
    logTrace("Testing memory.d ...");
    foreach( i; 0 .. 20 ){
        auto ia = alignedSize(i);
        assert(ia >= i);
        assert((ia & Allocator.alignmentMask) == 0);
        assert(ia < i+Allocator.alignment);
    }
}

private void ensureValidMemory(void[] mem)
{
    auto bytes = cast(ubyte[])mem;
    swap(bytes[0], bytes[$-1]);
    swap(bytes[0], bytes[$-1]);
}

template AllocSize(T)
{
    static if (is(T == class)) {
        // workaround for a strange bug where AllocSize!SSLStream == 0: TODO: dustmite!
        enum dummy = T.stringof ~ __traits(classInstanceSize, T).stringof;
        enum AllocSize = __traits(classInstanceSize, T);
    } else {
        enum AllocSize = T.sizeof;
    }
}