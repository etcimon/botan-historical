﻿/**
    Defines a string based multi-map with conserved insertion order.

    Copyright: © 2012-2014 RejectedSoftware e.K.
    License: Subject to the terms of the MIT license, as written in the included LICENSE.txt file.
    Authors: Sönke Ludwig
*/
module botan.utils.containers.multimap;

import botan.utils.memory.memory;
import botan.utils.types;
import std.exception : enforce;

alias MultiMap(KEY, VALUE, bool case_sensitive = true, size_t NUM_STATIC_FIELDS = 8) = FreeListRef!(DictionaryList!(KEY, VALUE, case_sensitive, NUM_STATIC_FIELDS));

/**
 * 
    Behaves similar to $(D VALUE[string]) but the insertion order is not changed
    and multiple values per key are supported.
    Note that despite case not being relevant for matching keyse, iterating
    over the map will yield    the original case of the key that was put in.

    Insertion and lookup has O(n) complexity.
*/
struct DictionaryList(KEY, VALUE, bool case_sensitive = true, size_t NUM_STATIC_FIELDS = 8) {
    import std.typecons : Tuple;
    
    private {
        static struct Field { uint keyCheckSum; KEY key; VALUE value; }
        Field[NUM_STATIC_FIELDS] m_fields;
        size_t m_fieldCount = 0;
        Field[] m_extendedFields;
        static char[256] s_keyBuffer;
    }

    alias KeyType = KEY;
    alias ValueType = VALUE;
    
    struct FieldTuple { KeyType key; ValueType value; }
    
    /** The number of fields present in the map.
    */
    @property size_t length() const { return m_fieldCount + m_extendedFields.length; }
    
    /** Removes the first field that matches the given key.
    */
    void remove(KeyType key)
    {
        auto keysum = computeCheckSumI(key);
        auto idx = getIndex(m_fields[0 .. m_fieldCount], key, keysum);
        if( idx >= 0 ){
            auto slice = m_fields[0 .. m_fieldCount];
            removeFromArrayIdx(slice, idx);
            m_fieldCount--;
        } else {
            idx = getIndex(m_extendedFields, key, keysum);
            enforce(idx >= 0);
            removeFromArrayIdx(m_extendedFields, idx);
        }
    }
    
    /** Removes all fields that matches the given key.
    */
    void removeAll(KeyType key)
    {
        auto keysum = computeCheckSumI(key);
        for (size_t i = 0; i < m_fieldCount;) {
            if (m_fields[i].keyCheckSum == keysum && matches(m_fields[i].key, key)) {
                auto slice = m_fields[0 .. m_fieldCount];
                removeFromArrayIdx(slice, i);
                m_fieldCount--;
            } else i++;
        }
        
        for (size_t i = 0; i < m_extendedFields.length;) {
            if (m_fields[i].keyCheckSum == keysum && matches(m_fields[i].key, key))
                removeFromArrayIdx(m_extendedFields, i);
            else i++;
        }
    }
    
    /** Adds a new field to the map.

        The new field will be added regardless of any existing fields that
        have the same key, possibly resulting in duplicates. Use opIndexAssign
        if you want to avoid duplicates.
    */
    void insert(KeyType key, ValueType value)
    {
        auto keysum = computeCheckSumI(key);
        if (m_fieldCount < m_fields.length)
            m_fields[m_fieldCount++] = Field(keysum, key, value);
        else m_extendedFields ~= Field(keysum, key, value);
    }

    /** Returns the first field that matches the given key.

        If no field is found, def_val is returned.
    */
    inout(ValueType) get(KeyType key, lazy inout(ValueType) def_val = ValueType.init)
    inout {
        if (auto pv = key in this) return *pv;
        return def_val;
    }
    
    /** Returns all values matching the given key.

        Note that the version returning an array will allocate for each call.
    */
    const(ValueType)[] equal_range(KeyType key)
    const {
        import std.array;
        auto ret = appender!(const(ValueType)[])();
        getAll(key, (v) { ret.put(v); });
        return ret.data;
    }
    /// ditto
    void equal_range(KeyType key, scope void delegate(const(ValueType)) del)
    const {
        uint keysum = computeCheckSumI(key);
        foreach (ref f; m_fields[0 .. m_fieldCount]) {
            if (f.keyCheckSum != keysum) continue;
            if (matches(f.key, key)) del(f.value);
        }
        foreach (ref f; m_extendedFields) {
            if (f.keyCheckSum != keysum) continue;
            if (matches(f.key, key)) del(f.value);
        }
    }
    
    /** Returns the first value matching the given key.
    */
    inout(ValueType) opIndex(KeyType key)
    inout {
        auto pitm = key in this;
        enforce(pitm !is null, "Accessing non-existent key '"~key~"'.");
        return *pitm;
    }
    
    /** Adds or replaces the given field with a new value.
    */
    ValueType opIndexAssign(ValueType val, KeyType key)
    {
        auto pitm = key in this;
        if( pitm ) *pitm = val;
        else if( m_fieldCount < m_fields.length ) m_fields[m_fieldCount++] = Field(computeCheckSumI(key), key, val);
        else m_extendedFields ~= Field(computeCheckSumI(key), key, val);
        return val;
    }
    
    /** Returns a pointer to the first field that matches the given key.
    */
    inout(ValueType)* opBinaryRight(string op)(KeyType key) inout if(op == "in") {
        uint keysum = computeCheckSumI(key);
        auto idx = getIndex(m_fields[0 .. m_fieldCount], key, keysum);
        if( idx >= 0 ) return &m_fields[idx].value;
        idx = getIndex(m_extendedFields, key, keysum);
        if( idx >= 0 ) return &m_extendedFields[idx].value;
        return null;
    }
    /// ditto
    bool opBinaryRight(string op)(KeyType key) inout if(op == "!in") {
        return !(key in this);
    }
    
    /** Iterates over all fields, including duplicates.
    */
    int opApply(scope int delegate(KeyType key, ref ValueType val) del)
    {
        foreach (ref kv; m_fields[0 .. m_fieldCount]) {
            if (auto ret = del(kv.key, kv.value))
                return ret;
        }
        foreach (ref kv; m_extendedFields) {
            if (auto ret = del(kv.key, kv.value))
                return ret;
        }
        return 0;
    }
    
    /// ditto
    int opApply(scope int delegate(ref ValueType val) del)
    {
        return this.opApply((KeyType key, ref ValueType val) { return del(val); });
    }
    
    /// ditto
    int opApply(scope int delegate(KeyType key, ref const(ValueType) val) del) const
    {
        return (cast() this).opApply(cast(int delegate(KeyType, ref ValueType)) del);
    }
    
    /// ditto
    int opApply(scope int delegate(ref const(ValueType) val) del) const
    {
        return (cast() this).opApply(cast(int delegate(ref ValueType)) del);
    }
    
    private ptrdiff_t getIndex(in Field[] map, KeyType key, uint keysum)
    const {
        foreach (i, ref const(Field) entry; map) {
            if (entry.keyCheckSum != keysum) continue;
            if (matches(entry.key, key)) return i;
        }
        return -1;
    }
    
    private static bool matches(KeyType a, KeyType b)
    {
        static if (case_sensitive) return a == b;
        else static if (is (KeyType == string)) return icmp2(a, b) == 0;
        else return a == b;
    }
    
    // very simple check sum function with a good chance to match
    // strings with different case equal
    private static uint computeCheckSumI(string s)
    @trusted {
        uint csum = 0;
        immutable(char)* pc = s.ptr, pe = s.ptr + s.length;
        for (; pc != pe; pc++) {
            static if (case_sensitive) csum ^= *pc;
            else csum ^= *pc & 0x1101_1111;
            csum = (csum << 1) | (csum >> 31);
        }
        return csum;
    }
}

void removeFromArrayIdx(T)(ref T[] array, size_t idx)
{
    foreach( j; idx+1 .. array.length)
        array[j-1] = array[j];
    array.length = array.length-1;
}

/// Special version of icmp() with optimization for ASCII characters
int icmp2(string a, string b)
@safe pure {
    size_t i = 0, j = 0;
    
    // fast skip equal prefix
    size_t min_len = min(a.length, b.length);
    while ( i < min_len && a[i] == b[i] ) i++;
    if( i > 0 && (a[i-1] & 0x80) ) i--; // don't stop half-way in a UTF-8 sequence
    j = i;
    
    // compare the differing character and the rest of the string
    while (i < a.length && j < b.length){
        uint ac = cast(uint)a[i];
        uint bc = cast(uint)b[j];
        if( !((ac | bc) & 0x80) ){
            i++;
            j++;
            if( ac >= 'A' && ac <= 'Z' ) ac += 'a' - 'A';
            if( bc >= 'A' && bc <= 'Z' ) bc += 'a' - 'A';
            if( ac < bc ) return -1;
            else if( ac > bc ) return 1;
        } else {
            dchar acp = decode(a, i);
            dchar bcp = decode(b, j);
            if( acp != bcp ){
                acp = std.uni.toLower(acp);
                bcp = std.uni.toLower(bcp);
                if( acp < bcp ) return -1;
                else if( acp > bcp ) return 1;
            }
        }
    }
    
    if( i < a.length ) return 1;
    else if( j < b.length ) return -1;
    
    assert(i == a.length || j == b.length, "Strings equal but we didn't fully compare them!?");
    return 0;
}