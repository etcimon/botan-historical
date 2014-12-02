/*
* Win32 CAPI EntropySource
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.entropy.es_capi;

version(Windows):
static if (BOTAN_HAS_ENTROPY_SRC_CAPI):

import botan.entropy.entropy_src;
import botan.utils.types;
import botan.utils.parsing;
import windows.h;
import wincrypt.h;

/**
* Win32 CAPI Entropy Source
*/
final class Win32_CAPI_EntropySource : EntropySource
{
public:
    @property string name() const { return "Win32 CryptoGenRandom"; }

    /*
    * Gather Entropy from Win32 CAPI
    */
    void poll(ref Entropy_Accumulator accum)
    {
        Secure_Vector!ubyte io_buffer = accum.get_io_buffer(32);
        
        foreach (prov_type; m_prov_types[])
        {
            CSP_Handle csp = CSP_Handle(prov_type);
            
            size_t got = csp.gen_random(io_buffer.ptr, io_buffer.length);
            
            if (got)
            {
                accum.add(io_buffer.ptr, io_buffer.length, 6);
                break;
            }
        }
    }

    /**
    * Win32_Capi_Entropysource Constructor
    * @param provs = list of providers, separated by ':'
    */
    this(in string provs = "")
    {
        Vector!string capi_provs = splitter(provs, ':');
        
        foreach (capi_prov; capi_provs)
        {
            if (capi_prov == "RSA_FULL")  m_prov_types.push_back(PROV_RSA_FULL);
            if (capi_prov == "INTEL_SEC") m_prov_types.push_back(PROV_INTEL_SEC);
            if (capi_prov == "FORTEZZA")  m_prov_types.push_back(PROV_FORTEZZA);
            if (capi_prov == "RNG")         m_prov_types.push_back(PROV_RNG);
        }
        
        if (m_prov_types.length == 0)
            m_prov_types.push_back(PROV_RSA_FULL);
    }

    private:
        Vector!( ulong ) m_prov_types;
}

final class CSP_Handle
{
public:
    this(ulong capi_provider)
    {
        m_valid = false;
        DWORD prov_type = cast(DWORD)capi_provider;
        
        if (CryptAcquireContext(&m_handle, 0, 0,
                                prov_type, CRYPT_VERIFYCONTEXT))
            m_valid = true;
    }
    
    ~this()
    {
        if (is_valid())
            CryptReleaseContext(m_handle, 0);
    }
    
    size_t gen_random(ubyte* output) const
    {
        if (is_valid() && CryptGenRandom(m_handle, cast(DWORD)(output.length), output))
            return output.length;
        return 0;
    }
    
    bool is_valid() const { return m_valid; }
    
    HCRYPTPROV get_handle() const { return m_handle; }
private:
    HCRYPTPROV m_handle;
    bool m_valid;
}
