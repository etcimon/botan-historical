/*
* Exceptions
* (C) 2004-2006 Jack Lloyd
*
* Released under the terms of the botan license.
*/
module botan.tls.tls_exceptn;

import botan.constants;
static if (BOTAN_HAS_TLS):

import botan.utils.exceptn;
import botan.tls.tls_alert;

/**
* Exception Base Class
*/
class TLS_Exception : Exception
{
public:
    TLS_Alert_Type type() const nothrow { return m_alert_type; }

    this(TLS_Alert_Type type, in string err_msg = "Unknown error") {
        m_alert_type = type;
        super(err_msg);
    }

private:
    TLS_Alert_Type m_alert_type;
}

/**
* TLS_Unexpected_Message Exception
*/
class TLS_Unexpected_Message : TLS_Exception
{
    this(in string err) 
    {
        super(TLS_Alert.UNEXPECTED_MESSAGE, err);
    }
}