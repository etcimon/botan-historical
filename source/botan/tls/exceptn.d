/*
* Exceptions
* (C) 2004-2006 Jack Lloyd
*
* Released under the terms of the botan license.
*/
module botan.tls.exceptn;

import botan.constants;
static if (BOTAN_HAS_TLS):

import botan.utils.exceptn;
import botan.tls.alert;

/**
* Exception Base Class
*/
class TLSException : Exception
{
public:
    TLSAlertType type() const nothrow { return m_alert_type; }

    this(TLSAlertType type, in string err_msg = "Unknown error") {
        m_alert_type = type;
        super(err_msg);
    }

private:
    TLSAlertType m_alert_type;
}

/**
* TLS_Unexpected_Message Exception
*/
class TLSUnexpectedMessage : TLS_Exception
{
    this(in string err) 
    {
        super(TLSAlert.UNEXPECTED_MESSAGE, err);
    }
}