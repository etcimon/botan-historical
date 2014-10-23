/*
* Cipher Modes
* (C) 2013 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.modes.cipher_mode;

import botan.algo_base.transform;

/**
* Interface for cipher modes
*/
class Cipher_Mode : Keyed_Transform
{
public:
	/**
	* Returns true iff this mode provides authentication as well as
	* confidentiality.
	*/
	abstract bool authenticated() const { return false; }
};