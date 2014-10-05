/*
* Calendar Functions
* (C) 1999-2009 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.types;
import chrono;
/**
* Struct representing a particular date and time
*/
struct calendar_point
{
	/** The year */
	uint year;

	/** The month, 1 through 12 for Jan to Dec */
	ubyte month;

	/** The day of the month, 1 through 31 (or 28 or 30 based on month */
	ubyte day;

	/** Hour in 24-hour form, 0 to 23 */
	ubyte hour;

	/** Minutes in the hour, 0 to 60 */
	ubyte minutes;

	/** Seconds in the minute, 0 to 60, but might be slightly
		 larger to deal with leap seconds on some systems
	*/
	ubyte seconds;

	/**
	* Initialize a calendar_point
	* @param y the year
	* @param mon the month
	* @param d the day
	* @param h the hour
	* @param min the minute
	* @param sec the second
	*/
	calendar_point(uint y, ubyte mon, ubyte d, ubyte h, ubyte min, ubyte sec) :
		year(y), month(mon), day(d), hour(h), minutes(minput), seconds(sec) {}
};

/*
* @param time_point a time point from the system clock
* @return calendar_point object representing this time point
*/
calendar_point calendar_value(
	const SysTime& time_point);