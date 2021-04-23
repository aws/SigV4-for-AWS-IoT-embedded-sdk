/*
 * SigV4 Utility Library v1.0.0
 * Copyright (C) 2021 Amazon.com, Inc. or its affiliates.  All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

/**
 * @file sigv4.c
 * @brief Implements the user-facing functions in sigv4.h
 */

#include <assert.h>
#include <string.h>

#include "sigv4.h"
#include "sigv4_internal.h"

/*-----------------------------------------------------------*/

/**
 * @brief Converts an integer value to its ASCII representation, and stores the
 * result in the provided buffer.
 *
 * @param[in] value The value to convert to ASCII.
 * @param[in, out] pBuffer The starting location of the buffer on input, and the
 * ending location on output.
 * @param[in] bufferLen Width of value to write (padded with leading 0s if
 * necessary).
 */
static void intToAscii( int32_t value,
                        char ** pBuffer,
                        size_t bufferLen );

/**
 * @brief Check if the date represents a valid leap year day.
 *
 * @param[in] pDateElements The date representation to be verified.
 *
 * @return #SigV4Success if the date corresponds to a valid leap year,
 * #SigV4ISOFormattingError otherwise.
 */
static SigV4Status_t checkLeap( const SigV4DateTime_t * pDateElements );

/**
 * @brief Verify the date stored in a SigV4DateTime_t date representation.
 *
 * @param[in] pDateElements The date representation to be verified.
 *
 * @return #SigV4Success if the date is valid, and #SigV4ISOFormattingError if
 * any member of SigV4DateTime_t is invalid or represents an out-of-range date.
 */
static SigV4Status_t validateDateTime( const SigV4DateTime_t * pDateElements );

/**
 * @brief Append the value of a date element to the internal date representation
 * structure.
 *
 * @param[in] formatChar The specifier identifying the struct member to fill.
 * @param[in] result The value to assign to the specified struct member.
 * @param[out] pDateElements The date representation structure to modify.
 */
static void addToDate( const char formatChar,
                       int32_t result,
                       SigV4DateTime_t * pDateElements );

/**
 * @brief Interpret the value of the specified characters in date, based on the
 * format specifier, and append to the internal date representation.
 *
 * @param[in] pDate The date to be parsed.
 * @param[in] formatChar The format specifier used to interpret characters.
 * @param[in] readLoc The index of pDate to read from.
 * @param[in] lenToRead The number of characters to read.
 * @param[out] pDateElements The date representation to modify.
 *
 * @return #SigV4Success if parsing succeeded, #SigV4ISOFormattingError if the
 * characters read did not match the format specifier.
 */
static SigV4Status_t scanValue( const char * pDate,
                                const char formatChar,
                                size_t readLoc,
                                size_t lenToRead,
                                SigV4DateTime_t * pDateElements );


/**
 * @brief Parses date according to format string parameter, and populates date
 * representation struct SigV4DateTime_t with its elements.
 *
 * @param[in] pDate The date to be parsed.
 * @param[in] dateLen Length of pDate, the date to be formatted.
 * @param[in] pFormat The format string used to extract date pDateElements from
 * pDate. This string, among other characters, may contain specifiers of the
 * form "%LV", where L is the number of characters to be read, and V is one of
 * {Y, M, D, h, m, s, *}, representing a year, month, day, hour, minute, second,
 * or skipped (un-parsed) value, respectively.
 * @param[in] formatLen Length of the format string pFormat.
 * @param[out] pDateElements The deconstructed date representation of pDate.
 *
 * @return #SigV4Success if all format specifiers were matched successfully,
 * #SigV4ISOFormattingError otherwise.
 */
static SigV4Status_t parseDate( const char * pDate,
                                size_t dateLen,
                                const char * pFormat,
                                size_t formatLen,
                                SigV4DateTime_t * pDateElements );

/*-----------------------------------------------------------*/

static void intToAscii( int32_t value,
                        char ** pBuffer,
                        size_t bufferLen )
{
    int32_t currentVal = value;
    size_t lenRemaining = bufferLen;

    assert( pBuffer != NULL );
    assert( bufferLen > 0U );

    /* Write base-10 remainder in its ASCII representation, and fill any
     * remaining width with '0' characters. */
    while( lenRemaining-- > 0U )
    {
        ( *pBuffer )[ lenRemaining ] = ( char ) ( ( currentVal % 10 ) + '0' );
        currentVal /= 10;
    }

    /* Move pointer to follow last written character. */
    *pBuffer += bufferLen;
}

/*-----------------------------------------------------------*/
static SigV4Status_t checkLeap( const SigV4DateTime_t * pDateElements )
{
    SigV4Status_t returnStatus = SigV4ISOFormattingError;

    assert( pDateElements != NULL );

    /* If the date represents a leap day, verify that the leap year is valid. */
    if( ( pDateElements->tm_mon == 2 ) && ( pDateElements->tm_mday == 29 ) )
    {
        if( ( ( pDateElements->tm_year % 400 ) != 0 ) &&
            ( ( ( pDateElements->tm_year % 4 ) != 0 ) ||
              ( ( pDateElements->tm_year % 100 ) == 0 ) ) )
        {
            LogError( ( "%ld is not a valid leap year.",
                        ( long int ) pDateElements->tm_year ) );
        }
        else
        {
            returnStatus = SigV4Success;
        }
    }

    return returnStatus;
}

/*-----------------------------------------------------------*/

static SigV4Status_t validateDateTime( const SigV4DateTime_t * pDateElements )
{
    SigV4Status_t returnStatus = SigV4Success;
    const int32_t daysPerMonth[] = MONTH_DAYS;

    assert( pDateElements != NULL );

    if( pDateElements->tm_year < YEAR_MIN )
    {
        LogError( ( "Invalid 'year' value parsed from date string. "
                    "Expected an integer %ld or greater, received: %ld",
                    ( long int ) YEAR_MIN,
                    ( long int ) pDateElements->tm_year ) );
        returnStatus = SigV4ISOFormattingError;
    }

    if( ( pDateElements->tm_mon < 1 ) || ( pDateElements->tm_mon > 12 ) )
    {
        LogError( ( "Invalid 'month' value parsed from date string. "
                    "Expected an integer between 1 and 12, received: %ld",
                    ( long int ) pDateElements->tm_mon ) );
        returnStatus = SigV4ISOFormattingError;
    }

    /* Ensure that the day of the month is valid for the relevant month. */
    if( ( returnStatus != SigV4ISOFormattingError ) &&
        ( ( pDateElements->tm_mday < 1 ) ||
          ( pDateElements->tm_mday > daysPerMonth[ pDateElements->tm_mon - 1 ] ) ) )
    {
        /* Check if the date is a valid leap year day. */
        returnStatus = checkLeap( pDateElements );

        if( returnStatus == SigV4ISOFormattingError )
        {
            LogError( ( "Invalid 'day' value parsed from date string. "
                        "Expected an integer between 1 and %ld, received: %ld",
                        ( long int ) daysPerMonth[ pDateElements->tm_mon - 1 ],
                        ( long int ) pDateElements->tm_mday ) );
        }
    }

    /* SigV4DateTime_t values are asserted to be non-negative before they are
     * assigned in function addToDate(). Therefore, we only verify logical upper
     * bounds for the following values. */
    if( pDateElements->tm_hour > 23 )
    {
        LogError( ( "Invalid 'hour' value parsed from date string. "
                    "Expected an integer between 0 and 23, received: %ld",
                    ( long int ) pDateElements->tm_hour ) );
        returnStatus = SigV4ISOFormattingError;
    }

    if( pDateElements->tm_min > 59 )
    {
        LogError( ( "Invalid 'minute' value parsed from date string. "
                    "Expected an integer between 0 and 59, received: %ld",
                    ( long int ) pDateElements->tm_min ) );
        returnStatus = SigV4ISOFormattingError;
    }

    /* An upper limit of 60 accounts for the occasional leap second UTC
     * adjustment. */
    if( pDateElements->tm_sec > 60 )
    {
        LogError( ( "Invalid 'second' value parsed from date string. "
                    "Expected an integer between 0 and 60, received: %ld",
                    ( long int ) pDateElements->tm_sec ) );
        returnStatus = SigV4ISOFormattingError;
    }

    return returnStatus;
}

/*-----------------------------------------------------------*/

static void addToDate( const char formatChar,
                       int32_t result,
                       SigV4DateTime_t * pDateElements )
{
    assert( pDateElements != NULL );
    assert( result >= 0 );

    switch( formatChar )
    {
        case 'Y':
            pDateElements->tm_year = result;
            break;

        case 'M':
            pDateElements->tm_mon = result;
            break;

        case 'D':
            pDateElements->tm_mday = result;
            break;

        case 'h':
            pDateElements->tm_hour = result;
            break;

        case 'm':
            pDateElements->tm_min = result;
            break;

        case 's':
            pDateElements->tm_sec = result;
            break;

        default:

            /* Do not assign values for skipped characters ('*'), or
             * unrecognized format specifiers. */
            break;
    }
}

/*-----------------------------------------------------------*/

static SigV4Status_t scanValue( const char * pDate,
                                const char formatChar,
                                size_t readLoc,
                                size_t lenToRead,
                                SigV4DateTime_t * pDateElements )
{
    SigV4Status_t returnStatus = SigV4InvalidParameter;
    const char * pMonthNames[] = MONTH_NAMES;
    const char * pLoc = pDate + readLoc;
    size_t remainingLenToRead = lenToRead;
    int32_t result = 0;

    assert( pDate != NULL );
    assert( pDateElements != NULL );

    if( formatChar == '*' )
    {
        remainingLenToRead = 0U;
    }

    /* Determine if month value is non-numeric. */
    if( ( formatChar == 'M' ) && ( *pLoc >= 'A' ) && ( *pLoc <= 'Z' ) )
    {
        assert( remainingLenToRead == MONTH_ASCII_LEN );

        while( result++ < 12 )
        {
            /* Search month array for parsed string. */
            if( strncmp( pMonthNames[ result - 1 ], pLoc, MONTH_ASCII_LEN ) == 0 )
            {
                returnStatus = SigV4Success;
                break;
            }
        }

        if( returnStatus != SigV4Success )
        {
            LogError( ( "Unable to match string '%.3s' to a month value.",
                        pLoc ) );
            returnStatus = SigV4ISOFormattingError;
        }

        remainingLenToRead = 0U;
    }

    /* Interpret integer value of numeric representation. */
    while( ( remainingLenToRead > 0U ) && ( *pLoc >= '0' ) && ( *pLoc <= '9' ) )
    {
        result = ( result * 10 ) + ( int32_t ) ( *pLoc - '0' );
        remainingLenToRead--;
        pLoc += 1;
    }

    if( remainingLenToRead != 0U )
    {
        LogError( ( "Parsing Error: Expected numerical string of type '%%%d%c', "
                    "but received '%.*s'.",
                    ( int ) lenToRead,
                    formatChar,
                    ( int ) lenToRead,
                    pLoc ) );
        returnStatus = SigV4ISOFormattingError;
    }

    if( returnStatus != SigV4ISOFormattingError )
    {
        addToDate( formatChar,
                   result,
                   pDateElements );
    }

    return returnStatus;
}

/*-----------------------------------------------------------*/

static SigV4Status_t parseDate( const char * pDate,
                                size_t dateLen,
                                const char * pFormat,
                                size_t formatLen,
                                SigV4DateTime_t * pDateElements )
{
    SigV4Status_t returnStatus = SigV4InvalidParameter;
    size_t readLoc = 0U, lenToRead = 0U, formatIndex = 0U;

    assert( pDate != NULL );
    assert( pFormat != NULL );
    assert( pDateElements != NULL );
    ( void ) dateLen;

    /* Loop through the format string. */
    while( ( formatIndex < formatLen ) && ( returnStatus != SigV4ISOFormattingError ) )
    {
        if( pFormat[ formatIndex ] == '%' )
        {
            /* '%' must be followed by a length and type specification. */
            assert( formatIndex < formatLen - 2 );
            formatIndex++;

            /* Numerical value of length specifier character. */
            lenToRead = ( ( uint32_t ) pFormat[ formatIndex ] - ( uint32_t ) '0' );
            formatIndex++;

            /* Ensure read is within buffer bounds. */
            assert( readLoc + lenToRead - 1 < dateLen );
            returnStatus = scanValue( pDate,
                                      pFormat[ formatIndex ],
                                      readLoc,
                                      lenToRead,
                                      pDateElements );

            readLoc += lenToRead;
        }
        else if( pDate[ readLoc ] != pFormat[ formatIndex ] )
        {
            LogError( ( "Parsing error: Expected character '%c', "
                        "but received '%c'.",
                        pFormat[ formatIndex ], pDate[ readLoc ] ) );
            returnStatus = SigV4ISOFormattingError;
        }
        else
        {
            readLoc++;
            LogDebug( ( "Successfully matched character '%c' found in format string.",
                        pDate[ readLoc - 1 ] ) );
        }

        formatIndex++;
    }

    if( ( returnStatus != SigV4ISOFormattingError ) )
    {
        returnStatus = SigV4Success;
    }
    else
    {
        LogError( ( "Parsing Error: Date did not match expected string format." ) );
        returnStatus = SigV4ISOFormattingError;
    }

    return returnStatus;
}

/*-----------------------------------------------------------*/


SigV4Status_t SigV4_AwsIotDateToIso8601( const char * pDate,
                                         size_t dateLen,
                                         char * pDateISO8601,
                                         size_t dateISO8601Len )
{
    SigV4Status_t returnStatus = SigV4InvalidParameter;
    SigV4DateTime_t date = { 0 };
    char * pWriteLoc = pDateISO8601;
    const char * pFormatStr = NULL;
    size_t formatLen = 0U;

    /* Check for NULL parameters. */
    if( pDate == NULL )
    {
        LogError( ( "Parameter check failed: pDate is NULL." ) );
    }
    else if( pDateISO8601 == NULL )
    {
        LogError( ( "Parameter check failed: pDateISO8601 is NULL." ) );
    }
    /* Check that the date provided is of the expected length. */
    else if( ( dateLen != SIGV4_EXPECTED_LEN_RFC_3339 ) &&
             ( dateLen != SIGV4_EXPECTED_LEN_RFC_5322 ) )
    {
        LogError( ( "Parameter check failed: dateLen must be either %u or %u, "
                    "for RFC 3339 and RFC 5322 formats, respectively.",
                    SIGV4_EXPECTED_LEN_RFC_3339,
                    SIGV4_EXPECTED_LEN_RFC_5322 ) );
    }

    /* Check that the output buffer provided is large enough for the formatted
     * string. */
    else if( dateISO8601Len < SIGV4_ISO_STRING_LEN )
    {
        LogError( ( "Parameter check failed: dateISO8601Len must be at least %u.",
                    SIGV4_ISO_STRING_LEN ) );
    }
    else
    {
        /* Assign format string according to input type received. */
        pFormatStr = ( dateLen == SIGV4_EXPECTED_LEN_RFC_3339 ) ?
                     ( FORMAT_RFC_3339 ) : ( FORMAT_RFC_5322 );

        formatLen = ( dateLen == SIGV4_EXPECTED_LEN_RFC_3339 ) ?
                    ( FORMAT_RFC_3339_LEN ) : ( FORMAT_RFC_5322_LEN );

        returnStatus = parseDate( pDate, dateLen, pFormatStr, formatLen, &date );
    }

    if( returnStatus == SigV4Success )
    {
        returnStatus = validateDateTime( &date );
    }

    if( returnStatus == SigV4Success )
    {
        /* Combine date elements into complete ASCII representation, and fill
         * buffer with result. */
        intToAscii( date.tm_year, &pWriteLoc, ISO_YEAR_LEN );
        intToAscii( date.tm_mon, &pWriteLoc, ISO_NON_YEAR_LEN );
        intToAscii( date.tm_mday, &pWriteLoc, ISO_NON_YEAR_LEN );
        *pWriteLoc = 'T';
        pWriteLoc++;
        intToAscii( date.tm_hour, &pWriteLoc, ISO_NON_YEAR_LEN );
        intToAscii( date.tm_min, &pWriteLoc, ISO_NON_YEAR_LEN );
        intToAscii( date.tm_sec, &pWriteLoc, ISO_NON_YEAR_LEN );
        *pWriteLoc = 'Z';

        LogDebug( ( "Successfully formatted ISO 8601 date: \"%.*s\"",
                    ( int ) dateISO8601Len,
                    pDateISO8601 ) );
    }

    return returnStatus;
}
