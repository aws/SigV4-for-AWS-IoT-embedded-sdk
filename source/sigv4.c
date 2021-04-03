/*
 * SigV4 Utility Library v1.0.0
 * Copyright (C) 2020 Amazon.com, Inc. or its affiliates.  All Rights Reserved.
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
#include <ctype.h>

#include "sigv4.h"
#include "sigv4_internal.h"

/*-----------------------------------------------------------*/

/**
 * @brief Converts an integer value to its ASCII respresentation, and stores the
 * result in the provided buffer.
 *
 * @param[in] value The value to convert to ASCII.
 * @param[in, out] pBuffer The starting location of the buffer on input, and the
 * ending location on output.
 * @param[in] lenBuf Width of value to write (padded with leading 0s if
 * necessary).
 */
static void intToAscii( int32_t value,
                        char ** pBuffer,
                        size_t lenBuf );

/**
 * @brief Parses date according to format string parameter, and populates date
 * representation struct SigV4DateTime_t with its elements.
 *
 * @param[in] pDate The date to be parsed.
 * @param[in] dateLen Length of pDate, the date to be formatted.
 * @param[in] pFormat The format string used to extract date pDateElements from pDate.
 * This string, among other characters, may contain specifiers of the form
 * "%LV", where L is the number of characters to be readLoc, and V is one of
 * {Y, M, D, h, m, s, *}, representing a year, month, day, hour, minute, second,
 * or skipped (un-parsed) value, respectively.
 * @param[in] formatLen Length of the format string pFormat.
 * @param[out] pDateElements The deconstructed date representation of pDate.
 *
 * @return The number of format specifiers found and filled in pDateElements.
 */
static size_t parseDate( const char * pDate,
                         size_t dateLen,
                         const char * pFormat,
                         size_t formatLen,
                         SigV4DateTime_t * pDateElements );

/**
 * @brief Verify date stored in a SigV4DateTime_t date representation.
 *
 * @param[in] pDateElements The date representation to be verified.
 *
 * @return #SigV4Success if successful, and #SigV4ISOFormattingError if any
 * member of SigV4DateTime_t is invalid or represents an out-of-range date.
 */
static SigV4Status_t validateDateTime( SigV4DateTime_t * pDateElements );

/**
 * @brief Format an ISO 8601 date, and fill the output buffer with the result.
 *
 * @param[in] pDate The date to be formatted, in RFC3339 format.
 * @param[in] dateLen Length of pDate, the date to be formatted.
 * @param[in] pDateISO8601 The buffer to hold the ISO 8601 encoded date.
 * @param[in] dateISO8601Len Length of pDateISO8601, the formatted date buffer.
 *
 * @return #SigV4Success if successful, and #SigV4ISOFormattingError if a
 * parsing error occurred due to an incorrectly formatted date, or if pDate
 * contains an out-of-range date.
 */
static SigV4Status_t dateToIso8601( const char * pDate,
                                    size_t dateLen,
                                    char * pDateISO8601,
                                    size_t dateISO8601Len );

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
    while( lenRemaining-- )
    {
        ( *pBuffer )[ lenRemaining ] = ( currentVal % 10 ) + '0';
        currentVal /= 10;
    }

    /* Move pointer to follow last written character. */
    *pBuffer += bufferLen;
}

/*-----------------------------------------------------------*/

static size_t parseDate( const char * pDate,
                         size_t dateLen,
                         const char * pFormat,
                         size_t formatLen,
                         SigV4DateTime_t * pDateElements )
{
    size_t readLoc = 0U, lenToRead = 0U, formatIndex = 0U, count = 0U;
    int32_t result = 0;
    char * pMonthNames[] = MONTH_NAMES;

    assert( pDate != NULL );
    assert( pFormat != NULL );
    assert( pDateElements != NULL );

    /* Loop through format string. */
    while( formatIndex < formatLen )
    {
        if( pFormat[ formatIndex ] == '%' )
        {
            /* '%' must be followed by a length and type specification. */
            assert( formatIndex < formatLen - 2 );

            /* Numerical value of length specifier character. */
            lenToRead = pFormat[ ++formatIndex ] - '0';
            result = 0;

            /* Ensure read is within buffer bounds. */
            assert( readLoc + lenToRead - 1 < dateLen );

            /* Read specified characters from pDate. */
            do
            {
                if( !isdigit( pDate[ readLoc ] ) )
                {
                    /* Month and skipped characters can be non-numeric, and are
                     * handled by the switch statement. */
                    if( ( pFormat[ formatIndex + 1U ] != 'M' ) &&
                        ( pFormat[ formatIndex + 1U ] != '*' ) )
                    {
                        LogError( ( "Parsing Error: Expected numerical string of type '%%%d%c', "
                                    "but received '%.*s'.",
                                    ( int ) lenToRead,
                                    pFormat[ formatIndex + 1U ],
                                    ( int ) lenToRead,
                                    &pDate[ readLoc ] ) );
                    }

                    /* Set invalid value to allow switch statement to handle
                     * case based on specifier. */
                    result = -1;
                    break;
                }

                result = result * 10 + ( pDate[ readLoc++ ] - '0' );
            } while( --lenToRead );

            switch( pFormat[ ++formatIndex ] )
            {
                case 'Y':
                    pDateElements->tm_year = result;
                    count += ( result != -1 ) ? 1 : 0;
                    break;

                case 'M':

                    /* Numerical month representation (ex. RFC 3339). */
                    if( result > 0 )
                    {
                        pDateElements->tm_mon = result;
                        count++;
                    }
                    /* Non-numerical month representation (ex. RFC 5322). */
                    else if( lenToRead == 3U )
                    {
                        result = 0;

                        while( result < 12 )
                        {
                            /* If parsed value exists in pMonthNames, assign
                             * numerical representation. */
                            if( strncmp( pMonthNames[ result++ ], &pDate[ readLoc ], lenToRead ) == 0 )
                            {
                                pDateElements->tm_mon = result;
                                readLoc += lenToRead;
                                count++;
                                break;
                            }
                        }
                    }

                    break;

                case 'D':
                    pDateElements->tm_mday = result;
                    count += ( result != -1 ) ? 1 : 0;
                    break;

                case 'h':
                    pDateElements->tm_hour = result;
                    count += ( result != -1 ) ? 1 : 0;
                    break;

                case 'm':
                    pDateElements->tm_min = result;
                    count += ( result != -1 ) ? 1 : 0;
                    break;

                case 's':
                    pDateElements->tm_sec = result;
                    count += ( result != -1 ) ? 1 : 0;
                    break;

                case '*':
                    readLoc += lenToRead;
                    break;

                default:
                    LogError( ( "Parsing error: Unexpected character '%c' "
                                "found in format string.",
                                ( char ) pFormat[ ++formatIndex ] ) );
                    break;
            }
        }
        else
        {
            if( pDate[ readLoc++ ] != pFormat[ formatIndex ] )
            {
                LogError( ( "Parsing error: Expected character '%c', "
                            "but received '%c'.",
                            pFormat[ formatIndex ], pDate[ readLoc - 1 ] ) );
                break;
            }
        }

        formatIndex++;
    }

    return count;
}

/*-----------------------------------------------------------*/

static SigV4Status_t validateDateTime( SigV4DateTime_t * pDateElements )
{
    SigV4Status_t returnStatus = SigV4InvalidParameter;
    int32_t daysPerMonth[] = MONTH_DAYS;

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

    /* Ensure that day value is within the valid range of its relevant month. */
    else if( ( pDateElements->tm_mday < 1 ) ||
             ( pDateElements->tm_mday > daysPerMonth[ pDateElements->tm_mon - 1 ] ) )
    {
        /* Check validity of a leap year date. */
        if( ( pDateElements->tm_mon == 2 ) && ( pDateElements->tm_mday == 29 ) )
        {
            if( ( ( pDateElements->tm_year % 400 ) != 0 ) &&
                ( ( ( pDateElements->tm_year % 4 ) != 0 ) ||
                  ( ( pDateElements->tm_year % 100 ) == 0 ) ) )
            {
                LogError( ( "%ld is not a valid leap year.",
                            ( long int ) pDateElements->tm_year ) );
                returnStatus = SigV4ISOFormattingError;
            }
        }
        else
        {
            LogError( ( "Invalid 'day' value parsed from date string. "
                        "Expected an integer between 1 and 31, received: %ld",
                        ( long int ) pDateElements->tm_mday ) );

            returnStatus = SigV4ISOFormattingError;
        }
    }

    if( ( pDateElements->tm_hour < 0 ) || ( pDateElements->tm_hour > 23 ) )
    {
        LogError( ( "Invalid 'hour' value parsed from date string. "
                    "Expected an integer between 0 and 23, received: %ld",
                    ( long int ) pDateElements->tm_hour ) );
        returnStatus = SigV4ISOFormattingError;
    }

    if( ( pDateElements->tm_min < 0 ) || ( pDateElements->tm_min > 59 ) )
    {
        LogError( ( "Invalid 'minute' value parsed from date string. "
                    "Expected an integer between 0 and 59, received: %ld",
                    ( long int ) pDateElements->tm_min ) );
        returnStatus = SigV4ISOFormattingError;
    }

    /* An upper limit of 60 accounts for the occasional leap second UTC
     * adjustment. */
    if( ( pDateElements->tm_sec < 0 ) || ( pDateElements->tm_sec > 60 ) )
    {
        LogError( ( "Invalid 'second' value parsed from date string. "
                    "Expected an integer between 0 and 60, received: %ld",
                    ( long int ) pDateElements->tm_sec ) );
        returnStatus = SigV4ISOFormattingError;
    }

    return ( returnStatus != SigV4ISOFormattingError ) ? SigV4Success : returnStatus;
}

/*-----------------------------------------------------------*/

static SigV4Status_t dateToIso8601( const char * pDate,
                                    size_t dateLen,
                                    char * pDateISO8601,
                                    size_t dateISO8601Len )
{
    SigV4Status_t returnStatus = SigV4InvalidParameter;
    SigV4DateTime_t date = { 0 };
    char * pWriteLoc = pDateISO8601;
    const char * pFormatStr = NULL;
    size_t formatLen = 0U;

    assert( pDate != NULL );
    assert( pDateISO8601 != NULL );
    assert( dateLen == SIGV4_EXPECTED_LEN_RFC_3339 ||
            dateLen == SIGV4_EXPECTED_LEN_RFC_5322 );
    assert( dateISO8601Len >= SIGV4_ISO_STRING_LEN );

    /* Assign format string according to input type received. */
    pFormatStr = ( dateLen == SIGV4_EXPECTED_LEN_RFC_3339 ) ?
                 FORMAT_RFC_3339 : FORMAT_RFC_5322;

    formatLen = ( dateLen == SIGV4_EXPECTED_LEN_RFC_3339 ) ?
                FORMAT_RFC_3339_LEN : FORMAT_RFC_5322_LEN;

    /* ISO 8601 contains 6 numerical date components requiring parsing. */
    if( parseDate( pDate, dateLen, pFormatStr, formatLen, &date ) == 6U )
    {
        returnStatus = validateDateTime( &date );
    }
    else
    {
        LogError( ( "Parsing Error: Date did not match expected string format." ) );
        returnStatus = SigV4ISOFormattingError;
    }

    if( returnStatus == SigV4Success )
    {
        /* Combine date elements into complete ASCII representation, and fill
         * buffer with result. */
        intToAscii( date.tm_year, &pWriteLoc, ISO_YEAR_LEN );
        intToAscii( date.tm_mon, &pWriteLoc, ISO_NON_YEAR_LEN );
        intToAscii( date.tm_mday, &pWriteLoc, ISO_NON_YEAR_LEN );
        *pWriteLoc++ = 'T';

        intToAscii( date.tm_hour, &pWriteLoc, ISO_NON_YEAR_LEN );
        intToAscii( date.tm_min, &pWriteLoc, ISO_NON_YEAR_LEN );
        intToAscii( date.tm_sec, &pWriteLoc, ISO_NON_YEAR_LEN );
        *pWriteLoc++ = 'Z';

        LogDebug( ( "Successfully formatted ISO 8601 date: \"%.*s\"",
                    ( int ) dateISO8601Len,
                    pDateISO8601 ) );
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
        returnStatus = dateToIso8601( pDate, dateLen, pDateISO8601, dateISO8601Len );
    }

    return returnStatus;
}
