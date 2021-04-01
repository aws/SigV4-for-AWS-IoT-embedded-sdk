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
 * @brief Format an ISO 8601 date, and fill the output buffer with the result.
 *
 * @param[in] pDate The date to be formatted, in RFC3339 format.
 * @param[in] pDateISO8601 The buffer to hold the ISO 8601 encoded date.
 *
 * @return #SigV4Success if successful, and #SigV4ISOFormattingError if a
 * parsing error occurred due to an incorrectly formatted date. If pDate is
 * correctly formatted but contains an out-of-range date, #SigV4InvalidParameter
 * is returned.
 */
static SigV4Status_t formatDate( const char * pDate,
                                 char * pDateISO8601 );

/*-----------------------------------------------------------*/

static SigV4Status_t formatDate( const char * pDate,
                                 char * pDateISO8601 )
{
    SigV4Status_t returnStatus = SigV4ISOFormattingError;
    struct tm dateInfo = { 0 };

    /* Parse pDate according to the input's expected string format, and populate
     * the date struct with its components.  */
    if( sscanf( pDate, "%4d-%2d-%2dT%2d:%2d:%2dZ",
                &dateInfo.tm_year,
                &dateInfo.tm_mon,
                &dateInfo.tm_mday,
                &dateInfo.tm_hour,
                &dateInfo.tm_min,
                &dateInfo.tm_sec ) != 6 )
    {
        LogError( ( "Failed to generate ISO 8601 date: call to sscanf() for input parsing failed." ) );
        returnStatus = SigV4ISOFormattingError;

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

        if( ( dateInfo.tm_year < 1900 ) )
    {
        LogError( ( "Invalid 'year' value parsed from date string. "
                        "Expected an integer larger than 1900, received: %ld",
                        ( long int ) dateInfo.tm_year ) );
            returnStatus = SigV4InvalidParameter;
    }

        if( ( dateInfo.tm_mon < 1 ) || ( dateInfo.tm_mon > 12 ) )
    {
        LogError( ( "Invalid 'month' value parsed from date string. "
                    "Expected an integer between 1 and 12, received: %ld",
                        ( long int ) dateInfo.tm_mon ) );
            returnStatus = SigV4InvalidParameter;
    }

        if( ( dateInfo.tm_mday < 1 ) || ( dateInfo.tm_mday > 31 ) )
        {
            LogError( ( "Invalid 'day' value parsed from date string. "
                        "Expected an integer between 1 and 31, received: %ld",
                        ( long int ) dateInfo.tm_mday ) );
            returnStatus = SigV4InvalidParameter;
    }

        if( ( dateInfo.tm_hour < 0 ) || ( dateInfo.tm_hour > 23 ) )
    {
        LogError( ( "Invalid 'hour' value parsed from date string. "
                    "Expected an integer between 0 and 23, received: %ld",
                        ( long int ) dateInfo.tm_hour ) );
            returnStatus = SigV4InvalidParameter;
    }

        if( ( dateInfo.tm_min < 0 ) || ( dateInfo.tm_min > 59 ) )
    {
        LogError( ( "Invalid 'minute' value parsed from date string. "
                    "Expected an integer between 0 and 59, received: %ld",
                        ( long int ) dateInfo.tm_min ) );
            returnStatus = SigV4InvalidParameter;
    }

        /* C90 allows for an additional leap second corresponding to the (rare)
         * UTC adjustment. */
        if( ( dateInfo.tm_sec < 0 ) || ( dateInfo.tm_sec > 60 ) )
    {
        LogError( ( "Invalid 'second' value parsed from date string. "
                    "Expected an integer between 0 and 60, received: %ld",
                        ( long int ) dateInfo.tm_sec ) );
            returnStatus = SigV4InvalidParameter;
    }

        if( returnStatus != SigV4InvalidParameter )
{
            /* Standardize month and year values for struct tm's specifications:
             *  - tm_mon = "months from January" (0-11)
             *  - tm_year = "years since 1900" */
            dateInfo.tm_mon--;
            dateInfo.tm_year -= 1900;

            /* Construct ISO 8601 string using members of populated date struct. */
            lenFormatted = strftime( pDateISO8601, SIGV4_ISO_STRING_LEN + 1, "%Y%m%dT%H%M%SZ", &dateInfo );

            if( lenFormatted != SIGV4_ISO_STRING_LEN )
    {
                LogError( ( "Failed to generate ISO 8601 date: call to strftime() for string formatting failed: "
                            "ExpectedReturnValue=%u, ActualReturnValue=%lu.",
                            SIGV4_ISO_STRING_LEN,
                            ( unsigned long ) lenFormatted ) );
                returnStatus = SigV4ISOFormattingError;
    }
    else
    {
                returnStatus = SigV4Success;
            }
    }
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
        returnStatus = formatDate( pDate, pDateISO8601 );
    }

    return returnStatus;
}
