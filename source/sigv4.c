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

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <time.h>

#include "sigv4.h"

/*-----------------------------------------------------------*/

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
    }
    else
    {
        size_t lenFormatted = 0U;

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
    else if( dateLen != SIGV4_EXPECTED_AWS_IOT_DATE_LEN )
    {
        LogError( ( "Parameter check failed: dateLen must be %u.",
                    SIGV4_EXPECTED_AWS_IOT_DATE_LEN ) );
    }

    /* Check that the output buffer provided is large enough for the formatted
     * string. */
    else if( dateISO8601Len < SIGV4_ISO_STRING_LEN + 1 )
    {
        LogError( ( "Parameter check failed: dateISO8601Len must be at least %u.",
                    SIGV4_ISO_STRING_LEN + 1 ) );
    }
    else
    {
        returnStatus = formatDate( pDate, pDateISO8601 );
    }

    return returnStatus;
}
