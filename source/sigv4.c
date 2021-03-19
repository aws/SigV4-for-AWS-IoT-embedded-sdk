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

SigV4Status_t SigV4_AwsIotDateToIso8601( const char * pDate,
                                         size_t dateLen,
                                         char * pDateISO8601,
                                         size_t dateISO8601Len )
{
    SigV4Status_t returnStatus = SigV4InvalidParameter;
    size_t lenFormatted = 0U;
    struct tm dateInfo;

    /* Check for NULL parameters. */
    if( pDate == NULL )
    {
        LogError( ( "Parameter check failed: pDate is NULL." ) );
    }
    else if( pDateISO8601 == NULL )
    {
        LogError( ( "Parameter check failed: pDateISO8601 is NULL." ) );
    }

    /* Check that the date buffer provided is not shorter than the expected
     * input format. */
    else if( dateLen < SIGV4_EXPECTED_DATE_LEN + 1 )
    {
        LogError( ( "Parameter check failed: dateLen must be at least %u.",
                    SIGV4_EXPECTED_DATE_LEN + 1 ) );
    }

    /* Check that the output buffer provided is large enough for the formatted
     * string. */
    else if( dateISO8601Len < SIV4_ISO_STRING_LEN + 1 )
    {
        LogError( ( "Parameter check failed: dateISO8601Len must be at least %u.",
                    SIV4_ISO_STRING_LEN + 1 ) );
    }
    else
    {
        memset( &dateInfo, 0, sizeof( struct tm ) );

        /* Parse pDate according to the input's expected string format, and
         * populate the date struct with its components.  */
        if( sscanf( pDate, "%4d-%2d-%2dT%2d:%2d:%2dZ",
                    &dateInfo.tm_year,
                    &dateInfo.tm_mon,
                    &dateInfo.tm_mday,
                    &dateInfo.tm_hour,
                    &dateInfo.tm_min,
                    &dateInfo.tm_sec ) != 6 )
        {
            LogError( ( "sscanf() failed to parse the date string using the format expected." ) );
            returnStatus = SigV4ISOFormattingError;
        }
        else
        {
            /* Standardize month and year values for struct tm's specifications:
             *  - tm_mon = "months from January" (0-11)
             *  - tm_year = "years since 1900" */
            dateInfo.tm_mon--;
            dateInfo.tm_year -= 1900;

            /* Construct ISO 8601 string using members of populated date struct. */
            lenFormatted = strftime( pDateISO8601, SIV4_ISO_STRING_LEN + 1, "%Y%m%dT%H%M%SZ", &dateInfo );

            if( lenFormatted != SIV4_ISO_STRING_LEN )
            {
                LogError( ( "Formatted string is not of expected length %u.",
                            SIV4_ISO_STRING_LEN ) );
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
