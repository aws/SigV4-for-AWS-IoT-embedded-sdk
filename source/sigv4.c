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
#include <time.h>

#include "sigv4.h"

/*-----------------------------------------------------------*/

SigV4Status_t SigV4_AwsIotDateToIso8601( const char * pDate,
                                         size_t dateLen,
                                         char pDateISO8601[ 17 ],
                                         size_t dateISO8601Len )
{
    SigV4Status_t returnStatus = SigV4InvalidParameter;
    size_t lenFormatted = 0U;
    char * pLastChar = NULL;
    struct tm dateInfo;

    /* Check for NULL parameters. */
    if( pDate == NULL )
    {
        LogError( ( "Parameter check failed: pDate is NULL." ) );
    }
    /* Check validity of the date header size provided. */
    else if( dateLen == 0U )
    {
        LogError( ( "Parameter check failed: dateLen must be greater than 0." ) );
    }
    else if( pDateISO8601 == NULL )
    {
        LogError( ( "Parameter check failed: pDateISO8601 is NULL." ) );
    }
    /* Check that the buffer provided is large enough for the formatted output
     * string. */
    else if( dateISO8601Len < ISO_BUFFER_MIN_LEN )
    {
        LogError( ( "Parameter check failed: dateISO8601Len must be at least %u.",
                    ISO_BUFFER_MIN_LEN ) );
    }
    else
    {
        memset( &dateInfo, 0, sizeof( struct tm ) );

        /* Parse pDate according to the input's expected string format, and
         * populate the date struct with its components.  */
        pLastChar = strptime( pDate, "%Y-%m-%dT%H:%M:%SZ", &dateInfo );

        if( pLastChar == NULL )
        {
            LogError( ( "Error matching input to ISO8601 format string." ) );
        }
        else if( pLastChar[ 0 ] != '\0' )
        {
            /* The expected pattern was found, but additional characters remain
             * unparsed in the input string. */
            LogWarn( ( "Input contained more characters than expected." ) );
        }
        else
            /* Construct ISO 8601 string using members of populated date struct. */
            lenFormatted = strftime( pDateISO8601, ISO_BUFFER_MIN_LEN, "%Y%m%dT%H%M%SZ", &dateInfo );

            if( lenFormatted != ISO_BUFFER_MIN_LEN - 1 )
            {
                LogError( ( "Formatted string is not of expected length 16." ) );
            }
            else
            {
                returnStatus = SigV4Success;
            }
        }
    }

    return returnStatus;
}
