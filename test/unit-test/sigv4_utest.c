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

#include <string.h>

#include "unity.h"

/* Include paths for public enums, structures, and macros. */
#include "sigv4.h"

/* The number of invalid date inputs tested in
 * test_SigV4_AwsIotDateToIso8601_Formatting_Error() */
#define SIGV4_TEST_INVALID_DATE_COUNT    22U

/* File-scoped global variables */
static char pTestBufferValid[ SIGV4_ISO_STRING_LEN ] = { 0 };

/* ============================ HELPER FUNCTIONS ============================ */

/**
 * @brief Format a date input with SigV4_AwsIotDateToIso8601(), and verify the
 * output against the expected result, if no errors occurred.
 */
void formatAndVerifyInputDate( const char * pInputDate,
                               SigV4Status_t expectedStatus,
                               const char * pExpectedOutputDate )
{
    TEST_ASSERT_NOT_NULL( pInputDate );

    SigV4Status_t returnVal = SigV4_AwsIotDateToIso8601( pInputDate,
                                                         strlen( pInputDate ),
                                                         pTestBufferValid,
                                                         SIGV4_ISO_STRING_LEN );
    TEST_ASSERT_EQUAL( expectedStatus, returnVal );

    if( returnVal == SigV4Success )
    {
        TEST_ASSERT_NOT_NULL( pExpectedOutputDate );
        TEST_ASSERT_EQUAL_STRING_LEN( pExpectedOutputDate,
                                      pTestBufferValid,
                                      SIGV4_ISO_STRING_LEN );
    }

    tearDown();
}

/* ============================ UNITY FIXTURES ============================== */

/* Called before each test method. */
void setUp()
{
}

/* Called after each test method. */
void tearDown()
{
    memset( &pTestBufferValid, 0, sizeof( pTestBufferValid ) );
}

/* Called at the beginning of the whole suite. */
void suiteSetUp()
{
}

/* Called at the end of the whole suite. */
int suiteTearDown( int numFailures )
{
    return numFailures;
}

/* ==================== Testing SigV4_AwsIotDateToIso8601 =================== */

/**
 * @brief Test happy path with zero-initialized and adequately sized input and
 * output buffers.
 */
void test_SigV4_AwsIotDateToIso8601_Happy_Path()
{
    /* Test unformatted inputs against their final expected values, in both RFC
     * 3339 and 5322 formats. */
    /* Valid non-leap year date. */
    formatAndVerifyInputDate( "2018-01-18T09:18:06Z",
                              SigV4Success,
                              "20180118T091806Z" );

    formatAndVerifyInputDate( "Wed, 18 Jan 2018 09:18:06 GMT",
                              SigV4Success,
                              "20180118T091806Z" );

    /* Valid leap year date (not divisible by 400). */
    formatAndVerifyInputDate( "2004-02-29T11:04:59Z",
                              SigV4Success,
                              "20040229T110459Z" );

    formatAndVerifyInputDate( "Sun, 29 Feb 2004 11:04:59 GMT",
                              SigV4Success,
                              "20040229T110459Z" );

    /* Valid leap year date (divisible by 400, a property of leap years). */
    formatAndVerifyInputDate( "2000-02-29T11:04:59Z",
                              SigV4Success,
                              "20000229T110459Z" );

    formatAndVerifyInputDate( "Tue, 29 Feb 2000 11:04:59 GMT",
                              SigV4Success,
                              "20000229T110459Z" );
}

/**
 * @brief Test NULL and invalid parameters.
 */
void test_SigV4_AwsIotDateToIso8601_Invalid_Params()
{
    /* Output buffer of insufficient length. */
    char testBufferShort[ SIGV4_ISO_STRING_LEN - 1U ] = { 0 };

    /* Test pDate == NULL. */
    SigV4Status_t returnVal = SigV4_AwsIotDateToIso8601( NULL,
                                                         SIGV4_EXPECTED_LEN_RFC_3339,
                                                         pTestBufferValid,
                                                         SIGV4_ISO_STRING_LEN );

    TEST_ASSERT_EQUAL( SigV4InvalidParameter, returnVal );
    tearDown();

    /* Test pDateISO8601 == NULL. */
    returnVal = SigV4_AwsIotDateToIso8601( "2018-01-18T09:18:06Z",
                                           SIGV4_EXPECTED_LEN_RFC_3339,
                                           NULL,
                                           SIGV4_ISO_STRING_LEN );
    TEST_ASSERT_EQUAL( SigV4InvalidParameter, returnVal );

    /* Test dateISO8601Len < SIGV4_ISO_STRING_LEN. */
    returnVal = SigV4_AwsIotDateToIso8601( "Wed, 18 Jan 2018 09:18:06 GMT",
                                           SIGV4_EXPECTED_LEN_RFC_5322,
                                           testBufferShort,
                                           SIGV4_ISO_STRING_LEN - 1U );
    TEST_ASSERT_EQUAL( SigV4InvalidParameter, returnVal );

    /* There are no 'expected output values' for invalid parameters, as
     * SigV4_AwsIotDateToIso8601() will return with an error prior to any
     * further execution. */
    /* dateLen < SIGV4_EXPECTED_LEN_RFC_3339. */
    formatAndVerifyInputDate( "2018-01T09:18Z",
                              SigV4InvalidParameter,
                              NULL );

    /* dateLen > SIGV4_EXPECTED_LEN_RFC_3339 */
    formatAndVerifyInputDate( "2018-01-18T09:18:06Z00:00",
                              SigV4InvalidParameter,
                              NULL );

    /* dateLen < SIGV4_EXPECTED_LEN_RFC_5322 */
    formatAndVerifyInputDate( "Wed, 18 Jan 2018 09:18:06",
                              SigV4InvalidParameter,
                              NULL );

    /* dateLen > SIGV4_EXPECTED_LEN_RFC_5322 */
    formatAndVerifyInputDate( "Wed, 18 Jan 2018 09:18:06 GMT+8",
                              SigV4InvalidParameter,
                              NULL );
}

/**
 * @brief Test valid input parameters representing invalid dates.
 */
void test_SigV4_AwsIotDateToIso8601_Formatting_Error()
{
    size_t index = 0U;

    /* Test parameters of acceptable size and format, with flawed date
     * representations, in both RFC3339 and RFC5322 form. */
    const char * pInvalidDateInputs[] =
    {
        "1776-01-18T09:18:06Z", "Thu, 18 Jan 1776 09:18:06 GMT", /* year < YEAR_MIN */
        "2018-00-18T03:21:09Z", "Wed, 18 Air 2018 09:18:06 GMT", /* month < 1 */
        "2018-15-18T03:21:09Z", "Wed, 18 a01 2018 09:18:06 GMT", /* month > 12 */
        "2018-01-00T03:21:09Z", "Mon, 31 Feb 2018 09:18:06 GMT", /* day < 1 */
        "1973-09-31T23:59:59Z", "Mon, 31 Sep 1973 23:59:59 GMT", /* day > days in month (28-31) */
        "1998-02-29T03:21:09Z", "Thu, 29 Feb 1900 09:18:06 GMT", /* Leap day in a non-leap year. */
        "2018-01-18T25:18:06Z", "Wed, 18 Jan 2018 61:18:06 GMT", /* hour > 23 */
        "1800-02-28T03:61:09Z", "Wed, 18 Jan 2018 09:99:06 GMT", /* minute > 59 */
        "1800-01-29T03:21:70Z", "Wed, 18 Jan 2018 09:18:75 GMT", /* seconds > 60 */
        "2018-01-18X09:18:06Z", "Wed. 31 Apr 2018T09:18:06 GMT", /* Unexpected character 'X'. */
        "2018-01-1!X09:18:06Z", "Wed. 31 Apr 2018T0A:18:06 GMT"  /* Unexpected non-digit found in date element. */
    };

    for( index = 0U; index < SIGV4_TEST_INVALID_DATE_COUNT - 1; index += 2 )
    {
        /* Test equivalent RFC 3339 and RFC 5322 representations of an invalid
         * date, and ensure that a formatting error code is received. */
        formatAndVerifyInputDate( pInvalidDateInputs[ index ], SigV4ISOFormattingError, NULL );
        formatAndVerifyInputDate( pInvalidDateInputs[ index + 1 ], SigV4ISOFormattingError, NULL );
    }
}
