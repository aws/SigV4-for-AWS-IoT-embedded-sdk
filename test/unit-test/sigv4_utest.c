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

#include <string.h>

#include "unity.h"

/* Include paths for public enums, structures, and macros. */
#include "sigv4.h"

/* Private includes for internal macros. */
#include "sigv4_internal.h"

/* Number of input strings provided to each test case. */
#define SIGV4_TEST_VALID_INPUT_COUNT          3U
#define SIGV4_TEST_INVALID_PARAMETER_COUNT    4U
#define SIGV4_TEST_INVALID_DATE_COUNT         10U

/* The formatted ISO 8601 dates corresponding to the valid inputs below. */
static const char * pExpectedOutputs[ SIGV4_TEST_VALID_INPUT_COUNT ] =
{
    "20180118T091806Z", /* Valid non-leap year date. */
    "20040229T110459Z", /* Valid leap year (not divisible by 400). */
    "20000229T110459Z"  /* Valid leap year (divisible by 400, a leap year property). */
};

/* Test valid RFC 3339 parameters against expected outputs. */
static const char * pRFC3339ValidInputs[ SIGV4_TEST_VALID_INPUT_COUNT ] =
{
    "2018-01-18T09:18:06Z", /* Non-leap year date. */
    "2004-02-29T11:04:59Z", /* Leap year date (not divisible by 400). */
    "2000-02-29T11:04:59Z"  /* Leap year date (divisible by 400). */
};

/* Test valid RFC 5322 parameters against expected outputs. */
static const char * pRFC5322ValidInputs[ SIGV4_TEST_VALID_INPUT_COUNT ] =
{
    "Wed, 18 Jan 2018 09:18:06 GMT", /* Non-leap year date. */
    "Sun, 29 Feb 2004 11:04:59 GMT", /* Leap year date (not divisible by 400). */
    "Tue, 29 Feb 2000 11:04:59 GMT"  /* Leap year date (divisible by 400). */
};

/* Test invalid parameters of unexpected size. */
static const char * pInvalidParameters[ SIGV4_TEST_INVALID_PARAMETER_COUNT ] =
{
    "2018-01T09:18Z",                 /* dateLen < SIGV4_EXPECTED_LEN_RFC_3339 */
    "2018-01-18T09:18:06Z00:00",      /* dateLen > SIGV4_EXPECTED_LEN_RFC_3339 */
    "Wed, 18 Jan 2018 09:18:06",      /* dateLen < SIGV4_EXPECTED_LEN_RFC_5322 */
    "Wed, 18 Jan 2018 09:18:06 GMT+8" /* dateLen > SIGV4_EXPECTED_LEN_RFC_5322 */
};

/* Test valid RFC 3339 parameters representing invalid dates. */
static const char * pRFC3339InvalidRepresentation[ SIGV4_TEST_INVALID_DATE_COUNT ] =
{
    "1776-01-18T09:18:06Z", /* year < YEAR_MIN */
    "2018-00-18T03:21:09Z", /* month < 1 */
    "2018-15-18T03:21:09Z", /* month > 12 */
    "2018-01-00T03:21:09Z", /* day < 1 */
    "1998-02-29T03:21:09Z", /* Leap day in a non-leap year. */
    "2018-01-18T25:18:06Z", /* hour > 23 */
    "1800-02-28T03:61:09Z", /* minute > 59 */
    "1800-01-29T03:21:70Z", /* seconds > 60 */
    "2018-01-18X09:18:06Z", /* Unexpected character 'X'. */
    "2018-01-1!X09:18:06Z"  /* Unexpected non-digit found in date element. */
};

/* Test valid RFC 5322 parameters representing invalid dates. */
static const char * pRFC5322InvalidRepresentation[ SIGV4_TEST_INVALID_DATE_COUNT ] =
{
    "Thu, 18 Jan 1776 09:18:06 GMT", /* year < YEAR_MIN */
    "Wed, 18 Air 2018 09:18:06 GMT", /* Month label not recognized. */
    "Wed, 18 a01 2018 09:18:06 GMT", /* Unexpected characters in month label. */
    "Mon, 31 Feb 2018 09:18:06 GMT", /* day > monthsPerDay */
    "Thu, 29 Feb 1900 09:18:06 GMT", /* Leap day in a non-leap year. */
    "Wed, 18 Jan 2018 61:18:06 GMT", /* hour > 23 */
    "Wed, 18 Jan 2018 09:99:06 GMT", /* minute > 59 */
    "Wed, 18 Jan 2018 09:18:75 GMT", /* seconds > 60 */
    "Wed. 31 Apr 2018T09:18:06 GMT", /* Unexpected characters '.' and 'T'. */
    "Wed. 31 Apr 2018T0A:18:06 GMT"  /* Unexpected non-digit found in date element. */
};

/* File-scoped global variables */
static SigV4Status_t returnVal = SigV4Success;
static char pTestBufferValid[ SIGV4_ISO_STRING_LEN ] = { 0 };
static size_t globalIndex = 0U;

/* ============================ UNITY FIXTURES ============================== */
/* Called before each test method. */
void setUp()
{
}

/* Called after each test method. */
void tearDown()
{
    returnVal = SigV4Success;
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
    for( globalIndex = 0U; globalIndex < SIGV4_TEST_VALID_INPUT_COUNT; globalIndex++ )
    {
        returnVal = SigV4_AwsIotDateToIso8601( pRFC3339ValidInputs[ globalIndex ],
                                               strlen( pRFC3339ValidInputs[ globalIndex ] ),
                                               pTestBufferValid,
                                               SIGV4_ISO_STRING_LEN );
        TEST_ASSERT_EQUAL( SigV4Success, returnVal );
        TEST_ASSERT_EQUAL_STRING_LEN( pExpectedOutputs[ globalIndex ], pTestBufferValid, SIGV4_ISO_STRING_LEN );

        tearDown();

        returnVal = SigV4_AwsIotDateToIso8601( pRFC5322ValidInputs[ globalIndex ],
                                               strlen( pRFC5322ValidInputs[ globalIndex ] ),
                                               pTestBufferValid,
                                               SIGV4_ISO_STRING_LEN );
        TEST_ASSERT_EQUAL( SigV4Success, returnVal );
        TEST_ASSERT_EQUAL_STRING_LEN( pExpectedOutputs[ globalIndex ], pTestBufferValid, SIGV4_ISO_STRING_LEN );
    }
}

/**
 * @brief Test NULL and invalid parameters, following order of else-if blocks in
 * SigV4_AwsIotDateToIso8601().
 */
void test_SigV4_AwsIotDateToIso8601_Invalid_Params()
{
    /* Output date buffer of insufficient length. */
    char testBufferShort[ SIGV4_ISO_STRING_LEN - 1U ] = { 0 };

    /* Test pDate == NULL. */
    returnVal = SigV4_AwsIotDateToIso8601( NULL,
                                           strlen( pRFC3339ValidInputs[ 0 ] ),
                                           pTestBufferValid,
                                           SIGV4_ISO_STRING_LEN );
    TEST_ASSERT_EQUAL( SigV4InvalidParameter, returnVal );

    /* Test pDateISO8601 == NULL. */
    returnVal = SigV4_AwsIotDateToIso8601( pRFC5322ValidInputs[ 0 ],
                                           strlen( pRFC5322ValidInputs[ 0 ] ),
                                           NULL,
                                           SIGV4_ISO_STRING_LEN );
    TEST_ASSERT_EQUAL( SigV4InvalidParameter, returnVal );

    /* Test invalid pDate buffers (i.e. dateLen not equal to either
     * SIGV4_EXPECTED_LEN_RFC_3339 or SIGV4_EXPECTED_LEN_RFC_5322). */
    for( globalIndex = 0U; globalIndex < SIGV4_TEST_INVALID_PARAMETER_COUNT; globalIndex++ )
    {
        returnVal = SigV4_AwsIotDateToIso8601( pInvalidParameters[ globalIndex ],
                                               strlen( pInvalidParameters[ globalIndex ] ),
                                               pTestBufferValid,
                                               SIGV4_ISO_STRING_LEN );
        TEST_ASSERT_EQUAL( SigV4InvalidParameter, returnVal );
    }

    /* Test dateISO8601Len < SIGV4_ISO_STRING_LEN. */
    returnVal = SigV4_AwsIotDateToIso8601( pRFC3339ValidInputs[ 0 ],
                                           strlen( pRFC3339ValidInputs[ 0 ] ),
                                           testBufferShort,
                                           SIGV4_ISO_STRING_LEN - 1U );
    TEST_ASSERT_EQUAL( SigV4InvalidParameter, returnVal );
}

/**
 * @brief Test parsed inputs representing invalid dates.
 */
void test_SigV4_AwsIotDateToIso8601_Formatting_Error()
{
    for( globalIndex = 0U; globalIndex < SIGV4_TEST_INVALID_DATE_COUNT; globalIndex++ )
    {
        returnVal = SigV4_AwsIotDateToIso8601( pRFC3339InvalidRepresentation[ globalIndex ],
                                               strlen( pRFC3339InvalidRepresentation[ globalIndex ] ),
                                               pTestBufferValid,
                                               SIGV4_ISO_STRING_LEN );
        TEST_ASSERT_EQUAL( SigV4ISOFormattingError, returnVal );

        tearDown();

        returnVal = SigV4_AwsIotDateToIso8601( pRFC5322InvalidRepresentation[ globalIndex ],
                                               strlen( pRFC5322InvalidRepresentation[ globalIndex ] ),
                                               pTestBufferValid,
                                               SIGV4_ISO_STRING_LEN );
        TEST_ASSERT_EQUAL( SigV4ISOFormattingError, returnVal );
    }
}
