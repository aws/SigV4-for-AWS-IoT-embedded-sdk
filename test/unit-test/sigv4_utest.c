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
#include "sigv4_internal.h"

/* Size of valid output date buffer. */
#define SIGV4_TEST_BUFFER_SIZE          ( 17 )

/* Size of larger-than-required output date buffer. */
#define SIGV4_TEST_BUFFER_SIZE_LONG     ( 30 )

/* Size of an output date buffer of insufficient length. */
#define SIGV4_TEST_BUFFER_SIZE_SHORT    ( 16 )

/* Test valid date inputs. */
static const char pTestDateExpected[] = "Wed, 18 Jan 2018 09:18:06 GMT"; /*"2018-01-18T09:18:06Z"; */
static const char pTestDateLong[] = "2018-01-18T09:18:06Z00:00";
static const char pOutputExpected[] = "20180118T091806Z";

/* Test invalid date inputs. */
static const char pTestDateShort[] = "2018-01T09:18Z";
static const char pTestParsingFailure[] = "2018-01-18X09:18:06Z";
static const char pTestFormatFailure[] = " 018-01-18T09:18:06Z";

/* File-scoped global variables */
static SigV4Status_t retCode = SigV4Success;
static char testBufferValid[ SIGV4_TEST_BUFFER_SIZE ] = { 0 };
static char testBufferLong[ SIGV4_TEST_BUFFER_SIZE_LONG ] = { 0 };
static char testBufferShort[ SIGV4_TEST_BUFFER_SIZE_SHORT ] = { 0 };


/* ============================ UNITY FIXTURES ============================== */
/* Called before each test method. */
void setUp()
{
}

/* Called after each test method. */
void tearDown()
{
    retCode = SigV4Success;
    memset( &testBufferValid, 0, sizeof( testBufferValid ) );
    memset( &testBufferLong, 0, sizeof( testBufferLong ) );
    memset( &testBufferShort, 0, sizeof( testBufferShort ) );
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
 * @brief Test the happy path with zero-initialized and adequately sized output
 * buffers.
 */
void test_SigV4_AwsIotDateToIso8601_Happy_Path()
{
    SigV4Status_t returnVal = SigV4Success;

    returnVal = SigV4_AwsIotDateToIso8601( pTestDateExpected, SIGV4_EXPECTED_LEN_RFC_5322, testBufferValid, SIGV4_TEST_BUFFER_SIZE );

    TEST_ASSERT_EQUAL( SigV4Success, returnVal );
    TEST_ASSERT_EQUAL_STRING( pOutputExpected, testBufferValid );

    /* returnVal = SigV4_AwsIotDateToIso8601( pTestDateLong, sizeof( pTestDateLong ), testBufferValid, SIGV4_TEST_BUFFER_SIZE ); */

    /* TEST_ASSERT_EQUAL( SigV4Success, returnVal ); */
    /* TEST_ASSERT_EQUAL_STRING( pOutputExpected, testBufferValid ); */
}

/**
 * @brief Test NULL and invalid parameters, following order of else-if blocks in
 * SigV4_AwsIotDateToIso8601().
 */
void test_SigV4_AwsIotDateToIso8601_Invalid_Params()
{
    SigV4Status_t returnVal = SigV4Success;

    /* Test pDate == NULL */
    returnVal = SigV4_AwsIotDateToIso8601( NULL, SIGV4_EXPECTED_LEN_RFC_3339, testBufferValid, SIGV4_TEST_BUFFER_SIZE );
    TEST_ASSERT_EQUAL( SigV4InvalidParameter, returnVal );

    /* Test pDateISO8601 == NULL */
    returnVal = SigV4_AwsIotDateToIso8601( pTestDateExpected, SIGV4_EXPECTED_LEN_RFC_5322, NULL, SIGV4_TEST_BUFFER_SIZE );
    TEST_ASSERT_EQUAL( SigV4InvalidParameter, returnVal );

    /* Test dateLen < SIGV4_EXPECTED_LEN_RFC_3339 */
    returnVal = SigV4_AwsIotDateToIso8601( pTestDateShort, sizeof( pTestDateShort ), testBufferValid, SIGV4_TEST_BUFFER_SIZE );
    TEST_ASSERT_EQUAL( SigV4InvalidParameter, returnVal );

    /* Test dateISO8601Len < SIGV4_ISO_STRING_LEN + 1 */
    returnVal = SigV4_AwsIotDateToIso8601( pTestDateExpected, sizeof( pTestDateExpected ), testBufferShort, SIGV4_TEST_BUFFER_SIZE_SHORT );
    TEST_ASSERT_EQUAL( SigV4InvalidParameter, returnVal );
}

/**
 * @brief Test invalid input date formats.
 */
void test_SigV4_AwsIotDateToIso8601_Formatting_Error()
{
    SigV4Status_t returnVal = SigV4Success;

    /* sscanf() failed to match input date to expected format string. */
    returnVal = SigV4_AwsIotDateToIso8601( pTestParsingFailure, sizeof( pTestParsingFailure ) - 1U, testBufferValid, SIGV4_TEST_BUFFER_SIZE );
    TEST_ASSERT_EQUAL( SigV4ISOFormattingError, returnVal );

    /* sscanf() parsed the input successfully (by trimming extraneous
     * spaces/zeros), feeding an invalid input to strftime(). */
    returnVal = SigV4_AwsIotDateToIso8601( pTestFormatFailure, sizeof( pTestFormatFailure ) - 1U, testBufferValid, SIGV4_TEST_BUFFER_SIZE );
    TEST_ASSERT_EQUAL( SigV4ISOFormattingError, returnVal );
}
