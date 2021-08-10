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
#include <openssl/sha.h>

#include "unity.h"

/* Include paths for public enums, structures, and macros. */
#include "sigv4.h"
/* We include the internal SigV4 macros so that they don't have to be redefined for these tests. */
#include "sigv4_internal.h"

#define STR_LIT_LEN( LIT )    ( sizeof( LIT ) - 1U )

/* The number of invalid date inputs tested in
 * test_SigV4_AwsIotDateToIso8601_Formatting_Error() */
#define SIGV4_TEST_INVALID_DATE_COUNT        24U

#define AUTH_BUF_LENGTH                      SIGV4_HASH_MAX_BLOCK_LENGTH + SIGV4_HASH_MAX_DIGEST_LENGTH
#define PATH                                 "/hi | world"
/* Iterator must not read beyond the null-terminator. */
#define NULL_TERMINATED_PATH                 "/pa\0th"
#define NULL_TERMINATED_PATH_LEN             ( sizeof( NULL_TERMINATED_PATH ) - 1U )
/* An equal in the query string value must be double-encoded. */
#define QUERY_STRING_VALUE_HAS_EQUALS        "quantum==&->sha256=dead&maybe&&"
/* A query string with paramater count exceeding SIGV4_MAX_HTTP_HEADER_COUNT=5. */
#define QUERY_STRING_GT_MAX_PARAMS           "params&allowed&to&have&no&values"

#define QUERY                                "Action=ListUsers&Version=2010-05-08"
#define QUERY_LENGTH                         ( sizeof( QUERY ) - 1U )
#define ACCESS_KEY_ID                        "AKIAIOSFODNN7EXAMPLE"
#define SECRET_KEY                           "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
#define SECRET_KEY_LEN                       ( sizeof( SECRET_KEY ) - 1U )
#define SECRET_KEY_LONGER_THAN_DIGEST        "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEYwJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEYwJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEYwJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
#define SECRET_KEY_LONGER_THAN_DIGEST_LEN    ( sizeof( SECRET_KEY_LONGER_THAN_DIGEST ) - 1U )
#define DATE                                 "20150830T123600Z"
#define REGION                               "us-east-1"
#define SERVICE                              "iam"
#define HEADERS                              "Host: iam.amazonaws.com\r\nContent-Type: application/x-www-form-urlencoded; charset=utf-8\r\nX-Amz-Date: "DATE "\r\n\r\n"
#define PRECANON_HEADER                      "content-type:application/json;host:iam.amazonaws.com"
#define HEADERS_LENGTH                       ( sizeof( HEADERS ) - 1U )
#define SECURITY_TOKEN                       "security-token"
#define SECURITY_TOKEN_LENGTH                ( sizeof( SECURITY_TOKEN ) - 1U )
#define EXPIRATION                           "20160930T123600Z"
#define EXPIRATION_LENGTH                    ( sizeof( EXPIRATION ) - 1U )

/* Insufficient memory parameters for SIGV4_PROCESSING_BUFFER_LENGTH=350. In the comments below,
 * + means concatenation, OOM means "Out of Memory", LF means newline character */

/* HTTP method + URI-encoded variant of this string must be greater than SIGV4_PROCESSING_BUFFER_LENGTH. */
#define PATH_FIRST_ENCODE_OOM                                                           \
    "/path-to-victory-will-soon-come-to-a-close-and-then-we-can-finally-eat-our-errors" \
    "-even-though-this-is-not-a-good-practice-at-all-so-obviously-this-is-just-a-joke-" \
    "so-why-are-you-still-reading-this-i-mean-im-crazy-enough-to-type-this-very-"       \
    "long-string-instead-of-using-a-lorem-ipsum-website-maybe-i-should-be-a-comedian-"  \
    "instead-be-a-programmer-really"
/* HTTP method + URI-encoded variant of this string + \n must be greater than SIGV4_PROCESSING_BUFFER_LENGTH. */
#define PATH_FIRST_ENCODE_AND_LF_OOM                                                    \
    "/path-to-victory-will-soon-come-to-a-close-and-then-we-can-finally-eat-our-errors" \
    "-even-though-this-is-not-a-good-practice-at-all-so-obviously-this-is-just-a-joke-" \
    "so-why-are-you-still-reading-this-i-mean-im-crazy-enough-to-type-this-very-"       \
    "long-string-instead-of-using-a-lorem-ipsum-website-maybe-i-should-be-a-comedian-"  \
    "instead-be-a-programmer-reall"
/* HTTP method + this URI-encoded variant of this string + double-encoded variant must be greater than SIGV4_PROCESSING_BUFFER_LENGTH. */
#define PATH_SECOND_ENCODE_OOM    "/path-to-victory-will-soon-come-to-a-close-and-then-we-can-finally-eat-our-errors-even-though-this-is-not-a-good-practice-at-all-so-obviously-this-is-just-a-joke-so-why-are-you-still-reading-this-i-mean-im-crazy-enough-to-type-this-very-long-string-instead-of-using-a-lorem-ipsum-website-maybe-i-should-be-a-comedian-instead"

/* Encoding query string field in canonicalized query string causes OOM. */
#define QUERY_ENCODE_FIELD_OOM                                                          \
    "path-to-victory-will-soon-come-to-a-close-and-then-we-can-finally-eat-our-errors"  \
    "-even-though-this-is-not-a-good-practice-at-all-so-obviously-this-is-just-a-joke-" \
    "so-why-are-you-still-&m=reading-this-i-mean-im-crazy-enough-to-type-this-very-"    \
    "long-string-instead-of-using-a-lorem-ipsum-website-maybe-i-should-be-a-comedian-"  \
    "instead-be-a-programmer-reall&y=3"

/* '=' before query string value in canonicalized query string causes OOM. */
#define QUERY_EQUAL_BEFORE_VALUE_OOM                                                      \
    "VwngXGfGGHUJcXAyjrfZapvWrAizcaCSSzWFgWVajgcHvPjiypSRThwgvGicnakSutzyFUNpFPXTtGp"     \
    "XNNdzbbpmapMikCuizEKHXLqWWXwHbLhDRajbw"                                              \
    "mlkzxncvlknlkanlkqwlerknlasdflkzxcnvklnlksqwerasdfklqwenrklnfsad"                    \
    "reading-this-i-mean-im-crazy-enough-to-type-this-very-qCdrPnpyimHMDLPcQwxhNGYYTyyUG" \
    "cApPMQygPCRMeVHpxdrFycVuEGZaFtGvdTXgMnPbzWvGNhLkecRqFGBgza=3"

/* '&' before next query string field in canonicalized query string causes OOM. */
#define QUERY_AMPERSAND_BEFORE_FIELD_OOM                                                  \
    "VwngXGfGGHUJcXAyjrfZapvWrAizcaCSSzWFgWVajgcHvPjiypSRThwgvGicnakSutzyFUNpFPXTtGp"     \
    "XNNdzbbpmapMikCuizEKHXLqWWXwHbLhDRajbw"                                              \
    "mlkzxncvlknlkanlkqwlerknlasdflkzxcnvklnlksqwerasdfklqwenrklnfsad"                    \
    "reading-this-i-mean-im-crazy-enough-to-type-this-very-qCdrPnpyimHMDLPcQwxhNGYYTyyUG" \
    "cApPMQygPCRMeVHpxdrFycVuEGZaFtGvdTXgMnPbzWvGNhLkecRqFGBg=3&a"

/* Encoding query string value in canonicalized query string causes OOM. */
#define QUERY_ENCODE_VALUE_OOM                                                                       \
    "hello-world&y=path-to-victory-will-soon-come-to-a-close-and-then-we-can-finally-eat-our-errors" \
    "-even-though-this-is-not-a-good-practice-at-all-so-obviously-this-is-just-a-joke-"              \
    "so-why-are-you-still-&m=reading-this-i-mean-im-crazy-enough-to-type-this-very-"                 \
    "long-string-instead-of-using-a-lorem-ipsum-website-maybe-i-should-be-a-comedian-"               \
    "instead-be-a-programmer-reall"

/* Precanonicalized query string causes OOM. */
#define PRECANON_QUERY_TOO_LONG                                                                                              \
    "wnqjNXBkZXXQvpwaHryRkLQuCQnMqQYAaXLFAUQGCnpbfiBUHkJKWgvGbUGrEcjuveUijcfxvFvUXKcedDbHwSdWqTTeLRwnVZapMEKrYprSdYgVGzSUG=" \
    "wnqjNXBkZXXQvpwaHryRkLQuCQnMqQYAaXLFAUQGCnpbfiBUHkJKWgvGbUGrEcjuveUijcfxvFvUXKcedDbHwSdWqTTeLRwnVZapMEKrYprSdYgVGzSUG&" \
    "wnqjNXBkZXXQvpwaHryRkLQuCQnMqQYAaXLFAUQGCnpb=fiBUHkJKWgvGbUGrEcjuveUijcfxvFvUXKcedDbHwSdWqTTeLRwnVZapMEKrYprSdYgVGzSUG" \

/* File-scoped global variables */
static char pTestBufferValid[ SIGV4_ISO_STRING_LEN ] = { 0 };

/* Input parameters. */
static SigV4Parameters_t params;
static SigV4HttpParameters_t httpParams;
static SigV4CryptoInterface_t cryptoInterface;
static SigV4Credentials_t creds;
static SHA256_CTX sha256;

static char authBuf[ AUTH_BUF_LENGTH ];
static size_t authBufLen = AUTH_BUF_LENGTH;
static char * signature = NULL;
static size_t signatureLen;

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

/*==================== OpenSSL Based implementation of Crypto Interface ===================== */

static int32_t valid_sha256_init( void * pHashContext )
{
    if( SHA256_Init( ( SHA256_CTX * ) pHashContext ) == 1 )
    {
        return 0;
    }

    return -1;
}

static int32_t valid_sha256_update( void * pHashContext,
                                    const char * pInput,
                                    size_t inputLen )
{
    if( SHA256_Update( ( SHA256_CTX * ) pHashContext, pInput, inputLen ) )
    {
        return 0;
    }

    return -1;
}

static int32_t valid_sha256_final( void * pHashContext,
                                   char * pOutput,
                                   size_t outputLen )
{
    if( SHA256_Final( ( uint8_t * ) pOutput, ( SHA256_CTX * ) pHashContext ) )
    {
        return 0;
    }

    return -1;
}

/*==================== Echo Implementation of Crypto Interface ===================== */

static hashEchoBuffer[ SIGV4_HASH_MAX_BLOCK_LENGTH ];
static size_t hashInputLen;

/* These hash functions simply take the input and write it back to the output.
 * The purpose of which is make it possible to write tests without having to
 * know the computed hash of the string to sign. */
static int32_t echo_hash_init( void * pHashContext )
{
    return 0;
}

static int32_t echo_hash_update( void * pHashContext,
                                 const char * pInput,
                                 size_t inputLen )
{
    hashInputLen = inputLen;
    ( void ) memcpy( hashEchoBuffer, pInput, inputLen );
}

static int32_t echo_hash_final( void * pHashContext,
                                char * pOutput,
                                size_t outputLen )
{
    ( void ) memcpy( pOutput, hashEchoBuffer, hashInputLen );
}

/*==================== Failable Implementation of Crypto Interface ===================== */

/*
 #define FAIL_HASH_INIT 1U,
 #define FAIL_HASH_UPDATE 2U
 #define FAIL_HASH_FINAL 3U
 *
 * static size_t hashToFail;
 */
#define HAPPY_PATH_HASH_ITERATIONS    11U

static size_t initHashCalledCount = 0U, initHashCallToFail = SIZE_MAX;
static size_t updateHashCalledCount = 0U, updateHashCallToFail = SIZE_MAX;
static size_t finalHashCalledCount = 0U, finalHashCallToFail = SIZE_MAX;

static int32_t hash_init_failable( void * pHashContext )
{
    int32_t ret = 0;

    if( initHashCalledCount++ == initHashCallToFail )
    {
        ret = 1;
    }

    return ret;
}

static int32_t hash_update_failable( void * pHashContext,
                                     const char * pInput,
                                     size_t inputLen )
{
    int32_t ret = 0;

    if( updateHashCalledCount++ == updateHashCallToFail )
    {
        ret = 1;
    }

    return ret;
}

static int32_t hash_final_failable( void * pHashContext,
                                    char * pOutput,
                                    size_t outputLen )
{
    int32_t ret = 0;

    if( finalHashCalledCount++ == finalHashCallToFail )
    {
        ret = 1;
    }

    return ret;
}

/*============================ Test Helpers ========================== */

static void resetFailableHashParams()
{
    initHashCalledCount = 0U;
    initHashCallToFail = SIZE_MAX;
    updateHashCalledCount = 0U;
    updateHashCallToFail = SIZE_MAX;
    finalHashCalledCount = 0U;
    finalHashCallToFail = SIZE_MAX;

    params.pCryptoInterface->hashInit = hash_init_failable;
    params.pCryptoInterface->hashUpdate = hash_update_failable;
    params.pCryptoInterface->hashFinal = hash_final_failable;
}

static void resetInputParams()
{
    /* Fill the input parameters with the happy path. */
    memset( &params, 0, sizeof( params ) );
    memset( &httpParams, 0, sizeof( httpParams ) );
    memset( &cryptoInterface, 0, sizeof( cryptoInterface ) );
    memset( &creds, 0, sizeof( creds ) );
    memset( &sha256, 0, sizeof( sha256 ) );
    memset( authBuf, 0, AUTH_BUF_LENGTH );
    authBufLen = AUTH_BUF_LENGTH;
    signature = NULL;
    httpParams.pHttpMethod = "GET";
    httpParams.httpMethodLen = 3;
    httpParams.pPath = PATH;
    httpParams.pathLen = sizeof( PATH ) - 1U;
    httpParams.pQuery = QUERY;
    httpParams.queryLen = QUERY_LENGTH;
    httpParams.flags = 0;
    httpParams.pHeaders = HEADERS;
    httpParams.headersLen = HEADERS_LENGTH;
    httpParams.pPayload = NULL;
    httpParams.payloadLen = 0U;
    params.pHttpParameters = &httpParams;
    creds.pAccessKeyId = ACCESS_KEY_ID;
    creds.accessKeyIdLen = sizeof( ACCESS_KEY_ID ) - 1U;
    creds.pSecretAccessKey = SECRET_KEY;
    creds.secretAccessKeyLen = SECRET_KEY_LEN;
    creds.pSecurityToken = SECURITY_TOKEN;
    creds.securityTokenLen = SECURITY_TOKEN_LENGTH;
    creds.pExpiration = EXPIRATION;
    creds.expirationLen = EXPIRATION_LENGTH;
    params.pAlgorithm = SIGV4_AWS4_HMAC_SHA256;
    params.algorithmLen = SIGV4_AWS4_HMAC_SHA256_LENGTH;
    params.pCredentials = &creds;
    params.pDateIso8601 = DATE;
    params.pRegion = REGION;
    params.regionLen = sizeof( REGION ) - 1U;
    params.pService = SERVICE;
    params.serviceLen = sizeof( SERVICE ) - 1U;
    cryptoInterface.pHashContext = &sha256;
    cryptoInterface.hashInit = valid_sha256_init;
    cryptoInterface.hashUpdate = valid_sha256_update;
    cryptoInterface.hashFinal = valid_sha256_final;
    cryptoInterface.hashBlockLen = SIGV4_HASH_MAX_BLOCK_LENGTH;
    cryptoInterface.hashDigestLen = SIGV4_HASH_MAX_DIGEST_LENGTH;
    params.pCryptoInterface = &cryptoInterface;
}

/* ============================ UNITY FIXTURES ============================== */

/* Called before each test method. */
void setUp()
{
    resetInputParams();
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
        "2018-01-1@X09:18:06Z", "Wed. 31 Apr 2018T0A:18:06 GMT", /* Unexpected non-digit found in date element. */
        "2018-01-1!X09:18:06Z", "Wed. 31 Apr 2018T!9:18:06 GMT"  /* Unexpected non-digit found in date element. */
    };

    for( index = 0U; index < SIGV4_TEST_INVALID_DATE_COUNT - 1; index += 2 )
    {
        /* Test equivalent RFC 3339 and RFC 5322 representations of an invalid
         * date, and ensure that a formatting error code is received. */
        formatAndVerifyInputDate( pInvalidDateInputs[ index ], SigV4ISOFormattingError, NULL );
        formatAndVerifyInputDate( pInvalidDateInputs[ index + 1 ], SigV4ISOFormattingError, NULL );
    }
}

/* ======================= Testing SigV4_GenerateHTTPAuthorization =========================== */
/* TODO - Verify the generated signatures. */
void test_SigV4_GenerateHTTPAuthorization_Happy_Paths()
{
    SigV4Status_t returnStatus;

    returnStatus = SigV4_GenerateHTTPAuthorization( &params, authBuf, &authBufLen, &signature, &signatureLen );
    TEST_ASSERT_EQUAL( SigV4Success, returnStatus );

    /* Attempt to generate the signature with a secret longer than the digest length. This
     * causes the inner-most HMAC key of the signing key to be hashed down. */
    creds.pSecretAccessKey = SECRET_KEY_LONGER_THAN_DIGEST;
    creds.secretAccessKeyLen = SECRET_KEY_LONGER_THAN_DIGEST_LEN;
    returnStatus = SigV4_GenerateHTTPAuthorization( &params, authBuf, &authBufLen, &signature, &signatureLen );
    TEST_ASSERT_EQUAL( SigV4Success, returnStatus );

    /* S3 is the only service in which the URI is only encoded once. */
    params.serviceLen = S3_SERVICE_NAME_LEN;
    params.pService = S3_SERVICE_NAME;
    returnStatus = SigV4_GenerateHTTPAuthorization( &params, authBuf, &authBufLen, &signature, &signatureLen );
    TEST_ASSERT_EQUAL( SigV4Success, returnStatus );

    /* Coverage for the case where the service name has the same length as "s3". */
    params.serviceLen = S3_SERVICE_NAME_LEN;
    params.pService = SERVICE;
    returnStatus = SigV4_GenerateHTTPAuthorization( &params, authBuf, &authBufLen, &signature, &signatureLen );
    TEST_ASSERT_EQUAL( SigV4Success, returnStatus );

    /* Coverage for the null-terminated path. */
    params.pHttpParameters->pPath = NULL_TERMINATED_PATH;
    params.pHttpParameters->pathLen = NULL_TERMINATED_PATH_LEN;
    returnStatus = SigV4_GenerateHTTPAuthorization( &params, authBuf, &authBufLen, &signature, &signatureLen );
    TEST_ASSERT_EQUAL( SigV4Success, returnStatus );

    /* Coverage for double-encoded equals in query string value. */
    params.pHttpParameters->pQuery = QUERY_STRING_VALUE_HAS_EQUALS;
    params.pHttpParameters->queryLen = STR_LIT_LEN( QUERY_STRING_VALUE_HAS_EQUALS );
    returnStatus = SigV4_GenerateHTTPAuthorization( &params, authBuf, &authBufLen, &signature, &signatureLen );
    TEST_ASSERT_EQUAL( SigV4Success, returnStatus );
}

void test_SigV4_GenerateHTTPAuthorization_Default_Arguments()
{
    SigV4Status_t returnStatus;

    /* Default algorithm is the macro defined by SIGV4_AWS4_HMAC_SHA256. */
    params.pAlgorithm = NULL;
    returnStatus = SigV4_GenerateHTTPAuthorization( &params, authBuf, &authBufLen, &signature, &signatureLen );
    TEST_ASSERT_EQUAL( SigV4Success, returnStatus );
    params.pAlgorithm = SIGV4_AWS4_HMAC_SHA256;
    params.algorithmLen = 0;
    returnStatus = SigV4_GenerateHTTPAuthorization( &params, authBuf, &authBufLen, &signature, &signatureLen );
    TEST_ASSERT_EQUAL( SigV4Success, returnStatus );
    /* Default path is "/". */
    params.pHttpParameters->pPath = NULL;
    returnStatus = SigV4_GenerateHTTPAuthorization( &params, authBuf, &authBufLen, &signature, &signatureLen );
    TEST_ASSERT_EQUAL( SigV4Success, returnStatus );
    params.pHttpParameters->pPath = "/";
    params.pHttpParameters->pathLen = 0;
    returnStatus = SigV4_GenerateHTTPAuthorization( &params, authBuf, &authBufLen, &signature, &signatureLen );
    TEST_ASSERT_EQUAL( SigV4Success, returnStatus );
}

/**
 * @brief Test the case when some input parameters are precanonicalized.
 */
void test_SigV4_GenerateHTTPAuthorization_Precanonicalized()
{
    SigV4Status_t returnStatus;

    params.pHttpParameters->flags = SIGV4_HTTP_PATH_IS_CANONICAL_FLAG;
    returnStatus = SigV4_GenerateHTTPAuthorization( &params, authBuf, &authBufLen, &signature, &signatureLen );
    TEST_ASSERT_EQUAL( SigV4Success, returnStatus );

    params.pHttpParameters->flags = SIGV4_HTTP_QUERY_IS_CANONICAL_FLAG;
    returnStatus = SigV4_GenerateHTTPAuthorization( &params, authBuf, &authBufLen, &signature, &signatureLen );
    TEST_ASSERT_EQUAL( SigV4Success, returnStatus );

    params.pHttpParameters->pHeaders = PRECANON_HEADER;
    params.pHttpParameters->headersLen = STR_LIT_LEN( PRECANON_HEADER );
    params.pHttpParameters->flags = SIGV4_HTTP_HEADERS_ARE_CANONICAL_FLAG;
    returnStatus = SigV4_GenerateHTTPAuthorization( &params, authBuf, &authBufLen, &signature, &signatureLen );
    TEST_ASSERT_EQUAL( SigV4Success, returnStatus );
}

/**
 * @brief Test for all cases where the processing buffer runs out of space.
 * @note While writing these tests, the inputs were deliberately crafted for
 * a buffer with 350 bytes as its maximum length.
 */
void test_SigV4_GenerateHTTPAuthorization_InsufficientMemory()
{
    /* The authorization buffer must be at least the size of the hash digest. */
    SigV4Status_t returnStatus;

    authBufLen = params.pCryptoInterface->hashDigestLen * 2;
    returnStatus = SigV4_GenerateHTTPAuthorization( &params, authBuf, &authBufLen, &signature, &signatureLen );
    TEST_ASSERT_EQUAL( SigV4InsufficientMemory, returnStatus );

    /* BEGIN: Coverage for generateCanonicalURI(). */
    /* The path here will cause the error for the first time the path is encoded. */
    resetInputParams();
    params.pHttpParameters->pPath = PATH_FIRST_ENCODE_OOM;
    params.pHttpParameters->pathLen = STR_LIT_LEN( PATH_FIRST_ENCODE_OOM );
    returnStatus = SigV4_GenerateHTTPAuthorization( &params, authBuf, &authBufLen, &signature, &signatureLen );
    TEST_ASSERT_EQUAL( SigV4InsufficientMemory, returnStatus );

    /* Same as previous but need for adding a linefeed character causes the error. We also explicitly use S3
     * service so that out of memory does not occur when double encoding. */
    resetInputParams();
    params.pService = S3_SERVICE_NAME;
    params.serviceLen = S3_SERVICE_NAME_LEN;
    params.pHttpParameters->pPath = PATH_FIRST_ENCODE_AND_LF_OOM;
    params.pHttpParameters->pathLen = STR_LIT_LEN( PATH_FIRST_ENCODE_AND_LF_OOM );
    returnStatus = SigV4_GenerateHTTPAuthorization( &params, authBuf, &authBufLen, &signature, &signatureLen );
    TEST_ASSERT_EQUAL( SigV4InsufficientMemory, returnStatus );

    /* The path here will cause the error for the second time the path is encoded. */
    resetInputParams();
    params.pHttpParameters->pPath = PATH_SECOND_ENCODE_OOM;
    params.pHttpParameters->pathLen = STR_LIT_LEN( PATH_SECOND_ENCODE_OOM );
    returnStatus = SigV4_GenerateHTTPAuthorization( &params, authBuf, &authBufLen, &signature, &signatureLen );
    TEST_ASSERT_EQUAL( SigV4InsufficientMemory, returnStatus );
    /* END: Coverage for generateCanonicalURI(). */

    /* BEGIN: Coverage for writeCanonicalQueryParameters(). */
    /* The attempt to encode the query field causes OOM (out of memory). */
    resetInputParams();
    params.pHttpParameters->pQuery = QUERY_ENCODE_FIELD_OOM;
    params.pHttpParameters->queryLen = STR_LIT_LEN( QUERY_ENCODE_FIELD_OOM );
    returnStatus = SigV4_GenerateHTTPAuthorization( &params, authBuf, &authBufLen, &signature, &signatureLen );
    TEST_ASSERT_EQUAL( SigV4InsufficientMemory, returnStatus );

    /* The attempt to encode the query value causes OOM (out of memory). */
    resetInputParams();
    params.pHttpParameters->pQuery = QUERY_ENCODE_VALUE_OOM;
    params.pHttpParameters->queryLen = STR_LIT_LEN( QUERY_ENCODE_VALUE_OOM );
    returnStatus = SigV4_GenerateHTTPAuthorization( &params, authBuf, &authBufLen, &signature, &signatureLen );
    TEST_ASSERT_EQUAL( SigV4InsufficientMemory, returnStatus );

    /* The attempt to write the '=' character before a value causes OOM (out of memory). */
    resetInputParams();
    params.pHttpParameters->pQuery = QUERY_EQUAL_BEFORE_VALUE_OOM;
    params.pHttpParameters->queryLen = STR_LIT_LEN( QUERY_EQUAL_BEFORE_VALUE_OOM );
    returnStatus = SigV4_GenerateHTTPAuthorization( &params, authBuf, &authBufLen, &signature, &signatureLen );
    TEST_ASSERT_EQUAL( SigV4InsufficientMemory, returnStatus );

    /* The attempt to write the '&' character before a field causes OOM (out of memory). */
    resetInputParams();
    params.pHttpParameters->pQuery = QUERY_AMPERSAND_BEFORE_FIELD_OOM;
    params.pHttpParameters->queryLen = STR_LIT_LEN( QUERY_AMPERSAND_BEFORE_FIELD_OOM );
    returnStatus = SigV4_GenerateHTTPAuthorization( &params, authBuf, &authBufLen, &signature, &signatureLen );
    TEST_ASSERT_EQUAL( SigV4InsufficientMemory, returnStatus );
    /* END: Coverage for writeCanonicalQueryParameters(). */

    /* BEGIN: Coverage for writeLineToCanonicalRequest(). */
    /* Writing a precanonicalized query to the processing buffer causes OOM. */
    resetInputParams();
    params.pHttpParameters->pQuery = PRECANON_QUERY_TOO_LONG;
    params.pHttpParameters->queryLen = STR_LIT_LEN( PRECANON_QUERY_TOO_LONG );
    params.pHttpParameters->flags = SIGV4_HTTP_QUERY_IS_CANONICAL_FLAG;
    returnStatus = SigV4_GenerateHTTPAuthorization( &params, authBuf, &authBufLen, &signature, &signatureLen );
    TEST_ASSERT_EQUAL( SigV4InsufficientMemory, returnStatus );
    /* END: Coverage for writeLineToCanonicalRequest(). */
}

/**
 * @brief Coverage for cases when the hashing functions return errors.
 */
void test_SigV4_GenerateHTTPAuthorization_Hash_Errors()
{
    SigV4Status_t returnStatus;
    size_t i;

    for( i = 0U; i < HAPPY_PATH_HASH_ITERATIONS; i++ )
    {
        resetFailableHashParams();
        initHashCallToFail = i;
        returnStatus = SigV4_GenerateHTTPAuthorization( &params, authBuf, &authBufLen, &signature, &signatureLen );
        TEST_ASSERT_EQUAL( SigV4HashError, returnStatus );

        resetFailableHashParams();
        updateHashCallToFail = i;
        returnStatus = SigV4_GenerateHTTPAuthorization( &params, authBuf, &authBufLen, &signature, &signatureLen );
        TEST_ASSERT_EQUAL( SigV4HashError, returnStatus );

        resetFailableHashParams();
        finalHashCallToFail = i;
        returnStatus = SigV4_GenerateHTTPAuthorization( &params, authBuf, &authBufLen, &signature, &signatureLen );
        TEST_ASSERT_EQUAL( SigV4HashError, returnStatus );
    }
}

/**
 * @brief Test the case when the query string or header parameters exceed the max.
 */
void test_SigV4_GenerateHTTPAuthorization_Greater_Than_Max_Header_Query_Count()
{
    SigV4Status_t returnStatus;

    params.pHttpParameters->pQuery = QUERY_STRING_GT_MAX_PARAMS;
    params.pHttpParameters->queryLen = STR_LIT_LEN( QUERY_STRING_GT_MAX_PARAMS );
    returnStatus = SigV4_GenerateHTTPAuthorization( &params, authBuf, &authBufLen, &signature, &signatureLen );
    TEST_ASSERT_EQUAL( SigV4MaxQueryPairCountExceeded, returnStatus );

    resetInputParams();
}
