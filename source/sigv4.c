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
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

#include "sigv4.h"
#include "sigv4_internal.h"

/*-----------------------------------------------------------*/

#if ( SIGV4_USE_CANONICAL_SUPPORT == 1 )

/**
 * @brief Interpret string parameters into standardized SigV4String_t structs to
 * assist in sorting and canonicalization.
 *
 * @param[in, out] pSigV4Value The SigV4 standardized struct to populate.
 * @param[in] pInput String containing sorting parameters.
 * @param[in] lenInput Length of string @pInput.
 */
    static void stringToSigV4Value( SigV4String_t * pSigV4Value,
                                    const char * pInput,
                                    size_t lenInput );

/**
 * @brief Verifies if a SigV4 string value is empty.
 *
 * @param[in] pInput The SigV4 string value struct to verify.
 *
 * @return Returns 'true' if @pInput is empty, and 'false' otherwise.
 */
    static bool emptySigV4String( SigV4String_t * pInput );

/**
 * @brief Normalize a URI string according to RFC 3986 and fill destination
 * buffer with the formatted string.
 *
 * @param[in] pURI The URI string to encode.
 * @param[in] uriLen Length of pURI.
 * @param[out] pCanonicalURI The resulting canonicalized URI.
 * @param[in, out] canonicalURILen input: the length of pCanonicalURI,
 * output: the length of the generated canonical URI.
 * @param[in] encodeSlash Option to indicate if slashes should be encoded.
 * @param[in] nullTerminate Option to indicate if a null character should be
 * added to the end of the canonical URI.
 */
    static void encodeURI( const char * pURI,
                           size_t uriLen,
                           char * pCanonicalURI,
                           size_t * canonicalURILen,
                           bool encodeSlash,
                           bool nullTerminate );

/**
 * @brief Canonicalize the full URI path. The input URI starts after the
 * HTTP host and ends at the question mark character ("?") that begins the
 * query string parameters (if any). Example: folder/subfolder/item.txt"
 *
 * @param[in] pUri HTTP request URI, also known that the request absolute
 * path.
 * @param[in] uriLen Length of pURI.
 * @param[in] encodeOnce Service-dependent option to indicate whether
 * encoding should be done once or twice. For example, S3 requires that the
 * URI is encoded only once, while other services encode twice.
 * @param[in, out] canonicalRequest Struct to maintain intermediary buffer
 * and state of canonicalization.
 */
    static void generateCanonicalURI( const char * pURI,
                                      size_t uriLen,
                                      bool encodeOnce,
                                      CanonicalContext_t * canonicalRequest );

/**
 * @brief Canonicalize the query string HTTP URL, beginning (but not
 * including) at the "?" character. Does not include "/".
 *
 * @param[in] pQuery HTTP request query.
 * @param[in] queryLen Length of pQuery.
 * @param[in, out] canonicalRequest Struct to maintain intermediary buffer
 * and state of canonicalization.
 */
    static void generateCanonicalQuery( const char * pQuery,
                                        size_t queryLen,
                                        CanonicalContext_t * canonicalRequest );

/**
 * @brief Compare two SigV4 data structures lexicographically, without case-sensitivity.
 *
 * @param[in] pFirstVal SigV4 key value data structure to sort.
 * @param[in] pSecondVal SigV4 key value data structure to sort.
 *
 * @return Returns a value less than 0 if @pFirstVal < @pSecondVal, or
 * a value greater than 0 if @pSecondVal < @pFirstVal. 0 is never returned in
 * order to provide stability to qSort() calls.
 */
    static int32_t cmpKeyValue( const void * pFirstVal,
                                const void * pSecondVal );

#endif /* #if (SIGV4_USE_CANONICAL_SUPPORT == 1) */

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
 * @brief Format the credential scope of the authorization header using the date, region, and service
 * parameters found in #SigV4Parameters_t.
 *
 * @param[in] pSigV4Params The application parameters defining the credential's scope.
 * @param[in, out] pCredScope The credential scope in the V4 required format.
 *
 * @return SigV4ISOFormattingError if a snprintf() error was encountered,
 * SigV4Success otherwise.
 */
static SigV4Status_t getCredentialScope( SigV4Parameters_t * pSigV4Params,
                                         SigV4String_t * pCredScope );

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

/**
 * @brief Verify @p pParams and its sub-members.
 *
 * @param[in] pParams Complete SigV4 configurations passed by application.
 *
 * @return #SigV4Success if successful, #SigV4InvalidParameter otherwise.
 */
static SigV4Status_t verifySigV4Parameters( const SigV4Parameters_t * pParams );

/**
 * @brief Hex digest of provided string parameter.
 *
 * @param[in] pInputStr String to encode.
 * @param[out] pHexOutput Hex representation of @p pInputStr.
 */
static void hexEncode( SigV4String_t * pInputStr,
                       SigV4String_t * pHexOutput );

/**
 * @brief Extract each header key and value from passed pHeaders string.
 *
 * @param[in] pHeaders HTTP headers to canonicalize.
 * @param[in] headersLen Length of HTTP headers to canonicalize.
 * @param[in] flags Flag to indicate if headers are already
 * in the canonical form.
 * @param[out] canonicalRequest Struct to maintain intermediary buffer
 * and state of canonicalization.
 *
 * @return Following statuses will be returned by the function:
 * #SigV4Success if headers are successfully added to the canonical request.
 * #SigV4InsufficientMemory if canonical request buffer cannot accommodate the header.
 * #SigV4MaxHeaderPairCountExceeded if number of headers that needs to be canonicalized
 * exceed the SIGV4_MAX_HTTP_HEADER_COUNT macro defined in the config file.
 */
static SigV4Status_t appendAllHeadersToCanonicalRequest( const char * pHeaders,
                                                         size_t headersLen,
                                                         uint32_t flags,
                                                         CanonicalContext_t * canonicalRequest );

/**
 * @brief Append Signed Headers to the string which needs to be signed.
 *
 * @param[in] headerCount Number of headers which needs to be appended.
 * @param[in] flags Flag to indicate if headers are already
 * in the canonical form.
 * @param[in,out] canonicalRequest Struct to maintain intermediary buffer
 * and state of canonicalization.
 *
 * @return Following statuses will be returned by the function:
 * #SigV4Success if headers are successfully added to the canonical request.
 * #SigV4InsufficientMemory if canonical request buffer cannot accommodate the header.
 */
static SigV4Status_t appendSignedHeaders( size_t headerCount,
                                          uint32_t flags,
                                          CanonicalContext_t * canonicalRequest );

/**
 * @brief Canonicalize headers and append it to the string which needs to be signed.
 *
 * @param[in] headerCount Number of headers which needs to be appended.
 * @param[in,out] canonicalRequest Struct to maintain intermediary buffer
 * and state of canonicalization.
 *
 * @return Following statuses will be returned by the function:
 * #SigV4Success if headers are successfully added to the canonical request.
 * #SigV4InsufficientMemory if canonical request buffer cannot accommodate the header.
 */
static SigV4Status_t appendCanonicalizedHeaders( size_t headerCount,
                                                 CanonicalContext_t * canonicalRequest );

/**
 * @brief Write signed headers to the buffer provided.
 *
 * @param[in] headerIndex Index of header to write to buffer.
 * @param[in] flags Flag to indicate if headers are already
 * in the canonical form.
 * @param[in,out] canonicalRequest Struct to maintain intermediary buffer
 * and state of canonicalization.
 *
 * @return Following statuses will be returned by the function:
 * #SigV4Success if the signed headers are successfully added to the canonical request.
 * #SigV4InsufficientMemory if canonical request buffer cannot accommodate the header.
 */
static SigV4Status_t writeSignedHeaderToCanonicalRequest( size_t headerIndex,
                                                          uint32_t flags,
                                                          CanonicalContext_t * canonicalRequest );

/**
 * @brief Write canonical headers to the buffer provided.
 *
 * @param[in] headerIndex Index of header to write to buffer.
 * @param[in,out] canonicalRequest Struct to maintain intermediary buffer
 * and state of canonicalization.
 *
 * @return Following statuses will be returned by the function:
 * #SigV4Success if the canonical headers are successfully added to the canonical request.
 * #SigV4InsufficientMemory if canonical request buffer cannot accommodate the header.
 */
static SigV4Status_t writeCanonicalHeaderToCanonicalRequest( size_t headerIndex,
                                                             CanonicalContext_t * canonicalRequest );

/**
 * @brief Helper function to determine whether a header string character represents a space
 * that can be trimmed when creating "Canonical Headers".
 * All leading and trailing spaces in the header strings need to be trimmed. Also, sequential spaces
 * in the header value need to be trimmed to a single space.
 *
 * Example of modifying header field for Canonical Headers:
 * Actual header pair:                 |      Modifier header pair
 * My-Header2:    "a   b   c"  \n      |      my-header2:"a b c"\n
 *
 * @param[in] value Header value or key string to be trimmed.
 * @param[in] index Index of current character.
 * @param[in] valLen Length of the string.
 * @param[in] trimmedLength Current length of trimmed string.
 *
 * @return `true` if the character needs to be trimmed, else `false`.
 */
static bool isTrimmableSpace( const char * value,
                              size_t index,
                              size_t valLen,
                              size_t trimmedLength );

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
    while( lenRemaining > 0U )
    {
        lenRemaining--;
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
    if( ( formatChar == 'M' ) && ( remainingLenToRead == MONTH_ASCII_LEN ) )
    {
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

/* Hex digest of provided parameter string. */
static void hexEncode( SigV4String_t * pInputStr,
                       SigV4String_t * pHexOutput )
{
    static const char digitArr[] = "0123456789abcdef";
    char * hex = NULL;
    size_t i = 0U;

    assert( pInputStr != NULL );
    assert( pHexOutput != NULL );
    assert( pInputStr->pData != NULL );
    assert( pHexOutput->pData != NULL );

    hex = pHexOutput->pData;

    for( i = 0; i < pInputStr->dataLen; i++ )
    {
        *( hex++ ) = digitArr[ ( pInputStr->pData[ i ] & 0xF0 ) >> 4 ];
        *( hex++ ) = digitArr[ ( pInputStr->pData[ i ] & 0xF0 ) ];
    }

    pHexOutput->dataLen = pInputStr->dataLen * 2;
}

/*-----------------------------------------------------------*/

static SigV4Status_t getCredentialScope( SigV4Parameters_t * pSigV4Params,
                                         SigV4String_t * pCredScope )
{
    SigV4Status_t returnVal = SigV4InvalidParameter;
    char * pBufWrite = NULL;
    int32_t bytesWritten = 0;

    assert( pSigV4Params != NULL );
    assert( pCredScope != NULL );
    assert( pCredScope->pData != NULL );

    pBufWrite = pCredScope->pData;

    /* Use only the first 8 characters from the provided ISO 8601 string (YYYYMMDD). */
    bytesWritten = snprintf( ( char * ) pBufWrite,
                             pCredScope->dataLen + 1U,
                             "%*s",
                             ISO_DATE_SCOPE_LEN,
                             pSigV4Params->pDateIso8601 );

    if( bytesWritten == ISO_DATE_SCOPE_LEN )
    {
        bytesWritten = snprintf( ( char * ) pBufWrite,
                                 pSigV4Params->regionLen,
                                 "/%s/",
                                 pSigV4Params->pRegion );

        if( bytesWritten != pSigV4Params->regionLen )
        {
            LogError( ( "Error in formatting provided region string for credential scope." ) );
            returnVal = SigV4ISOFormattingError;
        }
    }
    else
    {
        LogError( ( "Error obtaining date for credential scope string." ) );
        returnVal = SigV4ISOFormattingError;
    }

    if( returnVal != SigV4ISOFormattingError )
    {
        bytesWritten = snprintf( ( char * ) pBufWrite,
                                 pSigV4Params->serviceLen,
                                 "/%s/",
                                 pSigV4Params->pService );

        if( bytesWritten != pSigV4Params->serviceLen )
        {
            LogError( ( "Error in formatting provided service string for credential scope." ) );
            returnVal = SigV4ISOFormattingError;
        }
    }
    else
    {
        pCredScope->dataLen = ISO_DATE_SCOPE_LEN + pSigV4Params->regionLen + pSigV4Params->serviceLen;
        returnVal = SigV4Success;
    }

    return returnVal;
}

/*-----------------------------------------------------------*/

#if ( SIGV4_USE_CANONICAL_SUPPORT == 1 )

    static void stringToSigV4Value( SigV4String_t * pSigV4Value,
                                    const char * pInput,
                                    size_t lenInput )
    {
        assert( pSigV4Value != NULL );
        assert( pInput != NULL );
        assert( lenInput > 0U );

        pSigV4Value->pData = ( char * ) pInput;
        pSigV4Value->dataLen = ( size_t ) lenInput;
    }

/*-----------------------------------------------------------*/

    static bool emptySigV4String( SigV4String_t * pInput )
    {
        bool returnVal = true;

        assert( pInput != NULL );

        return ( pInput->pData == NULL || pInput->dataLen == 0 ) ? returnVal : !returnVal;
    }

/*-----------------------------------------------------------*/

    static int32_t cmpField( const void * pFirstVal,
                             const void * pSecondVal )
    {
        SigV4KeyValuePair_t * pFirst, * pSecond = NULL;
        size_t lenSmall = 0U;

        assert( pFirstVal != NULL );
        assert( pSecondVal != NULL );

        pFirst = ( SigV4KeyValuePair_t * ) pFirstVal;
        pSecond = ( SigV4KeyValuePair_t * ) pSecondVal;

        assert( !emptySigV4String( &pFirst->key ) );
        assert( !emptySigV4String( &pSecond->key ) );

        if( pFirst->key.dataLen <= pSecond->key.dataLen )
        {
            lenSmall = pFirst->key.dataLen;
        }
        else
        {
            lenSmall = pSecond->key.dataLen;
        }

        return strncmp( ( char * ) pFirst->key.pData,
                        ( char * ) pSecond->key.pData,
                        lenSmall );
    }

/*-----------------------------------------------------------*/

    static void encodeURI( const char * pURI,
                           size_t uriLen,
                           char * pCanonicalURI,
                           size_t * canonicalURILen,
                           bool encodeSlash,
                           bool nullTerminate )
    {
        const char * pURILoc = NULL;
        char * pBufLoc = NULL;
        size_t index = 0U;

        assert( pURI != NULL );
        assert( pCanonicalURI != NULL );
        assert( canonicalURILen != NULL );
        assert( *canonicalURILen > 0U );

        pURILoc = ( const char * ) pURI;
        pBufLoc = ( char * ) pCanonicalURI;

        while( index < uriLen && *pURILoc )
        {
            if( isalnum( *pURILoc ) || ( *pURILoc == '-' ) || ( *pURILoc == '_' ) || ( *pURILoc == '.' ) || ( *pURILoc == '~' ) )
            {
                *( pBufLoc++ ) = *pURILoc;
                index++;
            }
            else if( ( *pURILoc == '/' ) && !encodeSlash )
            {
                *( pBufLoc++ ) = *pURILoc;
                index++;
            }
            else
            {
                *( pBufLoc++ ) = '%';
                *( pBufLoc++ ) = *pURILoc >> 4;
                *( pBufLoc++ ) = *pURILoc & 0x0F;

                index += 3;
            }

            pURILoc++;
        }

        if( nullTerminate )
        {
            *( pBufLoc++ ) = '\0';
            index++;
        }

        *canonicalURILen = index;
    }

/*-----------------------------------------------------------*/

    static void generateCanonicalURI( const char * pURI,
                                      size_t uriLen,
                                      bool encodeOnce,
                                      CanonicalContext_t * canonicalRequest )
    {
        char * pBufLoc = NULL;
        size_t encodedLen, remainingLen = 0U;

        assert( pURI != NULL );
        assert( canonicalRequest != NULL );
        assert( canonicalRequest->pBufCur != NULL );

        pBufLoc = ( char * ) canonicalRequest->pBufCur;
        encodedLen, remainingLen = canonicalRequest->bufRemaining;
        encodeURI( pURI, uriLen, pBufLoc, &encodedLen, false, true );

        remainingLen -= encodedLen;

        if( !encodeOnce )
        {
            encodeURI( pBufLoc, encodedLen, pBufLoc + encodedLen, &remainingLen, false, true );
            memmove( canonicalRequest->pBufCur + encodedLen, canonicalRequest->pBufCur, remainingLen );
        }

        canonicalRequest->pBufCur += remainingLen;
        *( canonicalRequest->pBufCur++ ) = '\n';

        canonicalRequest->bufRemaining -= remainingLen + 1;
    }

/*-----------------------------------------------------------*/

    static bool isTrimmableSpace( const char * value,
                                  size_t index,
                                  size_t valLen,
                                  size_t trimmedLength )
    {
        bool ret = false;

        assert( ( value != NULL ) && ( index < valueLen ) );

        /* Only trim spaces. */
        if( isspace( value[ index ] ) )
        {
            /* The last character is a trailing space. */
            if( ( index + 1 ) == valLen )
            {
                ret = true;
            }
            /* Trim if the next character is also a space. */
            else if( isspace( value[ index + 1 ] ) )
            {
                ret = true;
            }
            /* It is a leading space if no characters have been written yet. */
            else if( trimmedLength == 0U )
            {
                ret = true;
            }
        }

        return ret;
    }

/*-----------------------------------------------------------*/

    static SigV4Status_t writeSignedHeaderToCanonicalRequest( size_t headerIndex,
                                                              uint32_t flags,
                                                              CanonicalContext_t * canonicalRequest )
    {
        char * pBufLoc;
        size_t buffRemaining, keyLen = 0, i = 0, trimKeyLen = 0;
        const char * headerKey;
        SigV4Status_t sigV4Status = SigV4Success;

        assert( canonicalRequest != NULL );
        assert( canonicalRequest->pBufCur != NULL );

        pBufLoc = canonicalRequest->pBufCur;
        buffRemaining = canonicalRequest->bufRemaining;

        keyLen = canonicalRequest->pHeadersLoc[ headerIndex ].key.dataLen;

        headerKey = canonicalRequest->pHeadersLoc[ headerIndex ].key.pData;

        for( i = 0; i < keyLen; i++ )
        {
            /* If the header field is not in canonical form already, we need to check
             * whether this character represents a trimmable space. */
            if( !( flags & SIGV4_HTTP_PATH_IS_CANONICAL_FLAG ) &&
                ( isTrimmableSpace( headerKey, i, keyLen, curNumOfCopiedBytes ) ) )
            {
                /* Cannot copy trimmable space into canonical request buffer. */
            }
            /* Remaining buffer space should at least accommodate the character to copy and the trailing ";" */
            else if( buffRemaining <= 1 )
            {
                sigV4Status = SigV4InsufficientMemory;
            }
            else
            {
                *pBufLoc = tolower( canonicalRequest->pHeadersLoc[ headerIndex ].key.pData[ i ] );
                pBufLoc++;
                buffRemaining = -1;
                curNumOfCopiedBytes++;
            }
        }

        /* Add the ending ";" character.
         * Note: Space for ending ";" was accounted for while copying header field data to
         * canonical request buffer. */
        if( sigV4Status == SigV4Success )
        {
            assert( buffRemaining >= 1 );
            *pBufLoc = ';';
            pBufLoc++;
            canonicalRequest->pBufCur = pBufLoc;
            canonicalRequest->bufRemaining = ( buffRemaining - 1 );
        }

        return sigV4Status;
    }

/*-----------------------------------------------------------*/

    static SigV4Status_t appendSignedHeaders( size_t headerCount,
                                              uint32_t flags,
                                              CanonicalContext_t * canonicalRequest )
    {
        size_t noOfHeaders = 0, keyLen = 0, i = 0;
        SigV4Status_t sigV4Status = SigV4Success;

        assert( canonicalRequest != NULL );
        assert( canonicalRequest->pBufCur != NULL );

        for( noOfHeaders = 0; noOfHeaders < headerCount; noOfHeaders++ )
        {
            assert( ( canonicalRequest->pHeadersLoc[ noOfHeaders ].key.pData ) != NULL );
            sigV4Status = writeSignedHeaderToCanonicalRequest( noOfHeaders, flags, canonicalRequest );

            if( sigV4Status != SigV4Success )
            {
                break;
            }
        }

        if( sigV4Status == SigV4Success )
        {
            /* Replacing the last ';' with '\n' as last header does need to have ';'. */
            *( canonicalRequest->pBufCur - 1 ) = '\n';
        }

        return sigV4Status;
    }

    static SigV4Status_t writeCanonicalHeaderToCanonicalRequest( size_t headerIndex,
                                                                 CanonicalContext_t * canonicalRequest )
    {
        size_t buffRemaining, keyLen = 0, valLen = 0, i = 0, trimValueLen = 0, trimKeyLen = 0;
        char * pBufLoc;
        const char * value;
        const char * headerKey;
        SigV4Status_t sigV4Status = SigV4Success;

        assert( canonicalRequest != NULL );
        assert( canonicalRequest->pBufCur != NULL );

        pBufLoc = canonicalRequest->pBufCur;
        buffRemaining = canonicalRequest->bufRemaining;

        keyLen = canonicalRequest->pHeadersLoc[ headerIndex ].key.dataLen;
        valLen = canonicalRequest->pHeadersLoc[ headerIndex ].value.dataLen;
        headerKey = canonicalRequest->pHeadersLoc[ headerIndex ].key.pData;

        for( i = 0; i < keyLen; i++ )
        {
            if( isTrimmableSpace( headerKey, i, keyLen, trimKeyLen ) )
            {
                /* Cannot copy trimmable space into canonical request buffer. */
            }
            /* Remaining buffer space should at least accommodate the character to copy and the trailing ":" */
            else if( buffRemaining <= 1 )
            {
                sigV4Status = SigV4InsufficientMemory;
                break;
            }
            else
            {
                *pBufLoc = tolower( headerKey[ i ] );
                pBufLoc++;
                trimKeyLen++;
                buffRemaining -= 1;
            }

            /* if( !( isTrimmableSpace( headerKey, i, keyLen, trimKeyLen ) ) ) */
            /* { */
            /*     if( buffRemaining < 1 ) */
            /*     { */
            /*         sigV4Status = SigV4InsufficientMemory; */
            /*         break; */
            /*     } */
            /*     else */
            /*     { */
            /*         *pBufLoc = tolower( headerKey[ i ] ); */
            /*         pBufLoc++; */
            /*         trimKeyLen++; */
            /*         buffRemaining -= 1; */
            /*     } */
            /* } */
        }

        if( sigV4Status == SigV4Success )
        {
            assert( buffRemaining >= 1 );
            *pBufLoc = ':';
            pBufLoc++;
            buffRemaining -= 1;
        }

        if( sigV4Status == SigV4Success )
        {
            value = canonicalRequest->pHeadersLoc[ headerIndex ].value.pData;
            trimValueLen = 0;

            for( i = 0; i < valLen; i++ )
            {
                if( ( isTrimmableSpace( value, i, valLen, trimValueLen ) ) )
                {
                    /* Cannot copy trimmable space into canonical request buffer. */
                }
                /* Remaining buffer space should at least accommodate the character to copy and the trailing "\n" */
                else if( ( buffRemaining <= 1 ) )
                {
                    sigV4Status = SigV4InsufficientMemory;
                    break;
                }
                else
                {
                    *pBufLoc = value[ i ];
                    pBufLoc++;
                    trimValueLen++;
                    buffRemaining -= 1;
                }

                /* if( !( isTrimmableSpace( value, i, valLen, trimValueLen ) ) ) */
                /* { */
                /*     if( buffRemaining < 1 ) */
                /*     { */
                /*         sigV4Status = SigV4InsufficientMemory; */
                /*         break; */
                /*     } */
                /*     else */
                /*     { */
                /*         *pBufLoc = value[ i ]; */
                /*         pBufLoc++; */
                /*         trimValueLen++; */
                /*         buffRemaining -= 1; */
                /*     } */
                /* } */
            }

            if( sigV4Status == SigV4Success )
            {
                assert( buffRemaining >= 1 );
                *pBufLoc = '\n';
                pBufLoc++;

                /* Calculate the remaining buffer. 1 is added for '\n' character. */
                buffRemaining -= 1;

                canonicalRequest->pBufCur = pBufLoc;
                canonicalRequest->bufRemaining = buffRemaining;
            }
        }

        return sigV4Status;
    }

/*-----------------------------------------------------------*/

    static SigV4Status_t appendCanonicalizedHeaders( size_t headerCount,
                                                     CanonicalContext_t * canonicalRequest )
    {
        size_t noOfHeaders = 0;
        SigV4Status_t sigV4Status = SigV4Success;

        assert( canonicalRequest != NULL );
        assert( canonicalRequest->pBufCur != NULL );

        for( noOfHeaders = 0; noOfHeaders < headerCount; noOfHeaders++ )
        {
            assert( canonicalRequest->pHeadersLoc[ noOfHeaders ].key.pData != NULL );
            sigV4Status = writeCanonicalHeaderToCanonicalRequest( noOfHeaders, canonicalRequest );

            if( sigV4Status != SigV4Success )
            {
                break;
            }
        }

        return sigV4Status;
    }

/*-----------------------------------------------------------*/

    static SigV4Status_t appendAllHeadersToCanonicalRequest( const char * pHeaders,
                                                             size_t headersLen,
                                                             uint32_t flags,
                                                             CanonicalContext_t * canonicalRequest )
    {
        const char * start;
        const char * end;
        size_t keyFlag = 1, noOfHeaders = 0, i = 0;
        SigV4Status_t sigV4Status = SigV4Success;

        assert( pHeaders != NULL );
        assert( canonicalRequest != NULL );
        assert( canonicalRequest->pBufCur != NULL );

        start = end = pHeaders;

        for( i = 0; i < headersLen; i++ )
        {
            if( noOfHeaders == SIGV4_MAX_HTTP_HEADER_COUNT )
            {
                sigV4Status = SigV4MaxHeaderPairCountExceeded;
                break;
            }

            /* Extracting each header key and value from the headers string. */
            if( ( keyFlag == 1 ) && ( pHeaders[ i ] == ':' ) )
            {
                canonicalRequest->pHeadersLoc[ noOfHeaders ].key.pData = start;
                canonicalRequest->pHeadersLoc[ noOfHeaders ].key.dataLen = ( end - start );
                start = end + 1U;
                keyFlag = 0;
            }
            else if( ( keyFlag == 0 ) && ( !( flags & SIGV4_HTTP_PATH_IS_CANONICAL_FLAG ) && ( pHeaders[ i ] == '\r' ) && ( ( i + 1 ) < headersLen ) && ( pHeaders[ i + 1 ] == '\n' ) ) )
            {
                canonicalRequest->pHeadersLoc[ noOfHeaders ].value.pData = start;
                canonicalRequest->pHeadersLoc[ noOfHeaders ].value.dataLen = ( end - start );
                start = end + 2U;
                keyFlag = 1;
                noOfHeaders++;
            }
            else if( ( keyFlag == 0 ) && ( ( flags & SIGV4_HTTP_PATH_IS_CANONICAL_FLAG ) && ( pHeaders[ i ] == '\n' ) ) )
            {
                canonicalRequest->pHeadersLoc[ noOfHeaders ].value.pData = start;
                canonicalRequest->pHeadersLoc[ noOfHeaders ].value.dataLen = ( end - start );
                start = end + 1U;
                keyFlag = 1;
                noOfHeaders++;
            }

            end++;
        }

        if( ( sigV4Status == SigV4Success ) && !( flags & SIGV4_HTTP_PATH_IS_CANONICAL_FLAG ) )
        {
            /* Sorting headers based on keys. */
            qsort( canonicalRequest->pHeadersLoc, noOfHeaders, sizeof( SigV4KeyValuePair_t ), cmpField );

            /* If the headers are canonicalized, we will copy them directly into the buffer as they do not
             * need processing, else we need to call the following function. */
            sigV4Status = appendCanonicalizedHeaders( noOfHeaders, canonicalRequest );
        }

        if( ( sigV4Status == SigV4Success ) && !( flags & SIGV4_HTTP_PATH_IS_CANONICAL_FLAG ) )
        {
            if( canonicalRequest->bufRemaining < 1 )
            {
                sigV4Status = SigV4InsufficientMemory;
            }
            else
            {
                *canonicalRequest->pBufCur = '\n';
                canonicalRequest->pBufCur++;
                canonicalRequest->bufRemaining--;
            }
        }

        if( sigV4Status == SigV4Success )
        {
            sigV4Status = appendSignedHeaders( noOfHeaders, flags, canonicalRequest );
        }

        return sigV4Status;
    }

    static void generateCanonicalQuery( const char * pQuery,
                                        size_t queryLen,
                                        CanonicalContext_t * canonicalRequest )
    {
        size_t index, remainingLen, i = 0U;
        char * pBufLoc, * tokenQueries, * tokenParams = NULL;

        assert( pQuery != NULL );
        assert( queryLen > 0U );
        assert( canonicalRequest != NULL );
        assert( canonicalRequest->pBufCur != NULL );

        remainingLen = canonicalRequest->bufRemaining;
        pBufLoc = ( char * ) canonicalRequest->pBufCur;

        tokenQueries = strtok( ( char * ) pQuery, "&" );

        while( tokenQueries != NULL )
        {
            canonicalRequest->pQueryLoc[ index ] = &tokenQueries[ 0 ];
            tokenQueries = strtok( NULL, "&" );

            index++;
        }

        qsort( canonicalRequest->pQueryLoc, index, sizeof( char * ), cmpKeyValue );

        for( i = 0U; i < index; i++ )
        {
            tokenParams = strtok( canonicalRequest->pQueryLoc[ i ], "=" );

            if( tokenParams != NULL )
            {
                encodeURI( tokenParams, strlen( tokenParams ), pBufLoc, &remainingLen, true, false );
                pBufLoc += remainingLen;
                *pBufLoc = '='; /* Overwrite null character. */

                canonicalRequest->bufRemaining -= remainingLen;
                remainingLen = canonicalRequest->bufRemaining;
            }

            tokenParams = strtok( NULL, "=" );

            if( tokenParams != NULL )
            {
                encodeURI( tokenParams, strlen( tokenParams ), pBufLoc, &remainingLen, true, false );
                pBufLoc += remainingLen;

                canonicalRequest->bufRemaining -= remainingLen;
                remainingLen = canonicalRequest->bufRemaining;
            }

            if( index != i + 1 )
            {
                *( pBufLoc++ ) = '&';
                *( pBufLoc++ ) = '\0';
                *( pBufLoc++ ) = '\n';
                canonicalRequest->bufRemaining -= 3;
            }
        }

        canonicalRequest->pBufCur = pBufLoc;
    }

#endif /* #if ( SIGV4_USE_CANONICAL_SUPPORT == 1 ) */

/*-----------------------------------------------------------*/

static SigV4Status_t verifySigV4Parameters( const SigV4Parameters_t * pParams )
{
    SigV4Status_t returnStatus = SigV4Success;

    /* Check for NULL members of struct pParams */
    if( pParams == NULL )
    {
        LogError( ( "Parameter check failed: pParams is NULL." ) );
        returnStatus = SigV4InvalidParameter;
    }
    else if( pParams->pCredentials == NULL )
    {
        LogError( ( "Parameter check failed: pParams->pCredentials is NULL." ) );
        returnStatus = SigV4InvalidParameter;
    }
    else if( pParams->pCredentials->pAccessKeyId == NULL )
    {
        LogError( ( "Parameter check failed: pParams->pCredentials->pAccessKeyId is NULL." ) );
        returnStatus = SigV4InvalidParameter;
    }
    else if( pParams->pCredentials->pSecretAccessKey == NULL )
    {
        LogError( ( "Parameter check failed: pParams->pCredentials->pSecretAccessKey is NULL." ) );
        returnStatus = SigV4InvalidParameter;
    }
    else if( pParams->pCredentials->pSecurityToken == NULL )
    {
        LogError( ( "Parameter check failed: pParams->pCredentials->pSecurityToken is NULL." ) );
        returnStatus = SigV4InvalidParameter;
    }
    else if( pParams->pCredentials->pExpiration == NULL )
    {
        LogError( ( "Parameter check failed: pParams->pCredentials->pExpiration is NULL." ) );
        returnStatus = SigV4InvalidParameter;
    }
    else if( pParams->pDateIso8601 == NULL )
    {
        LogError( ( "Parameter check failed: pParams->pDateIso8601 is NULL." ) );
        returnStatus = SigV4InvalidParameter;
    }
    else if( pParams->pRegion == NULL )
    {
        LogError( ( "Parameter check failed: pParams->pRegion is NULL." ) );
        returnStatus = SigV4InvalidParameter;
    }
    else if( pParams->pService == NULL )
    {
        LogError( ( "Parameter check failed: pParams->pService is NULL." ) );
        returnStatus = SigV4InvalidParameter;
    }
    else if( pParams->pCryptoInterface == NULL )
    {
        LogError( ( "Parameter check failed: pParams->pCryptoInterface is NULL." ) );
        returnStatus = SigV4InvalidParameter;
    }
    else if( pParams->pCryptoInterface->pHashContext == NULL )
    {
        LogError( ( "Parameter check failed: pParams->pCryptoInterface->pHashContext is NULL." ) );
        returnStatus = SigV4InvalidParameter;
    }
    else if( pParams->pHttpParameters == NULL )
    {
        LogError( ( "Parameter check failed: pParams->pHttpParameters is NULL." ) );
        returnStatus = SigV4InvalidParameter;
    }
    else if( pParams->pHttpParameters->pHttpMethod == NULL )
    {
        LogError( ( "Parameter check failed: pParams->pHttpParameters->pHttpMethod is NULL." ) );
        returnStatus = SigV4InvalidParameter;
    }
    else if( pParams->pHttpParameters->pPath == NULL )
    {
        LogError( ( "Parameter check failed: pParams->pHttpParameters->pPath is NULL." ) );
        returnStatus = SigV4InvalidParameter;
    }
    else if( pParams->pHttpParameters->pQuery == NULL )
    {
        LogError( ( "Parameter check failed: pParams->pHttpParameters->pQuery is NULL." ) );
        returnStatus = SigV4InvalidParameter;
    }
    else if( pParams->pHttpParameters->pHeaders == NULL )
    {
        LogError( ( "Parameter check failed: pParams->pHttpParameters->pHeaders is NULL." ) );
        returnStatus = SigV4InvalidParameter;
    }
    else if( pParams->pHttpParameters->pPayload == NULL )
    {
        LogError( ( "Parameter check failed: pParams->pHttpParameters->pPayload is NULL." ) );
        returnStatus = SigV4InvalidParameter;
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
