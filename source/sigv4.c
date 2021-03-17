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
#include <ctype.h>

#include "sigv4.h"
#include "sigv4_internal.h"

/*-----------------------------------------------------------*/

/**
 * @brief Verifies parameters in @p pParams and its sub-members.
 *
 * @param[in] pParams Complete SigV4 configurations passed by application.
 *
 * @return #SigV4Success if successful, #SigV4InvalidParameters otherwise.
 */
static SigV4Status_t verifySigV4Parameters( const SigV4Parameters_t * pParams );


#if ( SIGV4_USE_CANONICAL_SUPPORT == 1 )

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
                                      canonicalContext_t * canonicalRequest );

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
                                        canonicalContext_t * canonicalRequest );

    /**
     * @brief Canonicalize the HTTP request headers.
     *
     * @param[in] pHeaders The raw HTTP headers.
     * @param[in] headerLen Length of pHeaders.
     * @param[in, out] canonicalRequest Struct to maintain intermediary buffer
     * and state of canonicalization.
     */
    static void generateCanonicalHeaders( const char * pHeaders,
                                          size_t headerLen,
                                          canonicalContext_t * canonicalRequest );


#endif /* if ( SIGV4_USE_CANONICAL_SUPPORT == 1 ) */

/*-----------------------------------------------------------*/

/* Converts a hex character to its integer value */
static char hexToInt( char pHex )
{
    return isdigit( pHex ) ? pHex - '0' : tolower( pHex ) - 'a' + 10;
}

/* Converts an integer value to its hex character */
static char intToHex( char pInt )
{
    static char hex[] = "0123456789abcdef";

    return hex[ pInt & 15 ];
}

static void encodeURI( const char * pURI,
                       size_t uriLen,
                       char * pCanonicalURI,
                       size_t * canonicalURILen,
                       bool encodeSlash,
                       bool nullTerminate )
{
    char * pURILoc = pURI;
    char * pBufLoc = pCanonicalURI;
    size_t index = 0U;

    assert( pURI != NULL );
    assert( pCanonicalURI != NULL );
    assert( canonicalURILen != NULL );
    assert( *canonicalURILen > 0U );

    while( index < uriLen && *pURILoc )
    {
        if( isalnum( *pURILoc ) || ( *pURILoc == '-' ) || ( *pURILoc == '_' ) || ( *pURILoc == '.' ) || ( *pURILoc == '~' ) )
        {
            *pBufLoc++ = *pURILoc;
        }
        else if( *pURILoc == '/' )
        {
            *pBufLoc++ = encodeSlash ? '%2F' : *pURILoc;
        }
        else
        {
            *pBufLoc++ = '%', *pBufLoc++ = intToHex( *pURILoc >> 4 ), *pBufLoc++ = intToHex( *pURILoc & 15 );
        }

        pURILoc++;
        index++;
    }

    if( nullTerminate )
    {
        *pBufLoc++ = '\0';
        index++;
    }

    *canonicalURILen = index;
}

/*-----------------------------------------------------------*/

static void generateCanonicalURI( const char * pURI,
                                  size_t uriLen,
                                  bool encodeOnce,
                                  canonicalContext_t * canonicalRequest )
{
    size_t encodedLen, remainingLen = canonicalRequest->bufRemaining;
    char * pBufLoc = canonicalRequest->pBufCur;

    assert( pURI != NULL );
    assert( canonicalRequest != NULL );

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

static int cmpFun( const void * a,
                   const void * b )
{
    char * token_a = strtok( ( char * ) a, "=" );
    char * token_b = strtok( ( char * ) b, "=" );

    int compare = strcmp( token_a, token_b );

    if( strcmp == 0 )
    {
        token_a = strtok( NULL, "=" );
        token_b = strtok( NULL, "=" );

        assert( token_a != NULL );
        assert( token_b != NULL );

        compare = strcmp( token_a, token_b );
    }

    return compare;
}

static void generateCanonicalQuery( const char * pQuery,
                                    size_t queryLen,
                                    canonicalContext_t * canonicalRequest )
{
    size_t index = 0U;
    size_t remainingLen = canonicalRequest->bufRemaining;
    char * pBufLoc = canonicalRequest->pBufCur;
    char * tokenQueries, tokenParams;

    assert( pQuery != NULL );
    assert( canonicalRequest != NULL );

    tokenQueries = strtok( pQuery, "&" );

    while( tokenQueries != NULL )
    {
        canonicalRequest->pQueryLoc[ index ] = &tokenQueries[ 0 ];
        tokenQueries = strtok( NULL, "&" );

        index++;
    }

    qsort( canonicalRequest->pQueryLoc, index, cmpFun );

    for( int i = 0; i < index; i++ )
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
            *pBufLoc++ = '&';
            *pBufLoc++ = '\0';
            *pBufLoc++ = '\n';
            canonicalRequest->bufRemaining -= 3;
        }
    }

    canonicalRequest->pBufCur = pBufLoc;
}

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
                                         char pDateISO8601[ 17 ] )
{
    SigV4Status_t returnStatus = SigV4Success;
    size_t lenFormatted = 0U;
    char * pLastChar = NULL;
    struct tm tm;

    /* Check for NULL parameters. */
    if( pDate == NULL )
    {
        LogError( ( "Parameter check failed: pDate is NULL." ) );
        returnStatus = SigV4InvalidParameter;
    }
    else if( pDateISO8601 == NULL )
    {
        LogError( ( "Parameter check failed: pDateISO8601 is NULL." ) );
        returnStatus = SigV4InvalidParameter;
    }
    /* Check validity of the date header size provided. */
    else if( dateLen == 0U )
    {
        LogError( ( "Parameter check failed: dateLen must be greater than 0." ) );
        returnStatus = SigV4InvalidParameter;
    }

    if( returnStatus == SigV4Success )
    {
        memset( &tm, 0, sizeof( struct tm ) );
        pLastChar = strptime( pDate, "%Y-%m-%dT%H:%M:%SZ", &tm );

        if( pLastChar == NULL )
        {
            LogError( ( "Error matching input to ISO8601 format string." ) );
            returnStatus == SigV4ISOFormattingError;
        }
        else if( pLastChar != '\0' )
        {
            LogWarn( ( "Input contained more characters than expected." ) );
        }
    }

    if( returnStatus == SigV4Success )
    {
        lenFormatted = strftime( pDateISO8601, 17, "%Y%m%dT%H%M%SZ", &tm );

        if( lenFormatted != 16 )
        {
            LogError( ( "Formatted string is not of expected length 16." ) );
            returnStatus = SigV4ISOFormattingError;
        }
    }

    return returnStatus;
}
