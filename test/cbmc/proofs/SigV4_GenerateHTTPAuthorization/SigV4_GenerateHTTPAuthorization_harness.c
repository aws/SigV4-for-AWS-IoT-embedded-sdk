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
 * @file SigV4_GenerateHTTPAuthorization_harness.c
 * @brief Implements the proof harness for the SigV4_GenerateHTTPAuthorization function.
 */

/* Include paths for public enums, structures, and macros. */
#include "stdlib.h"
#include "sigv4.h"

void harness()
{
    SigV4Parameters_t * pSigV4Params;
    char * pAuthBuf;
    size_t * authBufLen;
    char ** pSignature;
    size_t * signatureLen;
    SigV4Status_t status;

    pSigV4Params = malloc( sizeof( SigV4Parameters_t ) );

    if( pSigV4Params != NULL )
    {
        __CPROVER_assume( pSigV4Params->regionLen < CBMC_MAX_OBJECT_SIZE );
        pSigV4Params->pRegion = malloc( pSigV4Params->regionLen );

        __CPROVER_assume( pSigV4Params->serviceLen < CBMC_MAX_OBJECT_SIZE );
        pSigV4Params->pService = malloc( pSigV4Params->serviceLen );

        pSigV4Params->pCredentials = malloc( sizeof( SigV4Credentials_t ) );
        pSigV4Params->pCryptoInterface = malloc( sizeof( SigV4CryptoInterface_t ) );
        pSigV4Params->pHttpParameters = malloc( sizeof( SigV4HttpParameters_t ) );
    }

    authBufLen = malloc( sizeof( size_t ) );
    signatureLen = malloc( sizeof( size_t ) );

    if( ( authBufLen != NULL ) && ( signatureLen != NULL ) )
    {
        __CPROVER_assume( *authBufLen < CBMC_MAX_OBJECT_SIZE );
        __CPROVER_assume( *signatureLen < CBMC_MAX_OBJECT_SIZE );

        pAuthBuf = malloc( *authBufLen );
        pSignature = malloc( *signatureLen );
    }

    status = SigV4_GenerateHTTPAuthorization( pSigV4Params, pAuthBuf, authBufLen, pSignature, signatureLen );
    __CPROVER_assert( status == SigV4InvalidParameter || status == SigV4Success || status == SigV4ISOFormattingError, "This is not a valid SigV4 return status" );
}
