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
 * @file sigv4_internal.h
 * @brief Internal definitions for the SigV4 Client Utility Library.
 */

#ifndef SIGV4_INTERNAL_H_
#define SIGV4_INTERNAL_H_

/* Constants for date verification. */
#define YEAR_MIN               1900L /**< Earliest year accepted. */
#define MONTH_ASCII_LEN        3U    /**< Length of month abbreviations. */

/**
 * @brief Month name abbreviations for RFC 5322 date parsing.
 */
#define MONTH_NAMES            { "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" }

/**
 * @brief Number of days in each respective month.
 */
#define MONTH_DAYS             { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 }

#define FORMAT_RFC_3339        "%4Y-%2M-%2DT%2h:%2m:%2sZ"         /**< Format string to parse RFC 3339 date. */
#define FORMAT_RFC_3339_LEN    sizeof( FORMAT_RFC_3339 ) - 1U     /**< Length of the RFC 3339 format string. */

#define FORMAT_RFC_5322        "%3*, %2D %3M %4Y %2h:%2m:%2s GMT" /**< Format string to parse RFC 5322 date. */
#define FORMAT_RFC_5322_LEN    sizeof( FORMAT_RFC_5322 ) - 1U     /**< Length of the RFC 3339 format string. */

#define ISO_YEAR_LEN           4U                                 /**< Length of year value in ISO 8601 date. */
#define ISO_NON_YEAR_LEN       2U                                 /**< Length of non-year values in ISO 8601 date. */

/**
 * @brief An aggregator representing the individually parsed elements of the
 * user-provided date parameter. This is used to verify the complete date
 * representation, and construct the final ISO 8601 string.
 */
typedef struct SigV4DateTime
{
    int32_t tm_year; /**< Year (1900 or later) */
    int32_t tm_mon;  /**< Month (1 to 12) */
    int32_t tm_mday; /**< Day of Month (1 to 28/29/30/31) */
    int32_t tm_hour; /**< Hour (0 to 23) */
    int32_t tm_min;  /**< Minutes (0 to 59) */
    int32_t tm_sec;  /**< Seconds (0 to 60) */
} SigV4DateTime_t;

#endif /* ifndef SIGV4_INTERNAL_H_ */
