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
 * @file sigv4_quicksort.c
 * @brief Implements an Iterative Quicksort Algorithm for the SigV4 Client Utility Library.
 */

#include "sigv4_quicksort.h"

#include <string.h>
#include <assert.h>

/**
 * @brief Push a value to the stack.
 */
#define PUSH_STACK( valueToPush, stack, index )   \
    {                                             \
        ( stack )[ ( index ) ] = ( valueToPush ); \
        ++( index );                              \
    }

/**
 * @brief Pop a value from the stack.
 */
#define POP_STACK( valueToPop, stack, index )    \
    {                                            \
        --( index );                             \
        ( valueToPop ) = ( stack )[ ( index ) ]; \
    }

/*-----------------------------------------------------------*/

/**
 * @brief A helper function to swap the value of two pointers
 * given their sizes.
 *
 * @param[in] pFirstItem The item to swap with @p pSecondItem.
 * @param[in] pSecondItem The item to swap with @p pFirstItem.
 * @param[in] itemSize The amount of memory per entry in the array.
 */
static void swap( void * pFirstItem,
                  void * pSecondItem,
                  size_t itemSize );

/**
 * @brief A helper function to perform quicksort on a subarray.
 *
 * @param[in] pArray The array to be sorted.
 * @param[in] low The low index of the array.
 * @param[in] high The high index of the array.
 * @param[in] itemSize The amount of memory per entry in the array.
 * @param[out] comparator The comparison function to determine if one item is less than another.
 */
static void quickSortHelper( void * pArray,
                             size_t low,
                             size_t high,
                             size_t itemSize,
                             ComparisonFunc_t comparator );

/**
 * @brief A helper function to partition a subarray using the last element
 * of the array as the pivot. All items smaller than the pivot end up
 * at its left while all items greater than end up at its right.
 *
 * @param[in] pArray The array to be sorted.
 * @param[in] low The low index of the array.
 * @param[in] high The high index of the array.
 * @param[in] itemSize The amount of memory per entry in the array.
 * @param[out] comparator The comparison function to determine if one item is less than another.
 *
 * @return The index of the pivot
 */
static size_t partition( void * pArray,
                         size_t low,
                         size_t high,
                         size_t itemSize,
                         ComparisonFunc_t comparator );

/*-----------------------------------------------------------*/

static void swap( void * pFirstItem,
                  void * pSecondItem,
                  size_t itemSize )
{
    uint8_t * pFirstByte = pFirstItem;
    uint8_t * pSecondByte = pSecondItem;
    size_t dataSize = itemSize;

    if( ( pFirstItem != NULL ) && ( pSecondItem != NULL ) )
    {
        /* Swap one byte at a time. */
        while( dataSize-- > 0U )
        {
            uint8_t tmp = *pFirstByte;
            *pFirstByte = *pSecondByte;
            ++pFirstByte;
            *pSecondByte = tmp;
            ++pSecondByte;
        }
    }
}

static void quickSortHelper( void * pArray,
                             size_t low,
                             size_t high,
                             size_t itemSize,
                             ComparisonFunc_t comparator )
{
    size_t stack[ SIGV4_WORST_CASE_SORT_STACK_SIZE ];

    /* Low and high are first two items on the stack. Note
     * that we use an intermediary variable for MISRA compliance. */
    size_t top = 0, lo = low, hi = high;

    PUSH_STACK( lo, stack, top );
    PUSH_STACK( hi, stack, top );

    while( top > 0U )
    {
        size_t partitionIndex;
        size_t len1, len2;
        POP_STACK( hi, stack, top );
        POP_STACK( lo, stack, top );

        partitionIndex = partition( pArray, lo, hi, itemSize, comparator );

        len1 = ( ( partitionIndex != 0U ) && ( ( partitionIndex - 1U ) > lo ) ) ? ( partitionIndex - 1U - lo ) : 0U;
        len2 = ( ( partitionIndex + 1U ) < hi ) ? ( hi - partitionIndex - 1U ) : 0U;

        if( len1 > len2 )
        {
            PUSH_STACK( lo, stack, top );
            PUSH_STACK( partitionIndex - 1U, stack, top );

            if( len2 > 0U )
            {
                PUSH_STACK( partitionIndex + 1U, stack, top );
                PUSH_STACK( hi, stack, top );
            }
        }
        else
        {
            if( len2 > 0U )
            {
                PUSH_STACK( partitionIndex + 1U, stack, top );
                PUSH_STACK( hi, stack, top );
            }

            if( len1 > 0U )
            {
                PUSH_STACK( lo, stack, top );
                PUSH_STACK( partitionIndex - 1U, stack, top );
            }
        }
    }
}

static size_t partition( void * pArray,
                         size_t low,
                         size_t high,
                         size_t itemSize,
                         ComparisonFunc_t comparator )
{
    void * pivot;
    size_t i = low - 1U, j = low;

    assert( pArray != NULL );

    pivot = pArray + ( high * itemSize );

    for( ; j < high; j++ )
    {
        /* Use comparator function to check current element is smaller than the pivot */
        if( comparator( pArray + ( j * itemSize ), pivot ) < 0 )
        {
            ++i;
            swap( pArray + ( i * itemSize ), pArray + ( j * itemSize ), itemSize );
        }
    }

    swap( pArray + ( ( i + 1U ) * itemSize ), pivot, itemSize );
    return i + 1U;
}

void quickSort( void * pArray,
                size_t numItems,
                size_t itemSize,
                ComparisonFunc_t comparator )
{
    if( ( numItems != 0U ) && ( pArray != NULL ) )
    {
        quickSortHelper( pArray, 0U, numItems - 1U, itemSize, comparator );
    }
}
