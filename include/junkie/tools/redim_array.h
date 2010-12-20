// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#ifndef REDIM_ARRAY_H_100907
#define REDIM_ARRAY_H_100907
#include <stdarg.h>
#include <junkie/tools/queue.h>

/** @file
 * @brief Redimentionable arrays
 */

/** A redim_array is a redimentionable array.
 * Each time you hit it's lenght you can resize it, without time penalty.
 * Performence are similar than a mere array if your initial size guess is validm
 * or similar to a mere list if your initial guess is too small.
 */
struct redim_array {
    unsigned nb_entries;    ///< Number of used entries
    unsigned alloc_size;    ///< Initial guess of the array size (we are going to alloc chunks of this size)
    size_t entry_size;      ///< Size of a single value
    TAILQ_HEAD(redim_array_chunks, redim_array_chunk) chunks;   ///< List of array chunks
    LIST_ENTRY(redim_array) entry;  ///< Entry in the list of all redim_arrays
    char const *name;       ///< Name of the array, for stats purpose
};

/// List of all existing redim_array, for stats purpose.
extern LIST_HEAD(redim_arrays, redim_array) redim_arrays;

/// Construct a new redim_array
int redim_array_ctor(struct redim_array *, unsigned alloc_size, size_t entry_size, char const *name);

/// Destruct a redim array
void redim_array_dtor(struct redim_array *);

/// Append a cell at the end of the array
void redim_array_push(struct redim_array *, void *cell);

/// We do not provide redim_array_pop because we don't want to return an address of an element that was removed from the array

/// @return the last cell from the array, or NULL if the array is empty
void *redim_array_last(struct redim_array *);

/// Chop the last entry of an array.
void redim_array_chop(struct redim_array *);

/// Empty the array.
void redim_array_clear(struct redim_array *);

/// Iterator
int redim_array_foreach(struct redim_array *, int (*cb)(struct redim_array *, void *cell, va_list), ...);

void redim_array_init(void);
void redim_array_fini(void);

#endif
