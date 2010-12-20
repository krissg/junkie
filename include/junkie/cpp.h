// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#ifndef CPP_H
#define CPP_H
#include <stdlib.h>

/** @file
 * @brief Some GCC attributes that may help to generate fast code.
 *
 * Here are defined :
 *
 * - pure_, hot_, cold_, for functions,
 * - likely_, unlikely_, for if statements,
 * - unused_, to avoid some warnings,
 * - a_la_printf_, to check parameters according to a format string,
 * - packed_, to pack data structures.
 *
 * Of these, only the last one must be implemented in a way or another
 * in order for junkie to work properly.
 */

#ifndef pure__
#   if __GNUC_PREREQ(2, 96)
#       define pure_ __attribute__((pure))
#   else
#       define pure_
#   endif
#else
#   define pure_  ///< functions which result only depends on inputs be careful of thread safety, etc.
#endif

#ifndef hot_
#   if __GNUC_PREREQ(4, 3)
#       define hot_ __attribute__((hot))    ///< for often-called function
#   else
#       define hot_
#   endif
#else
#   define hot_
#endif

#ifndef cold_
#   if __GNUC_PREREQ(4, 3)
#       define cold_  __attribute__((cold))    ///< for rarely-called function
#   else
#       define cold_
#   endif
#else
#   define cold_
#endif

#ifndef likely_
#   if __GNUC_PREREQ(2, 96)
#       define likely_(x) __builtin_expect(!!(x), 1) ///< very probable branch in if statement
#   else
#       define likely_(x)
#   endif
#else
#   define likely_(x)
#endif

#ifndef unlikely_
#   if __GNUC_PREREQ(2, 96)
#       define unlikely_(x)  __builtin_expect(!!(x), 0) ///< very improbable branch in if statement
#   else
#       define unlikely_(x)
#   endif
#else
#   define unlikely_(x)
#endif

#ifndef unused_
#   if __GNUC_PREREQ(3, 0)
#       define unused_ __attribute__((__unused__))
#   else
#       define unused_
#   endif
#endif

#ifndef a_la_printf_
#   if __GNUC_PREREQ(3,0)
#       define a_la_printf_(str_i, arg_i) __attribute__((__format__(__printf__, str_i, arg_i)))
#   else
#       define a_la_printf_(str_i, arg_i)
#   endif
#endif

#ifndef packed_
#   if __GNUC_PREREQ(3,0)
#       define packed_ __attribute__((__packed__))
#   else
#       define packed_
#   endif
#endif

#endif
