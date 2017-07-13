/*
 * Copyright (C) 2012 William Swanson
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF
 * CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * Except as contained in this notice, the names of the authors or
 * their institutions shall not be used in advertising or otherwise to
 * promote the sale, use or other dealings in this Software without
 * prior written authorization from the authors.
 */

/**
 * \file map.h
 * 
 * \brief map macro interface 
 *
 */
#ifndef MAP_H_INCLUDED
#define MAP_H_INCLUDED

#ifdef WIN32

// combine names
#define PLUS_TEXT_(x,y) x ## y
#define PLUS_TEXT(x, y) PLUS_TEXT_(x, y)

// receive args from VA_ARGS
#define ARG_1(_1, ...) _1
#define ARG_2(_1, _2, ...) _2
#define ARG_3(_1, _2, _3, ...) _3

#define ARG_40( _0, _1, _2, _3, _4, _5, _6, _7, _8, _9, \
                _10, _11, _12, _13, _14, _15, _16, _17, _18, _19, \
                _20, _21, _22, _23, _24, _25, _26, _27, _28, _29, \
                _30, _31, _32, _33, _34, _35, _36, _37, _38, _39, \
                ...) _39

// slice VA_ARGS
#define OTHER_1(_1, ...) __VA_ARGS__
#define OTHER_3(_1, _2, _3, ...) __VA_ARGS__

// hack for recursion in macro
#define EVAL0(...) __VA_ARGS__
#define EVAL1(...) EVAL0 (EVAL0 (EVAL0 (__VA_ARGS__)))
#define EVAL2(...) EVAL1 (EVAL1 (EVAL1 (__VA_ARGS__)))
#define EVAL3(...) EVAL2 (EVAL2 (EVAL2 (__VA_ARGS__)))
#define EVAL4(...) EVAL3 (EVAL3 (EVAL3 (__VA_ARGS__)))
#define EVAL(...) EVAL4 (EVAL4 (EVAL4 (__VA_ARGS__)))
// expand expressions
#define EXPAND(x) x

// "return" 2 if there are args, otherwise return 0
// for MAP it's ok that ignore first arg and no case with only one arg
// IMPORTANT! must call as MAP_SWITCH(0, __VA_ARGS__) for detection 0/1 arg case
#define MAP_SWITCH(...)\
    EXPAND(ARG_40(__VA_ARGS__, 2, 2, 2, 2, 2, 2, 2, 2, 2,\
            2, 2, 2, 2, 2, 2, 2, 2, 2, 2,\
            2, 2, 2, 2, 2, 2, 2, 2, 2,\
            2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 0))

// macro for recursion
#define MAP_B(...) \
    PLUS_TEXT(MAP_NEXT_, MAP_SWITCH(0, __VA_ARGS__)) (MAP_A, __VA_ARGS__)

#define MAP_A(...) \
    PLUS_TEXT(MAP_NEXT_, MAP_SWITCH(0, __VA_ARGS__)) (MAP_B, __VA_ARGS__)

#define MAP_CALL(fn, Value) EXPAND(fn(Value))

#define MAP_OUT /* empty! nasty hack for recursion */

// call destination func/macro
#define MAP_NEXT_2(...)\
    MAP_CALL(EXPAND(ARG_2(__VA_ARGS__)), EXPAND(ARG_3(__VA_ARGS__))) \
    EXPAND(ARG_1(__VA_ARGS__)) \
    MAP_OUT \
    (EXPAND(ARG_2(__VA_ARGS__)), EXPAND(OTHER_3(__VA_ARGS__)))

#define MAP_NEXT_0(...) /* end mapping */

// run foreach mapping... 1st arg must be function/macro with one input argument
#define MAP(...)    EVAL(MAP_A(__VA_ARGS__))

#else

#define EVAL0(...) __VA_ARGS__
#define EVAL1(...) EVAL0 (EVAL0 (EVAL0 (__VA_ARGS__)))
#define EVAL2(...) EVAL1 (EVAL1 (EVAL1 (__VA_ARGS__)))
#define EVAL3(...) EVAL2 (EVAL2 (EVAL2 (__VA_ARGS__)))
#define EVAL4(...) EVAL3 (EVAL3 (EVAL3 (__VA_ARGS__)))
#define EVAL(...)  EVAL4 (EVAL4 (EVAL4 (__VA_ARGS__)))

#define MAP_END(...)
#define MAP_OUT

#define MAP_GET_END() 0, MAP_END
#define MAP_NEXT0(test, next, ...) next MAP_OUT
#define MAP_NEXT1(test, next) MAP_NEXT0 (test, next, 0)
#define MAP_NEXT(test, next)  MAP_NEXT1 (MAP_GET_END test, next)

#define MAP0(f, x, peek, ...) f(x) MAP_NEXT (peek, MAP1) (f, peek, __VA_ARGS__)
#define MAP1(f, x, peek, ...) f(x) MAP_NEXT (peek, MAP0) (f, peek, __VA_ARGS__)
#define MAP(f, ...) EVAL (MAP1 (f, __VA_ARGS__, (), 0))

#endif

#endif
