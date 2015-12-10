/*
 * Copyright (c) 2015, Columbia University
 *
 * This software was developed by Theofilos Petsios <theofilos@cs.columbia.edu>
 * at Columbia University, New York, NY, USA, in May 2015.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __LIBDYNAGUARD_H__
#define __LIBDYNAGUARD_H__

#include "offsets.h"

/* urandom device path */
#define URANDOM_PATH    "/dev/urandom"

/* compiler directives for branch prediction */
#define likely(x)       __builtin_expect((x), 1)
#define unlikely(x)     __builtin_expect((x), 0)

/*==================================================================*/
/*                                                                  */
/*                              DEBUG                               */
/*                                                                  */
/*==================================================================*/

#define DEBUG	0

/* debug printing */
#define P_PTR(PTR, x)	printf(PTR ": 0x%016lx\n", (x));
#define P(...)		{ printf("[+] " __VA_ARGS__); printf("\n"); }

#if	(DEBUG)
#define D(...)		P(__VA_ARGS__)
#define DPTR(...)	P_PTR(__VA_ARGS__)
#else
#define D(...)
#define DPTR(...)
#endif

typedef struct {
	uintptr_t *fptr;
	uintptr_t *arg;
} dyna_arg_t;

/*==================================================================*/
/*                                                                  */
/*                          ARCH-SPECIFIC                           */
/*                                                                  */
/*==================================================================*/

#if     defined(__i386__)
/* TODO: 32-bit */
#error  "Unsupported architecture"
#elif   defined(__x86_64__)
#define GET_STACK_PTR(x)          \
    asm volatile ("mov %%rsp, %0" : "=r" (x));
/*
 * getter & setter functions for TLS data
 */
/* canary used by DynaGuard */
#define GET_TLS(x)                \
    asm volatile ("mov %%fs:0x0, %0" : "=r" (x));

#define SET_DYNA_STACK_GUARD(x)   \
    asm volatile ("mov %0, %%fs:" CAN_TLS_OFFSET_STR ""::"r" (x) : "memory");
#define GET_DYNA_STACK_GUARD(x)   \
    asm volatile ("mov %%fs:" CAN_TLS_OFFSET_STR  ", %0" : "=r" (x));
/* address of DynaGuard's canary address buffer (CAB) */
#define GET_CAB(x)                \
    asm volatile ("mov %%fs:" CAB_TLS_OFFSET_STR ", %0" : "=r" (x));
#define SET_CAB(x)                \
    asm volatile ("mov %0, %%fs:" CAB_TLS_OFFSET_STR ""::"r" (x) : "memory");
/* idx in DynaGuard's canary stack; how many elements are currently stored */
#define GET_CAB_IDX(x)            \
    asm volatile ("mov %%fs:" CAB_IDX_TLS_OFFSET_STR ", %0" : "=r" (x));
#define SET_CAB_IDX(x)            \
    asm volatile ("mov %0, %%fs:" \
                  CAB_IDX_TLS_OFFSET_STR ""::"r" (x) : "memory");
/* total size of DynaGuard's CAB */
#define GET_CAB_SZ(x)             \
    asm volatile ("mov %%fs:" CAB_SZ_TLS_OFFSET_STR ", %0" : "=r" (x));
#define SET_CAB_SZ(x)             \
    asm volatile ("mov %0, %%fs:" \
                  CAB_SZ_TLS_OFFSET_STR ""::"r" (x) : "memory");

#define JB_RSP    6   /* RSP position in jump buffer */
/* JB_RSP * 0x8 = 0x30 -> xor with TLS pointer_guard to
 * get the value of RSP. We use r14 as it is a reserved register */
#define DEMANGLE_RSP(mangled, demangled)      \
    asm volatile ("mov %1, %%r14\n\t"         \
                  "ror $0x11, %%r14\n\t"      \
                  "xor %%fs:0x30, %%r14\n\t"  \
                  "mov %%r14, %0\n\t"         \
                  : "=r" (demangled)          \
                  : "r" (mangled)             \
                  : "%r14", "memory"          \
                  );
#else
#error  "Unsupported architecture"
#endif

#endif  /* LIBDYNAGUARD_H */
