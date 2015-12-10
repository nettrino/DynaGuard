/*
 * Copyright (c) 2015, Columbia University
 * All rights reserved.
 *
 * This software was developed by Theofilos Petsios <theofilos@cs.columbia.edu>
 * and Vasileios P. Kemerlis <vpk@cs.columbia.edu> at Columbia University,
 * New York, NY, USA, in May 2015.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *   * Neither the name of Columbia University nor the
 *     names of its contributors may be used to endorse or promote products
 *     derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * 12/08/2015:
 * 	Added support for dynamically updating the canaries upon thread
 * 	creation -- every thread runs with a fresh canary.
 * 
 * 		-- Vasileios P. Kemerlis (vpk@cs.brown.edu)
 * 		   Brown University, Providence, RI. 
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <bsd/stdlib.h>

#include <map>

#include "dynaguard.h"
#include "pin.H"

/*
 * thread_ctx_ptr: thread context pointer (TLS emulation)
 *
 * we spill a register for emulating TLS-like storage; thread_ctx_ptr
 * holds the address of a per-thread context structure
 */
REG thread_ctx_ptr;

/* page size (in bytes) */
size_t page_sz;

/* associative map: thread-id to per-thread context; lock-protected */
map<THREADID, thread_ctx_t*> tid_ctx_map;

/*
 * canary generator
 *
 * use the kernel random device (/dev/urandom) to compute a new canary value;
 * if such a device is not available, then fallback to using the arc4 cipher
 *
 */
static canary_t
rnd_canary(void)
{
	/* new canary value	*/
	canary_t ncanary	= 0;

	/* kernel random device	*/
	FILE *fp		= NULL;

	/* open urandom & get a new canary value */
	if (unlikely(((fp = fopen(URANDOM_PATH, "r")) == NULL) ||
			(fread(&ncanary, sizeof(canary_t), 1, fp) != 1))) {
		/* failed */

		/* fallback: get a new random canary using the arc4 cipher */
#if	defined(__x86_64__)
		ncanary	= (arc4random() & MASK_VAL);
		ncanary	<<= SHIFT_VAL;
		ncanary	|= (arc4random() & MASK_VAL);
#elif	defined(__i386__)
		ncanary	= arc4random();
#endif
	}

	/* cleanup */
	if (likely(fp != NULL))
		fclose(fp);

	/* done */
	return ncanary;
}

/*
 * update all the stored canaries
 * with a new random value
 *
 * @tid:	thread id
 * @ctx:	CPU context
 *   @v:	callback value
 */
static VOID
update_canaries(THREADID tid, const CONTEXT *ctx, VOID *v)
{
	/* iterators					*/
	map<THREADID, thread_ctx_t*>::iterator it;
	unsigned long i;

	/* new canary value				*/
	canary_t ncanary = rnd_canary();

	/* get the thread context			*/
	thread_ctx_t *tctx =
		(thread_ctx_t *)PIN_GetContextReg(ctx, thread_ctx_ptr);

	/* get the TLS base				*/
	unsigned long tls = PIN_GetContextReg(ctx, TLS_BASE);

	/* update the canary in TLS			*/
	*(canary_t *)(tls + CAN_SEG_REG_OFFSET) = ncanary;

	/* update the canaries in (process) stack	*/
	for (i = 0; i < tctx->cstack_idx; i++)
		*tctx->cstack[i] = ncanary;

	/* cleanup					*/
	for (	it = tid_ctx_map.begin();
		it != tid_ctx_map.end();
		++it	) {
		/* skip self */
		if (unlikely(it->first == tid))
			continue;

		free(it->second->cstack);
		free(it->second);
		tid_ctx_map.erase(it);
	}
}

/*
 * unwind the per-thread array/stack (analysis function)
 *
 * pop all the canary pointers that point at
 * stack locations (addresses) below the new
 * stack pointer
 *
 * @tctx:	per-thread context
 *   @sp:	stack pointer value
 */
static void PIN_FAST_ANALYSIS_CALL
unwind_stack(thread_ctx_t *tctx, canary_t *sp)
{
	while (tctx->cstack_idx > 0) {
		if (sp <= tctx->cstack[tctx->cstack_idx - 1])
			break;
		tctx->cstack_idx--;
	}
}

/*
 * check if a memory offset corresponds
 * to the canary offset (analysis function)
 *
 * @tctx:	per-thread context
 *   @ea:	effective address of memory read
 *
 * returns:	1 if `ea' is a valid canary offset, 0 otherwise
 */
static ADDRINT PIN_FAST_ANALYSIS_CALL
valid_offset(thread_ctx_t *tctx, ADDRINT *ea)
{
	return (ea != NULL && *ea == CAN_SEG_REG_OFFSET);
}

/*
 * resize the per-thread array/stack (analysis function)
 *
 * @tctx:	per-thread context
 */
static void PIN_FAST_ANALYSIS_CALL
resize_stack(thread_ctx_t *tctx)
{
	/* original array/stack				*/
	canary_t **tcstack = tctx->cstack;

	/* increase the array/stack size by a page	*/
	tctx->cstack_sz += page_sz;

	tctx->cstack = (canary_t **) realloc(tctx->cstack, tctx->cstack_sz);
	if (unlikely(tctx->cstack == NULL)) {
		/* error message */
		LOG(string(__func__)			+
        		": realloc (cstack) failed ("	+
			strerror(errno)			+
			")\n");

		/* no need for cleanup; the detach callback will do the job  */

		/* restore the original array/stack */
		tctx->cstack = tcstack;

		/* run naked */
		PIN_Detach();
	}
}

/*
 * pop a canary address from the
 * per-thread array/stack (analysis function)
 *
 * @tctx:	per-thread context
 */
static void PIN_FAST_ANALYSIS_CALL
pop_canary_addr(thread_ctx_t *tctx)
{
	tctx->cstack_idx--;
}

/*
 * push a canary address on the
 * per-thread array/stack (analysis function)
 *
 * append the address of a canary on the
 * per-thread array/stack and resize it
 * in case of an overflow
 *
 * @tctx:	per-thread context
 * @cptr:	canary address
 */
static void PIN_FAST_ANALYSIS_CALL
push_canary_addr2(thread_ctx_t *tctx, canary_t *cptr)
{
	/* push			*/
	tctx->cstack[tctx->cstack_idx++] = cptr;

	/* check for overflow	*/
	if (unlikely((tctx->cstack_idx * sizeof(canary_t *)) >=
				tctx->cstack_sz))
		/* resize the array/stack */
		resize_stack(tctx);
}

/*
 * push a canary address on the
 * per-thread array/stack (analysis function)
 *
 * append the address of a canary on the
 * per-thread array/stack and check for overflow
 *
 * @tctx:	per-thread context
 * @cptr:	canary address
 *
 * returns:	1 if the array/stack is full, 0 otherwise
 */
static ADDRINT PIN_FAST_ANALYSIS_CALL
push_canary_addr(thread_ctx_t *tctx, canary_t *cptr)
{
	/* push			*/
	tctx->cstack[tctx->cstack_idx++] = cptr;

	/* check for overflow	*/
	return ((tctx->cstack_idx * sizeof(canary_t *)) >= tctx->cstack_sz);
}

/*
 * trace instrumentation
 *
 * @trace:	the trace to inspect and instrument
 *    @v:	callback value
 */
static VOID
trace_instr(TRACE trace, VOID *v)
{
	/* temporaries */
	BBL bbl;
	INS ins, next_ins;

	for(	bbl = TRACE_BblHead(trace);
		BBL_Valid(bbl);
		bbl = BBL_Next(bbl)	) {
	
		for(	ins = BBL_InsHead(bbl);
			INS_Valid(ins);
			ins = INS_Next(ins)	) {

			/* get the succeeding (next) instruction	*/
			next_ins = INS_Next(ins);

			/* paranoid					*/
			if (!INS_Valid(next_ins))
				/* continue with the next instruction	*/
				continue;

			/* "push canary" */
			if (	/* has segment prefix			*/
				INS_SegmentPrefix(ins)			&&
				/* segment is FS/GS			*/
				INS_SegmentRegPrefix(ins) == CAN_SEG_REG&&
				/* is a `mov'				*/
				INS_IsMov(ins)				&&
				/* destination operand is a register	*/
				INS_OperandIsReg(ins, 0)		&&
				/* valid destination register		*/
				/* REG_valid(INS_RegW(ins, 0)) &&	*/
				/* source operand is memory		*/
				INS_OperandIsMemory(ins, 1)		&&
				/* next instruction is (also) a `mov'	*/
				INS_IsMov(next_ins)			&&
				/*
				 * the source operand of next
				 * instruction is a register
				 */
				INS_OperandIsReg(next_ins, 1)		&&
				/*
				 * the destination operand of
				 * next instruction is memory
				 */
				INS_OperandIsMemory(next_ins, 0)	&&
				/*
				 * the destination operand (register)
				 * of the current instruction is the
				 * source operand of the next instruction
				 */
				INS_RegW(ins, 0) ==
#if defined(__x86_64__)
					INS_RegR(next_ins, 1)
#elif	defined(__i386__)
					INS_RegR(next_ins, 2)
#endif
				) {
				/* fixed offset (0x28/0x14) */
				if (INS_MemoryDisplacement(ins) ==
						CAN_SEG_REG_OFFSET) {
					/*
					 * conditional instrumentation
					 *
					 * if (fast) path:
					 * push the address of the stack canary
					 * in the per-thread array/stack and
					 * check for overflows
					 */
					INS_InsertIfPredicatedCall(
						next_ins,
						IPOINT_BEFORE,
						(AFUNPTR)push_canary_addr,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
						IARG_MEMORYWRITE_EA,
						IARG_END);
					/*
					 * else (slow) path:
 					 * resize the per-thread array/stack
 					 */
					INS_InsertThenPredicatedCall(
						next_ins,
						IPOINT_BEFORE,
						(AFUNPTR)resize_stack,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
						IARG_END);
				}
				else {	/* variable offset */
					/*
					 * conditional instrumentation
					 *
					 * if (fast) path:
					 * get the offset value
					 */
					INS_InsertIfPredicatedCall(
						ins,
						IPOINT_BEFORE,
						(AFUNPTR)valid_offset,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
						IARG_MEMORYREAD_EA,
						IARG_END);
					/*
					 * else (slow) path:
					 * push the address of the stack canary
					 * in the per-thread array/stack and
					 * check for overflows
					 */
					INS_InsertThenPredicatedCall(
						next_ins,
						IPOINT_BEFORE,
						(AFUNPTR)push_canary_addr2,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
						IARG_MEMORYWRITE_EA,
						IARG_END);
				}
				/* continue with the next instruction */
				continue;
			}

			/* "pop canary" */
			if (	/* is a `mov'				*/
				INS_IsMov(ins)				&&
				/* next instruction is a `xor'		*/
				INS_Opcode(next_ins) == XED_ICLASS_XOR	&&
				/* next instruction has a segment prefix*/
				INS_SegmentPrefix(next_ins)		&&
				/* segment is FS/GS			*/
				INS_SegmentRegPrefix(next_ins) ==
					CAN_SEG_REG			&&
				/* fixed offset (0x28/0x14)		*/
				INS_MemoryDisplacement(next_ins) ==
					CAN_SEG_REG_OFFSET		&&
				/* destination operand is a register	*/
				INS_OperandIsReg(ins, 0)		&&
				/* source operand is memory		*/
				INS_OperandIsMemory(ins, 1)		&&
				/*
				 * the destination operand of next
				 * instruction is a register
				 */
				INS_OperandIsReg(next_ins, 0)		&&
				/* valid source register		*/
				/* REG_valid(INS_RegW(ins, 0))	&&	*/
				/*
				 * the destination operand (register)
				 * of the current instruction is the
				 * destination operand of the next instruction
				 */
				INS_RegW(ins, 0) == INS_RegR(next_ins, 0)) {
			
					INS_InsertPredicatedCall(
						ins,
						IPOINT_BEFORE,
						(AFUNPTR)pop_canary_addr,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
						IARG_END);

					/* continue with the next instruction */
					continue;
			}

			/* stack unwinding */
			if (	/* is a `mov'				*/
				INS_IsMov(ins)				&&
				/* destination operand is a register	*/
				INS_OperandIsReg(ins, 0)		&&
				/*
				 * the destination register is
				 * the stack pointer
				 */
				INS_RegW(ins, 0) == REG_STACK_PTR) {

					INS_InsertPredicatedCall(
						ins,
						IPOINT_AFTER,
						(AFUNPTR)unwind_stack,
						IARG_FAST_ANALYSIS_CALL,
						IARG_REG_VALUE, thread_ctx_ptr,
						IARG_REG_VALUE, REG_STACK_PTR,
						IARG_END);
			}
		}
	}
}

/*
 * thread start callback (analysis function)
 *
 * allocate space for the per-thread context
 *
 *   @tid:	thread id
 *   @ctx:	CPU context
 * @flags:	OS specific flags for the new thread
 *     @v:	callback value
 */
static VOID
thread_alloc(THREADID tid, CONTEXT *ctx, INT32 flags, VOID *v)
{
	/* thread context	*/
	thread_ctx_t *tctx;

	/* canary value		*/
	canary_t ncanary;

	/* TLS base		*/
	unsigned long tls;

	/* allocate space for the per-thread context; optimized branch */
	tctx = (thread_ctx_t *) malloc(sizeof(thread_ctx_t));
	if (unlikely(tctx == NULL)) {
		/* error message */
		LOG(string(__func__)				+
			": malloc (thread_ctx_t) failed ("	+
			strerror(errno)				+
			")\n");
	
		/* run naked */
		PIN_Detach();
	}

	/* init */
	tctx->cstack_sz		= page_sz;
	tctx->cstack_idx	= 0;

	tctx->cstack = (canary_t **) malloc(tctx->cstack_sz);
	if (unlikely(tctx->cstack == NULL)) {
		/* error message */
		LOG(string(__func__)				+
			": malloc (cstack) failed ("		+
			strerror(errno)				+
			")\n");

		/* cleanup	*/
		free(tctx);

		/* run naked	*/
		PIN_Detach();
	}

	/* save the address of the per-thread context to the spilled register */
	PIN_SetContextReg(ctx, thread_ctx_ptr, (ADDRINT)tctx);

	/* update the map; add */
	tid_ctx_map[tid] = tctx;

	/* new canary value		*/
	ncanary = rnd_canary();

	/* get the TLS base		*/
	tls = PIN_GetContextReg(ctx, TLS_BASE);

	/* update the canary in TLS	*/
	if (tls)
	    *(canary_t *)(tls + CAN_SEG_REG_OFFSET) = ncanary;
}

/*
 * thread finish callback (analysis function)
 *
 * free the space of the per-thread context
 *
 *  @tid:	thread id
 *  @ctx:	CPU context
 * @code:	OS specific termination code for the thread
 *    @v:	callback value
 */
static VOID
thread_free(THREADID tid, const CONTEXT *ctx, INT32 code, VOID *v)
{
	/* iterator			*/
	map<THREADID, thread_ctx_t*>::iterator it;

	/* get the per-thread context	*/
	if (unlikely((it = tid_ctx_map.find(tid)) == tid_ctx_map.end()))
		/* already handled; paranoid */
		return;

	/* cleanup			*/
	free(it->second->cstack);
	free(it->second);

	/* update the map; remove	*/
	tid_ctx_map.erase(it);
}

/*
 * detach callback (analysis function)
 *
 * deallocate the per-thread contexts
 *
 * @v:	callback value
 */
static VOID
detach_cleanup(VOID *v)
{
	/* iterator */
	map<THREADID, thread_ctx_t*>::iterator it;

	/* cleanup */
	for (	it = tid_ctx_map.begin();
		it != tid_ctx_map.end();
		++it	) {
		free(it->second->cstack);
		free(it->second);
		tid_ctx_map.erase(it);
	}
}

/*
 * initialize thread contexts
 *
 * spill a tool register for the thread contexts
 * and register a thread start/finish callback
 * and a detach callback
 *
 * returns: true on success, false on error
 */
static inline bool
thread_ctx_init(void)
{
	/* claim a tool register; optimized branch */
	if (unlikely(
		(thread_ctx_ptr = PIN_ClaimToolRegister()) == REG_INVALID())) {
		/* error message	*/
		LOG(string(__func__) + ": PIN_ClaimToolRegister failed\n");

		/* failed		*/
		return false;
	}

	/* register a detach callback	*/
	PIN_AddDetachFunction(detach_cleanup, NULL);

	/*
	 * thread start/finish hooks
	 *
	 * keep track of the threads and allocate/free
	 * space for the per-thread logistics
	 */
	PIN_AddThreadStartFunction(thread_alloc, NULL);
	PIN_AddThreadFiniFunction(thread_free, NULL);

	/* success			*/
	return true;
}

/*
 * DynaGuard
 *
 * this simple pintool instruments an x86/x86-64 Linux binary to
 * replace all canaries (both in the stack and TLS) of the child
 * process, with a new random canary value, after fork()
 *
 * NOTE:
 * 	- works with multi-{process, threaded} binaries
 *	- supports only (g)libc canaries
 */
int
main(int argc, char **argv)
{
	/* temporary 			*/
	int psz;

	/* initialize Pin; optimized branch */
	PIN_InitSymbols();

	if (unlikely(PIN_Init(argc, argv))) {
		/* error message	*/
		LOG(string(__func__)		+
			": PIN_Init failed ("	+
			strerror(errno)		+
			")\n");

		/* failed		*/
		return EXIT_FAILURE;
	}

	/* get the page size (in bytes); optimized branch */
	if (unlikely((psz = sysconf(_SC_PAGE_SIZE)) == -1)) {
		/* error message	*/
		LOG(string(__func__)		+
			": sysconf failed ("	+
			strerror(errno)		+
			")\n");

		/* failed		*/
		return EXIT_FAILURE;
	}

	/* update the global		*/
	page_sz = psz;

	/* initialize thread contexts; optimized branch */
	if (unlikely(!thread_ctx_init())) {
		/* error message	*/
		LOG(string(__func__)		+
			": thread_ctx_init failed\n");

		/* failed		*/
		return EXIT_FAILURE;
	}

	/* register a trace callback	*/
	TRACE_AddInstrumentFunction(trace_instr, NULL);

	/* register a fork() callback	*/
	PIN_AddForkFunction(FPOINT_AFTER_IN_CHILD, update_canaries, NULL);

	/* start the program; never returns */
	PIN_StartProgram();

	/* make the compiler happy	*/
	return EXIT_SUCCESS;
}
