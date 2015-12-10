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

#include <sys/mman.h>
#include <cxxabi.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <pthread.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <string>
#include <map>
#include <iostream>

#include "libdynaguard.h"

/* (glibc) interposition prototypes */
sighandler_t __sys_signal_handler                                       = NULL;
void        (*__sys_sigaction_handler)(int, siginfo_t *, void *)        = NULL;
void *      (*__sys_start_routine)(void *)                              = NULL;

/* associative map: thread-id to per-thread context; lock-protected */
std::map<pthread_t, uintptr_t> tid_tls_map;
pthread_mutex_t                tmutex;

unsigned long pg_sz;     /* page size (in bytes)                    */
uintptr_t     main_tls;  /* TLS base (for main thread)              */

void cleanup_dynaguard(void *);

/* 
 * Update the canary in the TLS with a fresh value.
 */
static void
renew_canary(void)
{
  union {
    uintptr_t num;
    unsigned char bytes[sizeof(uintptr_t)];
  } ret;
  ssize_t reslen;
  const ssize_t filllen = sizeof(ret.bytes) - 1;
  int fd; /* file descriptor for /dev/urandom */

  ret.num = 0;
  fd = open(URANDOM_PATH, O_RDONLY);
  if (fd >= 0) {
    reslen = read(fd, ret.bytes + 1, filllen);
    if (unlikely(reslen != filllen)) {
      perror("DynaGuard: reading from the random device failed (renew_canary");
      close(fd);
      exit(EXIT_FAILURE);
    }
  }
  close(fd);

  /* update the value in the TLS */
  SET_DYNA_STACK_GUARD(ret.num);
}

/*
 * Resize the CAB.
 */
static void
resize_cab(uintptr_t *tls, uintptr_t *cab, uintptr_t cab_sz)
{
  uintptr_t *ncab;
  
  if (unlikely(mprotect((void *)((uintptr_t)cab + cab_sz - pg_sz),
               pg_sz,
               PROT_READ | PROT_WRITE) == -1)) {
    perror("DynaGuard: mprotect(2) failed (resize_cab)");
    exit(EXIT_FAILURE);
  }

  /* increase the CAB size */
  cab_sz += pg_sz;

  /* resize */
  cab = (uintptr_t *)realloc(cab, cab_sz);
  if (unlikely(cab == NULL)) {
    perror("DynaGuard: CAB re-allocation failed (resize_cab)");
    exit(EXIT_FAILURE);
  }

  /* check if realloc(3) returned memory which is not page-aligned */
  if (((uintptr_t)cab & (pg_sz - 1))) {

    /* 
     * if the CAB is not page-aligned, allocate a new memory region,
     * copy the data over, and free the memory allocated by realloc(3)
     */
    if (unlikely(posix_memalign((void **)&ncab, pg_sz, cab_sz) != 0)) {
      perror("DynaGuard: CAB allocation failed (resize_cab)");
      exit(EXIT_FAILURE);
    }

    /* copy data over */
    memcpy(ncab, cab, cab_sz - (pg_sz << 1));

    /* free the memory allocated by realloc(3) */
    free(cab);

    /* update the CAB pointer */
    cab = ncab;
  }

  /* write-protect the last page for dynamically resizing the CAB */
  if (unlikely(mprotect((void *)((uintptr_t)cab + cab_sz - pg_sz),
               pg_sz,
               PROT_READ) == -1)) {
    perror("DynaGuard: mprotect(2) failed (resize_cab)");
    exit(EXIT_FAILURE);
  }

  /* update the TLS entries */
  *(uintptr_t **)((uintptr_t)tls + CAB_OFFSET) = cab;
  *(uintptr_t *)((uintptr_t)tls + CAB_SZ)      = cab_sz;
}

/*
 *  Helper routine for `__dyna_sighandler' and `__dyna_sigsegv_handler'.
 */
static bool
__dyna_segfault(uintptr_t *faddr)
{
  std::map<pthread_t, uintptr_t>::iterator it; /* thread iterator */
  uintptr_t *t_cab;    /* CAB */
  uintptr_t t_cab_sz;  /* CAB size */

  /* examine if segfault came from main thread */
  t_cab    = *(uintptr_t **)(main_tls + CAB_OFFSET);
  t_cab_sz = *(uintptr_t *)(main_tls + CAB_SZ);
  if ((uintptr_t)faddr == ((uintptr_t)t_cab + t_cab_sz - pg_sz)) {
    resize_cab((uintptr_t *)main_tls, t_cab, t_cab_sz);
    return true;
  }

  /* check if SIGSEGV is because of DynaGuard in any of the other threads */
  pthread_mutex_lock(&tmutex);
  for (it = tid_tls_map.begin(); it != tid_tls_map.end(); it++) {
    t_cab    = *(uintptr_t **)(it->second + CAB_OFFSET);
    t_cab_sz = *(uintptr_t *)(it->second + CAB_SZ);
    if ((uintptr_t)faddr == ((uintptr_t)t_cab + t_cab_sz - pg_sz)) {
      pthread_mutex_unlock(&tmutex);
      resize_cab((uintptr_t *)it->second, t_cab, t_cab_sz);
      return true;
    }
  }
  pthread_mutex_unlock(&tmutex);

  return false;
}

/*
 * DynaGuard SIGSEGV handler.
 */
static void
__dyna_sigsegv_handler(int signum, siginfo_t *siginfo, void *context)
{
  if (!__dyna_segfault((uintptr_t *)siginfo->si_addr)) {
    if (__sys_sigaction_handler != NULL)
       __sys_sigaction_handler(signum, siginfo, context);
    else if (__sys_signal_handler != NULL)
       __sys_signal_handler(signum);
  }
}

/*
 * Unwind the CAB.
 *
 * Pop all the canary pointers that point at
 * stack locations (addresses) below the new
 * stack pointer.
 *
 * @sptr: in the case of a (sig)longjmp, the new stack pointer, else 0
 */
static void
__dyna_unwind_cab(uintptr_t sptr)
{
  uintptr_t *cab;          /* CAB */
  uintptr_t cab_idx;       /* current index in CAB    */

  /* get the CAB */
  GET_CAB(cab);
 
  /* get the CAB idx */
  GET_CAB_IDX(cab_idx);

  /* get current stack pointer (if none was passed) */
  if (!sptr)
    GET_STACK_PTR(sptr);

  /* unwind the stack */
  while (cab_idx > 0) {
    if (sptr <= *(cab + (cab_idx - 1)))
      break;
    cab_idx--;
  }

  /* update the index in the TLS to reflect the changes */
  SET_CAB_IDX(cab_idx);
}

/*
 * pthread_create(3) helper: wraps the `start_routine' of the
 * newly-created thread to setup the TLS entries accordingly.
 */
static void *
__dyna_start_routine(void *darg)
{
  void      *ret;       /* return value                 */
  uintptr_t cab_sz;     /* size of CAB                  */
  uintptr_t *cab;       /* CAB                          */
  uintptr_t tls;        /* TLS address (current thread) */

  /* FIXME: ugly argument passing */
  void * (*__sys_start_routine)(void *) =
	  (void * (*)(void *))((dyna_arg_t *)darg)->fptr;
  void *arg = (void *)((dyna_arg_t *)darg)->arg;
  free((dyna_arg_t *)darg);

  /* get the TLS */
  GET_TLS(tls);

  /* add the current thread to the associative map */
  pthread_mutex_lock(&tmutex);
  tid_tls_map[pthread_self()] = tls;
  pthread_mutex_unlock(&tmutex);

  /* allocate space for the new CAB */
  cab_sz = pg_sz * CAB_PAGES;
  if (unlikely(posix_memalign((void **)&cab, pg_sz, cab_sz) != 0)) {
    perror("DynaGuard: CAB allocation failed (__dyna_start_routine)");
    exit(EXIT_FAILURE);
  }

  /* write-protect the last page for dynamically resizing the CAB */
  if (unlikely(mprotect((void *)((uintptr_t)cab + cab_sz - pg_sz),
               pg_sz,
               PROT_READ) == -1)) {
    perror("DynaGuard: mprotect(2) failed (__dyna_start_routine)");
    exit(EXIT_FAILURE);
  }

  /* initialize the CAB entries in the TLS and setup a new canary */
  SET_CAB(cab);
  SET_CAB_IDX(0);
  SET_CAB_SZ(cab_sz);
  
  /* get a fresh canary */
  renew_canary();

  /* register a cleanup callback for this thread */
  pthread_cleanup_push(cleanup_dynaguard, NULL);

  /* start the (original) main routine */
  ret = __sys_start_routine(arg);

  /* cleanup DynaGuard's CAB */
  pthread_cleanup_pop(1);

  /* done */
  return ret;
}

/*
 * Cleanup routine: upon a fork(), cleanup the `tid_tls_map' that
 * was copied to the child process due to copy-on-write (COW).
 * Free all copied CABs except for the thread that invoked fork(2)
 * and erase the respective entries from the map.
 */
static void
thread_cab_free(void)
{
  uintptr_t *cab;     /* CAB address                  */
  uintptr_t this_tls; /* TLS address (current thread) */
  std::map<pthread_t, uintptr_t>::iterator it; /* iterator */

  /* get the TLS address of the current (child) process */
  GET_TLS(this_tls);
  
  /* update the global tls for main process */
  main_tls = this_tls;

  for (it = tid_tls_map.begin(); it != tid_tls_map.end(); it++) {
    /* 
     * free the CAB for all threads except the
     * one that forked the current child process
     */
    cab = *(uintptr_t **)(it->second + CAB_OFFSET);
    if (likely(cab != NULL && it->second != this_tls))
      free(cab);

    /* cleanup */
    tid_tls_map.erase(it);
  }
}

/*
 * Update the canaries after a fork(2). 
 */
static void
update_canaries(void)
{
  uintptr_t i;          /* iterator */
  uintptr_t *cab;       /* CAB */
  uintptr_t cab_idx;    /* current index in the CAB */
  uintptr_t canary;     /* the canary value */

  /* change the canary in the TLS */
  renew_canary();

  /* get the new canary from the TLS */
  GET_DYNA_STACK_GUARD(canary);
  
  /* get the CAB */
  GET_CAB(cab);
  
  /* get the CAB idx */
  GET_CAB_IDX(cab_idx);

  /*
   * Unwind the stack and change the canaries in the inherited
   * frames. Notice that we don't remove entries from the CAB
   * as we may call fork(2) again and bestow them to the child.
   */
  for (i = 0; i < cab_idx; i++)
    /* paranoid */
    if (likely(*(cab + i)))
      *(uintptr_t *)(*(cab + i)) = canary;
}

/*
 * signal(2) hook.
 */
sighandler_t
signal(int signum, sighandler_t handler)
{
  sighandler_t __prev_handler; /* previous signal handler */

  typedef sighandler_t (*fptr) (int signum, sighandler_t handler);
  static fptr __sys_signal = NULL;

  if (unlikely(!__sys_signal &&
		  !(__sys_signal = (fptr) dlsym(RTLD_NEXT, "signal")))) {
    perror("DynaGuard: failed to locate signal(2)");
    exit(EXIT_FAILURE);
  }

  /* do it */
  if (signum != SIGSEGV)
    return __sys_signal(signum, handler);

  /* save the signal handler */
  __prev_handler       = __sys_signal_handler;
  __sys_signal_handler = handler;

  /* return the previous signal handler */
  return __prev_handler;
}

/*
 * sigaction(2) hook.
 */
int
sigaction(int signum, const struct sigaction *act,
              struct sigaction *oldact)
{
  typedef int (*fptr) (int signum, const struct sigaction *act,
                        struct sigaction *oldact);
  static fptr __sys_sigaction = NULL;

  if (unlikely(!__sys_sigaction &&
		  !(__sys_sigaction = (fptr) dlsym(RTLD_NEXT, "sigaction")))) {
    perror("DynaGuard: failed to locate sigaction(2)");
    exit(EXIT_FAILURE);
  }

  /* do it */
  if (signum != SIGSEGV)
    return __sys_sigaction(((signum == -SIGSEGV) ? -signum : signum),
                           act,
                           oldact);

  /* save the signal handler */
  if (act)
	  __sys_sigaction_handler = act->sa_sigaction;

  /* success */
  return __sys_sigaction(signum, NULL, oldact);
}

/*
 * C++ exception handling hook.
 */
extern "C" void
__cxxabiv1::__cxa_end_catch(void)
{
  typedef void (*fptr)(void);
  static fptr __sys_cxa_end_catch = NULL;

  if (unlikely(!__sys_cxa_end_catch &&
  	!(__sys_cxa_end_catch = (fptr) dlsym(RTLD_NEXT, "__cxa_end_catch")))) {
    perror("DynaGuard: failed to locate __cxa_end_catch");
    exit(EXIT_FAILURE);
  }

  __dyna_unwind_cab(0);

  __sys_cxa_end_catch();
}

/*
 * siglongjmp(3) hook.
 */
void
siglongjmp(sigjmp_buf env, int val)
{
  uintptr_t nsptr; /* stack pointer (after longjmp(3)) */
  typedef void (*fptr) (sigjmp_buf env, int val);
  static fptr __sys_siglongjmp = NULL;

  if (unlikely(!__sys_siglongjmp &&
		 !(__sys_siglongjmp = (fptr) dlsym(RTLD_NEXT, "siglongjmp")))) {
    perror("DynaGuard: failed to locate siglongjmp(3)");
    exit(EXIT_FAILURE);
  }

  /* get the value of the stack pointer after the `jmp' from jump buffer */
  DEMANGLE_RSP(env->__jmpbuf[JB_RSP], nsptr);

  /* unwind the CAB (prior to calling siglongjmp(3)) */
  __dyna_unwind_cab(nsptr);
  
  /* do the actual stack unwinding */
  __sys_siglongjmp(env, val);
  
  /* noreturn */
  __builtin_unreachable();
}

/*
 * longjmp(3) hook.
 */
void
longjmp(jmp_buf env, int val)
{
  uintptr_t nsptr; /* stack pointer (after longjmp(3)) */
  typedef void (*fptr) (jmp_buf env, int val);
  static fptr __sys_longjmp = NULL;

  if (unlikely(!__sys_longjmp &&
		  !(__sys_longjmp = (fptr) dlsym(RTLD_NEXT, "longjmp")))) {
    perror("DynaGuard: failed to locate longjmp(3)");
    exit(EXIT_FAILURE);
  }

  /* get the value of the stack pointer after the `jmp' from jump buffer */
  DEMANGLE_RSP(env->__jmpbuf[JB_RSP], nsptr);

  /* unwind the CAB (prior to calling longjmp(3)) */
  __dyna_unwind_cab(nsptr);
  
  /* do the actual stack unwinding */
  __sys_longjmp(env, val);
  
  /* noreturn */
  __builtin_unreachable();
}

/*
 * pthread_create(3) hook.
 */
int
pthread_create(pthread_t *thread,
               const pthread_attr_t *attr,
               void *(*start_routine)(void *),
               void *arg)
{
  typedef int (*fptr) (pthread_t *thread,
                       const pthread_attr_t *attr,
                       void *(*start_routine)(void *),
                       void *arg);
  static fptr __sys_pthread_create = NULL;
  dyna_arg_t *darg = NULL;

  /* get the actual (POSIX threads) pthread_create(3) */
  if (unlikely(!__sys_pthread_create &&
	!(__sys_pthread_create = (fptr) dlsym(RTLD_NEXT, "pthread_create")))) {
    perror("DynaGuard: failed to locate pthread_create(3)");
    exit(EXIT_FAILURE);
  }

  /* FIXME: ugly argument passing */
  if (unlikely((darg = (dyna_arg_t *)malloc(sizeof(dyna_arg_t))) == NULL)) {
    perror("DynaGuard: failed to allocate dyna_arg_t (pthread_create)");
    exit(EXIT_FAILURE);
  }

  /* original `start_routine' and its argument */
  darg->fptr = (uintptr_t *)start_routine;
  darg->arg  = (uintptr_t *)arg; 

  /* do it */
  return __sys_pthread_create(thread,
                              attr,
                              __dyna_start_routine,
                              darg);
}

/*
 * fork(2) hook.
 */
pid_t
fork(void)
{
  typedef pid_t (*fptr) (void);
  static fptr __sys_fork = NULL;
  pid_t pid;

  /* get the actual (glibc) fork(2) */
  if (unlikely(!__sys_fork &&
			  !(__sys_fork = (fptr) dlsym(RTLD_NEXT, "fork")))) {
    perror("DynaGuard: failed to locate fork(2)");
    exit(EXIT_FAILURE);
  }

  /* do it */
  if ((pid = __sys_fork()) == 0) {
    /* 
     * cleanup the CABs in the rest
     * of the threads and start with
     * a fresh `tid_tls_map'
     */
    thread_cab_free();
   
    /* update the canaries */
    update_canaries();
  }

  /* done */
  return pid;
}

/*
 * Destructor: perform the necessary cleanup upon exit (per-thread).
 */
/* __attribute__((destructor)) */ void
cleanup_dynaguard(void *arg)
{
  uintptr_t *cab;  /* CAB address */
  std::map<pthread_t, uintptr_t>::iterator it; /* iterator */

  /* get the per-thread context */
  pthread_mutex_lock(&tmutex);
  if (unlikely((it = tid_tls_map.find(pthread_self())) == tid_tls_map.end())) {
    /* already handled; paranoid */
    pthread_mutex_unlock(&tmutex);
    return;
  }

  /* cleanup */
  tid_tls_map.erase(it);
  pthread_mutex_unlock(&tmutex);

  GET_CAB(cab);
  if (likely(cab != NULL))
    free(cab);
}

/*
 * Constructor (called before `main'): setup DynaGuard's canary and initialize
 * the entries in TLS related to the canary address buffer (CAB) .
 */
__attribute__((constructor)) void
setup_dynaguard(void)
{
  uintptr_t        *cab;    /* CAB address */
  uintptr_t        cab_sz;  /* CAB size    */
  struct sigaction dyna_sa; /* DynaGuard's signal handler for SIGSEGV */

  /* allocate space for the CAB */
  pg_sz  = sysconf(_SC_PAGESIZE);
  cab_sz = pg_sz * CAB_PAGES;
  if (unlikely(posix_memalign((void **)&cab, pg_sz, cab_sz) != 0)) {
    perror("DynaGuard: CAB allocation failed (ctor)");
    exit(EXIT_FAILURE);
  }

  /* write-protect the last page for dynamically resizing the CAB */
  if (unlikely(mprotect((void *)((uintptr_t)cab + cab_sz - pg_sz),
               pg_sz,
               PROT_READ) == -1)) {
    perror("DynaGuard: mprotect(2) failed (ctor)");
    exit(EXIT_FAILURE);
  }

  /* initialize the CAB entries in the TLS and setup a new canary */
  SET_CAB(cab);
  SET_CAB_IDX(0);
  SET_CAB_SZ(cab_sz);

  /* get a fresh canary */
  renew_canary();

  /* store the TLS base to access it globally */
  GET_TLS(main_tls);

  /* 
   * register the signal handler for
   * handling any fill-up of the CAB
   */
  memset(&dyna_sa, 0, sizeof(dyna_sa));
  dyna_sa.sa_flags      = SA_SIGINFO;
  dyna_sa.sa_sigaction  = __dyna_sigsegv_handler;

  if (unlikely(sigaction(-SIGSEGV, &dyna_sa, NULL) == -1)) {
    perror("DynaGuard: sigaction(2) failed");
    exit(EXIT_FAILURE);
  }
}
