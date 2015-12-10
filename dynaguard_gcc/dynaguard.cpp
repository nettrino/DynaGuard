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

#include "dynaguard.h"

#if DEBUG_INSN

static FILE *flog = NULL;

/*
 * start the auditing process
 * open the logfile in appending mode
 */
static void
openlog(void)
{
  char lname[LOG_STR_N];

  /* differet log file per thread */
  memset(lname, 0, LOG_STR_N);
  sprintf(lname, "%s.%d", LOG_STR, getpid());

  /* open the logfile in appending mode */
  if (likely((flog = fopen(lname, "a")) != NULL))
    /* dump information regarding the translation unit */
    (void)fprintf(flog, "[%s]\n", IDENTIFIER_POINTER(DECL_NAME(cfun->decl)));
  else
    /* failed */
    (void)fprintf(stderr, "%s: failed to open %s\n", NAME, lname);
}

/*
 * terminate the auditing process
 *
 * close the logfile
 */
static void
closelog(void)
{
  /* check if logging has been enabled */
  if (flog != NULL) {
    /* dump information regarding the translation unit */
    (void)fprintf(flog, "[/%s]\n", IDENTIFIER_POINTER(DECL_NAME(cfun->decl)));
    /* cleanup */
    (void)fclose(flog);
  }
}

/*
 * do the actual logging
 *
 * print the RTL expression of the inspected instruction; in case of
 * instrumented instructions print an additional discriminator (i.e.,
 * `M' for branches via an unsafe memory location, and `SM`/`R` for
 * branches via safe memory locations or registers)
 *
 * insn:	the instruction to log
 */
static void
commitlog(const rtx insn, const char *msg)
{
  /* check if logging has been enabled */
  if (flog != NULL) {
    (void)fprintf(flog, msg);
    /* dump the instruction */
    print_rtl_single(flog, insn);
  }
}
#endif /* DEBUG LOGGING END */

int plugin_is_GPL_compatible;


/*
 *  Returns a 64-bit register string from an RTX REG expression
 */
static std::string
reg_to_str(rtx reg)
{
  std::string regstr;

  /* if reg is rxx do nothing */
  if (reg_names[REGNO(reg)][0] == 'r')
    regstr = "%%" + std::string(reg_names[REGNO(reg)],
                                strlen(reg_names[REGNO(reg)]));
  else
#ifdef __i386__
    /* if reg is ax, bx etc return the 64-bit version: rax, rbx etc */
    regstr = "%%e" + std::string(reg_names[REGNO(reg)],
                                 strlen(reg_names[REGNO(reg)]));
#elif defined __x86_64__
    /* if reg is ax, bx etc return the 64-bit version: rax, rbx etc */
    regstr = "%%r" + std::string(reg_names[REGNO(reg)],
                                 strlen(reg_names[REGNO(reg)]));
#endif
  return regstr;
}

/*
 * Update canary address buffer upon each canary push in the stack frame
 * Returns: true on success, false on error
 */
static bool
canary_push(rtx *insn)
{
  rtx expr;                     /* sub-expression in PARALLEL */
  rtx canary_addr = NULL_RTX;   /* canary address in the stack */
  char *mov_cstr;               /* char array for assembly insns */
  rtx as;                       /* assembly instructions to be pushed */
  rtx creg;                     /* scratch register */
  rtx lea;
  std::string movstr, r1, r2, r3;

  if (!(GET_CODE(*insn) == INSN               &&
        GET_CODE(PATTERN(*insn)) == PARALLEL  &&
        XVECLEN(PATTERN(*insn), 0) == 3))
    return false;

  expr = XVECEXP(PATTERN(*insn), 0, 0);
  if (expr                                &&
      GET_CODE(expr) == SET               &&
      MEM_P(XEXP(expr, 0))                &&
      GET_CODE(XEXP(expr, 1)) == UNSPEC   &&
      XINT(XEXP(expr, 1), 1) == UNSPEC_SP_TLS_SET) {
    canary_addr = XEXP(XEXP(expr, 0), 0);
  }

  if (canary_addr == NULL_RTX)
   return false;

  movstr = "";
  /* scratch register in which canary is stored
   * we always use registers r11, r12, r13 and spill them for now */
  creg = XEXP(XVECEXP(PATTERN(*insn), 0, 1), 0);
  r1   = reg_to_str(creg);

  r2 = "%%r11";
  r3 = "%%r12";

  if (REGNO(creg) == R11_REG)
    r2 = "%%r13";
  else if (REGNO(creg) == R12_REG)
    r3 = "%%r13";

  /* modify canary check to compare with DynaGuard's canary */
  XVECEXP(XEXP(XVECEXP(PATTERN(*insn), 0, 0), 1), 0, 0) = GEN_INT(CAN_OFFSET);
  /* store the address of the canary in this frame to our spill register */
  lea = emit_insn_before(gen_rtx_SET(DImode,
                                     creg,
                                     canary_addr),
                         *insn);
  /* construct assembly for storing canary address to shadow stack */
  movstr = "pushq " + r2 + "\n\t";
  movstr = movstr + "pushq " + r3 + "\n\t";
  movstr = movstr + "mov %%fs:" CAB_TLS_OFFSET_STR ", " + r2 + "\n\t";
  movstr = movstr + "mov %%fs:" CAB_IDX_TLS_OFFSET_STR ", " + r3 + "\n\t";

  /* store effective address in shadow stack */
  movstr = movstr + "mov " + r1 + ", (" + r2 + "," + r3 + ", 8)\n\t";
  movstr = movstr + "incq %%fs:" CAB_IDX_TLS_OFFSET_STR "\n\t";
  movstr = movstr + "pop " + r3 + "\n\t";
  movstr = movstr + "pop " + r2 + "\n\t";

  /* ugly hack */
  mov_cstr = new char[movstr.length() + 1];
  std::strcpy(mov_cstr, movstr.c_str());

  /* get base of shadow stack */
  as = gen_rtx_ASM_OPERANDS(VOIDmode,
                            mov_cstr,
                            "",
                            0,
                            rtvec_alloc(0),
                            rtvec_alloc(0),
                            rtvec_alloc(0),
                            expand_location(RTL_LOCATION(lea)).line);
  emit_insn_after(as, lea);

  return true;
}

/*
 * Pop last entry from canary address buffer upon frame destruction
 * Returns: true on success, false on error
 */
static bool
canary_pop(rtx *insn)
{
  rtx tls_set;    /* subexpressions in PARALLEL */
  rtx as;         /* assembly instructions to be pushed */

  if (!(GET_CODE(*insn) == INSN && GET_CODE(PATTERN(*insn)) == PARALLEL))
    return false;

  /* get first PARALLEL subexpression and check if SP_TLS_TEST */
  tls_set = XVECEXP(PATTERN(*insn), 0, 0);

  /* if not a canary check return */
  if (!(tls_set                                  &&
        GET_CODE(tls_set) == SET                 &&
        REG_P(XEXP(tls_set, 0))                  &&
        REGNO(XEXP(tls_set, 0))    == FLAGS_REG  &&
        GET_MODE(XEXP(tls_set, 0)) == CCZmode    &&
        GET_CODE(XEXP(tls_set, 1)) == UNSPEC     &&
        XINT(XEXP(tls_set, 1), 1)  == UNSPEC_SP_TLS_TEST))
    return false;

  /* modify canary check to compare with DynaGuard's canary */
  XVECEXP(XEXP(XVECEXP(PATTERN(*insn), 0, 0), 1), 0, 1) = GEN_INT(CAN_OFFSET);

  /* pop canary from shadow stack */
  as = gen_rtx_ASM_OPERANDS(VOIDmode,
                            "decq %%fs:" CAB_IDX_TLS_OFFSET_STR,
                            "",
                            0,
                            rtvec_alloc(0),
                            rtvec_alloc(0),
                            rtvec_alloc(0),
                            expand_location(RTL_LOCATION(*insn)).line);
  emit_insn_before(as, *insn);
  return true;
}

/*
 * main pass
 * (invoked for every translation unit)
 *
 * returns: SUCCESS on success, FAILURE on error
 */
static unsigned int
execute_dynaguard(void)
{

#ifdef __i386__
  return SUCCESS; /* FIXME */
#endif

  rtx insn;          /* instruction (INSN) iterator */

#if DEBUG_INSN
  openlog();
#endif
  /* modify canary upon canary push and modify check upon pop*/
  for (insn=get_insns(); insn; insn=NEXT_INSN(insn)) {
    commitlog(insn, "INSN\n");

    /* ignore assembly */
    if (GET_CODE(insn) == INSN && asm_noperands(PATTERN(insn)) >= 0)
      continue;

    /* hacky optimization to skip extra checks */
    if (canary_push(&insn) || canary_pop(&insn))
      continue;
  }

#if DEBUG_INSN
  closelog();
#endif

  /* return with success */
  return SUCCESS;
}

#if (GCCPLUGIN_VERSION_MAJOR == 4) && (GCCPLUGIN_VERSION_MINOR == 9)
namespace {

const pass_data pass_data_dynaguard =
{
  RTL_PASS,      /* type */
  NAME,          /* name */
  OPTGROUP_NONE, /* optinfo_flags */
  false,         /* has gate */
  true,          /* has execute */
  TV_NONE,       /* tv_id */
  PROP_rtl,      /* properties_required */
  0,             /* properties_provided */
  0,             /* properties_destroyed */
  0,             /* todo_flags_start */
  0,             /* todo_flags_finish */
};

class pass_dynaguard : public rtl_opt_pass
{
 public:
  pass_dynaguard(gcc::context *ctxt)
      : rtl_opt_pass(pass_data_dynaguard, ctxt)
  {}

  /* opt_pass methods: */
  bool gate () {}
  unsigned int execute () { return execute_dynaguard(); }

}; /* class pass_dynaguard */

} /* anon namespace */

static rtl_opt_pass *
make_pass_dynaguard(gcc::context *ctxt)
{
  return new pass_dynaguard(ctxt);
}
#else

static bool
gate_dynaguard(void)
{
  return true;
}

static struct rtl_opt_pass dynaguard =
{
  {
    RTL_PASS,           /* type */
    NAME,               /* name */
    gate_dynaguard,     /* gate */
    execute_dynaguard,  /* execute */
    NULL,               /* sub */
    NULL,               /* next */
    0,                  /* static pass number */
    TV_NONE,            /* tv_id */
    PROP_rtl,           /* properties_required */
    0,                  /* properties_provided */
    0,                  /* properties_destroyed */
    0,                  /* todo_flags_start */
    0,                  /* todo_flags_finish */
  }
};

#endif

int
plugin_init(struct plugin_name_args *plugin_info,
            struct plugin_gcc_version *version)
{
  struct register_pass_info pass_info;

  if (!plugin_default_version_check(version, &gcc_version))
    return FAILURE;

#if (GCCPLUGIN_VERSION_MAJOR == 4) && (GCCPLUGIN_VERSION_MINOR == 9)
  pass_info.pass = make_pass_dynaguard(g);
#else
  pass_info.pass = &dynaguard.pass;
#endif
  pass_info.reference_pass_name = "vartrack";
  pass_info.ref_pass_instance_number = 1;
  pass_info.pos_op = PASS_POS_INSERT_AFTER;

  /* provide the pass information to the pass manager */
  register_callback(NAME, PLUGIN_PASS_MANAGER_SETUP, NULL, &pass_info);

  return SUCCESS;
}
