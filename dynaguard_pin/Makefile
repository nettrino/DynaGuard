#
# NSL DynaGuard
#
# Columbia University, Department of Computer Science
# Network Security Lab
#
# Vasileios P. Kemerlis (vpk@cs.columbia.edu)
#
# NOTE: use this Makefile with Pin v2.14-71313,
# 	or any version after that
#

# variable definitions
CFLAGS		= -Wall -g -fPIC -O3 -c
CXXFLAGS	= -Wno-unknown-pragmas -Wall -g			\
		   -c -fomit-frame-pointer -std=c++0x -O3	\
		   -fno-strict-aliasing -fno-stack-protector	\
		   -DBIGARRAY_MULTIPLIER=1 -DUSING_XED		\
		   -DTARGET_LINUX # -mtune=core2
CXXFLAGS32	= -DTARGET_IA32 -DHOST_IA32
CXXFLAGS64	= -fPIC -DTARGET_IA32E -DHOST_IA32E
CFLAGS_SO	= -shared
CXXFLAGS_SO	= -g -Wl,--hash-style=sysv -Wl,-Bsymbolic -shared	\
		  -Wl,--version-script=$(PIN_HOME)/source/include/pin/pintool.ver
LIBS		= -lpin -lxed -lpindwarf -ldl -lbsd
I_INCLUDE	= -I.						\
		   -I$(PIN_HOME)/source/include/pin		\
		   -I$(PIN_HOME)/source/include/pin/gen		\
		   -I$(PIN_HOME)/extras/components/include
I_INCLUDE32	=  -I$(PIN_HOME)/extras/xed-ia32/include
I_INCLUDE64	=  -I$(PIN_HOME)/extras/xed-intel64/include
L_INCLUDE	=
L_INCLUDE32	=  -L$(PIN_HOME)/extras/xed-ia32/lib		\
		   -L$(PIN_HOME)/ia32/lib			\
		   -L$(PIN_HOME)/ia32/lib-ext			\
		   -Wl,-rpath $(PIN_HOME)/ia32/runtime
L_INCLUDE64	=  -L$(PIN_HOME)/extras/xed-intel64/lib	\
		   -L$(PIN_HOME)/intel64/lib			\
		   -L$(PIN_HOME)/intel64/lib-ext		\
		   -Wl,-rpath $(PIN_HOME)/intel64/runtime/glibc
OBJS		= dynaguard.o
SOBJS		= $(OBJS:.o=.so)

# phony targets
.PHONY: all sanity tool clean

# get system information
OS=$(shell uname -o | grep Linux$$)	# OS
ARCH=$(shell uname -m | grep 86)	# arch

# default target
all: sanity tool

# sanity checks (i.e., PIN_HOME, OS, architecture)
sanity:
# check if PIN_HOME variable is defined
ifndef PIN_HOME
	$(error "PIN_HOME environment variable is not set")
endif
# check the OS (must be Linux)
ifeq ($(strip $(OS)),)
	$(error "This version of DynaGuard is for Linux only")
endif
# check the architecture (must be x86_64, x86, i386, i486, i686, ...)
ifeq	($(strip $(ARCH)),)
	$(error "This version of DynaGuard is for x86/x86_64 only")
else
ifeq	($(strip $(ARCH)),x86_64)
CXXFLAGS	+= $(CXXFLAGS64)
I_INCLUDE	+= $(I_INCLUDE64)
L_INCLUDE	+= $(L_INCLUDE64)
else
CXXFLAGS	+= $(CXXFLAGS32)
I_INCLUDE	+= $(I_INCLUDE32)
L_INCLUDE	+= $(L_INCLUDE32)
endif
endif

# tool
tool: $(SOBJS)

# dynaguard
dynaguard.so: dynaguard.o
	$(CXX) $(CXXFLAGS_SO) $(L_INCLUDE) -o $(@) $(@:.so=.o) $(LIBS)
dynaguard.o: dynaguard.c dynaguard.h
	$(CXX) $(CXXFLAGS) $(I_INCLUDE) -o $(@) $(@:.o=.c)

# clean
clean:
	rm -rf $(OBJS) $(SOBJS)
