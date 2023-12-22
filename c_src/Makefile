CURDIR		:= $(shell pwd)
BASEDIR		:= $(abspath $(dir $(CURDIR)))
PROJECT		?= erlexec
PROJECT		:= $(strip $(PROJECT))

ERL_CXXFLAGS ?= $(shell erl -noshell -noinput -eval "io:format(\"-I~ts/erts-~ts/include -I~ts\", [code:root_dir(), erlang:system_info(version), code:lib_dir(erl_interface, include)]), halt(0).")
ERL_LDFLAGS  ?= $(shell erl -noshell -noinput -eval "io:format(\"-L~ts\", [code:lib_dir(erl_interface, lib)]), halt(0).")

CXXFLAGS  += -g -std=c++11 -finline-functions -Wall -DHAVE_PTRACE -MMD
USE_POLL  ?= 1

UNAME_SYS := $(shell uname -s | tr 'A-Z' 'a-z')

# System type and C compiler/flags.

# For cross building using erlang:system_info() does not work as rebar runs
# using the build hosts Erlang runtime.
# If CXX environment variable is defined we are most likely running in a cross environment.
ifeq ($(CXX),)
  CXX     := g++
  TARGET  := $(shell erl -noshell -noinput -eval "io:format("~s\n", [erlang:system_info(system_architecture)]), halt(0).")
  SYSROOT := ""
else
  TARGET  := $(shell $(CXX) -dumpmachine)
  SYSROOT := $(shell $(CXX) -print-sysroot)
endif


# By default use poll(2). If USE_POLL=0 is defined, use select(2):
ifneq ($(filter $(USE_POLL),0 1 true),)
  CXXFLAGS += -DUSE_POLL=$(USE_POLL)
endif

ifeq ($(findstring $(TARGET),linux),)
  MARCH   := $(TARGET)
else
  TEMP    := $(shell echo $(TARGET) | tr '-' '\n' | wc -l)
  ifeq ($(TEMP),4)
    MARCH := $(TARGET)
  else
    MARCH := $(TARGET)-gnu
  endif
endif

VSN       := $(shell git describe --always --tags --abbrev=0 | sed 's/^v//')
X64       := $(if $(findstring $(MARCH),x86_64),-m64)

# Set optimization flag
OPTIMIZE  ?= true
ifneq ($(filter $(OPTIMIZE),true 3),)
  CXXFLAGS += -O3 -DNDEBUG
else ifneq ($(filter $(OPTIMIZE),false 0),)
  CXXFLAGS += -O0 -g
else
  CXXFLAGS += -O$(OPTIMIZE) -g
endif

CXX_VSN   ?= $(shell $(CXX) --version | sed -n '1s/^[^0-9]\+\([0-9]\+\)\(.[0-9-]\)\+.*$$/\1/p')
BASE_CXX  := $(notdir $(CXX))

ifeq ($(BASE_CXX),g++)
  ifeq ($(shell expr $(CXX_VSN) \>= 13),1)
    C20_FEATURES=1
  endif
else ifeq ($(BASE_CXX),clang++)
  ifeq ($(shell expr $(CXX_VSN) \>= 15),1)
    C20_FEATURES=1
  endif
endif

HAVE_FORMAT ?= $(C20_FEATURES)
HAVE_SRCLOC ?= $(C20_FEATURES)

ifeq ($(UNAME_SYS),linux)
  CXXFLAGS += -mavx2 -DHAVE_SETRESUID -DHAVE_PIPE2 $(X64)
  # Check for Linux capability API (Install package: libcap-devel)
  ifneq ($(wildcard $(SYSROOT)/usr/include/sys/capability.h),)
    CXXFLAGS += -DHAVE_CAP
    LDFLAGS  += -lcap
  endif
else ifeq ($(UNAME_SYS),darwin)
  CXXFLAGS += -pie -DHAVE_SETREUID
  LDFLAGS  += -flat_namespace -undefined suppress $(X64)
else ifeq ($(uname_sys),solaris)
  CXXFLAGS += -dhave_setreuid
  LDFLAGS  += -lrt $(x64)
else ifneq ($(filter $(UNAME_SYS),freebsd openbsd dradonfly),)
  CXXFLAGS += -DHAVE_SETRESUID -DHAVE_PIPE2 $(X64)
  LDFLAGS  += $(X64)
else
  $(error Architecture $(UNAME_SYS) not supported!)
endif

CXXFLAGS   += $(ADD_FLAGS) $(ERL_CXXFLAGS)
LDFLAGS    += $(ERL_LDFLAGS) -lei

SRC_DIR     = $(CURDIR)
EXE_OUTPUT ?= $(BASEDIR)/priv/$(MARCH)/exec-port
EXE_DIR    := $(dir $(EXE_OUTPUT))

SOURCES    := $(wildcard *.c*)
OBJECTS     = $(SOURCES:%.cpp=%.o)

COMPILE_CPP = $(cpp_verbose) $(CXX) $(CXXFLAGS) $(CPPFLAGS) -c

# Targets

all: $(EXE_OUTPUT)

clean:
	rm -f $(EXE_OUTPUT) *.o *.d

info:
	@echo "SOURCES: $(SOURCES)"
	@echo "OBJECTS: $(OBJECTS)"
	@echo "OUTPUT:  $(EXE_OUTPUT)"
	@echo "OUT_DIR: $(EXE_DIR)"

$(EXE_OUTPUT): $(OBJECTS) $(EXE_DIR)
	mkdir -p "$(EXE_DIR)"
	$(CXX) $(OBJECTS) $(LDFLAGS) -o $@

$(EXE_DIR):
	mkdir -p $(BASEDIR)/priv/$(MARCH)/

%.o: %.cpp
	$(COMPILE_CPP) $(OUTPUT_OPTION) $<

.SUFFIXES:  # Delete default suffixes
.SUFFIXES: .cpp .o .hpp
