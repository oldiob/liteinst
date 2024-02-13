
ROOT= ../..
INSTALL= $(ROOT)/build/lib
DEPS_ROOT= $(ROOT)/deps

EXTRA_WARNS= -pedantic

override CFLAGS += --std=c++11 -g -Wall $(EXTRA_WARNS) -DAUDIT
# CFLAGS=-DPROBE_TRUE_EMPTY_ON -DPROBE_CPU_TIME
# CFLAGS=-DPROBE_HIST_ON -DPROBE_CPU_TIME

# Setup build macros from env variables

ARGS= -I. -I.. -I./liteprobes -I$(ROOT)/include -I$(ROOT)/utils/include -I$(ROOT)/deps/distorm/include -I$(ROOT)/deps/elph/include

LDFLAGS  = -Bsymbolic -fPIC -Wl,--hash-style=sysv -shared
POINTPATCH = $(ROOT)/libpointpatch/src/libpointpatch.a
UTILS = $(ROOT)/utils/src/libutils.a
DEPS = $(POINTPATCH) $(UTILS)
LIBS = -lstdc++ -pthread

ELPH = $(DEPS_ROOT)/elph

CC+  = $(CC) $(ARGS)
CXX+ = $(CXX) $(ARGS) $(CFLAGS)

AR = ar
RM = rm
OPTS =
FIND = find

CODE = $(wildcard liteprobes/*.cpp)

OBJ0 = $(CODE:.cpp=.o)
OBJ  = $(OBJ0:.c=.o)

.PHONY: all build install clean init

all: libliteinst.so

libliteinst.so: $(OBJ)
	$(CXX+) $(LIBS) -O2 -shared -Wl,-soname,libliteinst.so  -Wl,-init,init_point_patcher -o libliteinst.so $(OBJ) $(DEPS) # -Wl,-init,boostrap

.cpp.o:
	$(CXX+) -O2 -fPIC -c -Wall -o $@ $<

clean:
	$(FIND) . \( -name '*.o' -o -name '*.a' -o -name '*.so' \) -type f -delete
	$(RM) -f $(INSTALL)/libliteinst.*
