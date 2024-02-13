
ROOT = ../..
BUILD = $(ROOT)/build
INSTALL= $(ROOT)/build/lib

# using icc requires some extra flags.
# these flags are probably different from when using gcc
# since a lot of what we do is not standard-c (asm, REG_RIP, etc not standard!)
#  gcc --std=gnu99
#  icc -- ?????
# it seems that icc also accepts the flag std=gnu99, good.
CC= gcc
CXX= g++ 

CODE = patcher.c
OBJ0 = $(CODE:.cpp=.o)
OBJ  = $(OBJ0:.c=.o)

EXTRA_FLAGS = 
CFLAGS = -g -O2

COMMON = $(wildcard $(ROOT)/common/src/patch/*.c)
COMMON_OBJ = $(COMMON:.c=.o)

INCLUDES = -I$(ROOT)/include -I$(ROOT)/utils/include -I$(ROOT)/deps/distorm/include

LIBS =
DEPS = $(ROOT)/deps/distorm/distorm3.a $(ROOT)/utils/src/libutils.a

AR = ar
RM = rm

.PHONY: test insta

all: libpointpatch.a

libpointpatch.a: $(OBJ) $(COMMON_OBJ)
	if [ -d libpointpatch.a ]; then $(RM) -f libpointpatch.a; fi
	if [ -d temp ]; then $(RM) -rf temp; fi
	mkdir temp;cd temp; $(foreach dep,$(DEPS),$(AR) -x ../$(dep);)
	$(AR) rc libpointpatch.a  $(OBJ) $(COMMON_OBJ) temp/*.o
	$(RM) -rf temp

.c.o:
	  $(CC) -O2 -std=gnu99 $(INCLUDES) $(EXTRA_FLAGS) $(CFLAGS) $(OPTS) -fPIC -c -Wall  -o $@ $<
