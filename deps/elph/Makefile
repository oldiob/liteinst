
SRCDIR=src
OBJDIR=obj
HDRDIR=include

EXEC=elph
CC=g++
_CFLAGS = -W -Wall -Wextra -I $(HDRDIR) -g -fPIC $(CFLAGS)
LDFLAGS=

_DEPS=elf64.h elf64_read.h elf64_write.h elf64_hdr.h elf64_shr.h sym_tab.h fdetect.h elf64_phr.h elf64_payload.h elf64_patch.h verbose.h 
_SRC=elf64.c elf64_read.c elf64_write.c elf64_hdr.c elf64_shr.c sym_tab.c fdetect.c elf64_phr.c elf64_payload.c elf64_patch.c verbose.c
_OBJ=$(_SRC:.c=.o)
DEPS=$(patsubst %,$(HDRDIR)/%,$(_DEPS))
OBJ=$(patsubst %,$(OBJDIR)/%,$(_OBJ))
SRC=$(patsubst %,$(SRCDIR)/%,$(_SRC))

all: $(OBJ)

$(EXEC): $(OBJ)
	$(CC) -o $@ $^ $(_CFLAGS)

$(OBJDIR)/$(EXEC).o: $(DEPS)

$(OBJDIR)/%.o: $(SRCDIR)/%.c
	$(CC) -o $@ -c $< $(_CFLAGS)

install: $(OBJ)
	ar rc libelph.a $(OBJ)

.PHONY: clean mrproper

clean:
	rm -rf $(OBJDIR)/*.o *.a

mproper: clean
	rm -rf $(EXEC)
