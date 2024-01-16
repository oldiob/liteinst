.PHONY: all

all:
	make -C deps/elph
	make -C deps/distorm/make/linux
	make -C utils/src
	make -C libpointpatch/src
	make CFLAGS="$(CFLAGS) -DNDEBUG -DWAIT_SPIN_RDTSC" -C libliteinst/src

install:
	install -m 444 -Dt $(PREFIX)/include include/liteinst.hpp
	install -Dt $(PREFIX)/lib libliteinst/src/libliteinst.so
