build: check_dest_set $(LIBDIR)
	cp -R auth util $(LIBDIR)

check_dest_set:
ifndef LIBDIR
	$(error LIBDIR is undefined)
endif

$(LIBDIR):
	mkdir -p $(LIBDIR)
