build: $(LIBDIR)
	cp -R auth util $(LIBDIR)
	
$(LIBDIR):
	mkdir -p $(LIBDIR)