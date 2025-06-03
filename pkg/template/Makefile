
prefix = $(DESTDIR)/opt/bowline

all:

install:
	mkdir -p $(prefix)/bin
	for n in ./bin/* ; do \
	    install -m 755 $$n $(prefix)/bin/ ; \
	done
	mkdir -p $(prefix)/etc
	for n in ./etc/* ; do \
	    install -m 644 $$n $(prefix)/etc/ ; \
	done

clean:
