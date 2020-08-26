CC=cc
CFLAGS=-Wall -Wno-missing-braces -Wno-parentheses -Wno-switch -Wno-pointer-to-int-cast -fno-diagnostics-color -ggdb -c -O2
LDFLAGS=-static
O=o
BIN=$(HOME)/bin

TARG=logwatch
OFILES=\
	main.$O\

LIBS=\
	libutf/libutf.a\

HFILES=\
	args.h\
	libutf/utf.h\

.PHONY: all clean
all: $(TARG)

%.$O: %.c
	$(CC) $(CFLAGS) $<

$(OFILES): $(HFILES)

$(TARG): $(OFILES)
	$(CC) -o $@ $(OFILES) $(LIBS) $(LDFLAGS)

install: $(TARG)
	cp $(TARG) $(BIN)/

uninstall:
	rm -f $(BIN)/$(TARG)

man:
	groff -man $(TARG).8.man | ps2pdf - >$(TARG).8.pdf

clean:
	rm $(TARG) *.o *.pdf
