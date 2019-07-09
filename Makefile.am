AUTOMAKE_OPTIONS = 1.9.6 foreign

CC = gcc
RM = rm -vf
INSTALL = install

AM_CFLAGS = @CFLAGS@ $(libpipeline_CFLAGS)
AM_CFLAGS += -g3 -Wall
LIBS = $(libpipeline_LIBS)

prefix = @prefix@
bindir = $(prefix)/bin
datadir = $(prefix)/share
mandir = $(datadir)/man
man1dir = $(mandir)/man1

SRCS = mgrep.c decode.c
OBJS = $(SRCS:.c=.o)

all: mgrep

%.o : %.c
	$(CC) $(AM_CFLAGS) -c -o $@ $^

mgrep: $(OBJS)
	$(CC) $(AM_CFLAGS) -o $@ $^ $(LIBS)

clean-local:
	$(RM) $^ $(OBJS) mgrep

install-exec-local: mgrep
	$(mkinstalldirs) $(DESTDIR)$(bindir)
	$(INSTALL) $(INSTALLBIN) $< $(DESTDIR)$(bindir)

install-data-local: mgrep.1
	$(mkinstalldirs) $(DESTDIR)$(man1dir)
	$(INSTALL) $(INSTALLDTA) $< $(DESTDIR)$(man1dir)
