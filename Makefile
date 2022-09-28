# Makefile for authbind
# 
# authbind is Copyright (C) 1998 Ian Jackson
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2, or (at your option)
# any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software Foundation,
# Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA. 

prefix=/usr/local

bin_dir=$(prefix)/bin
lib_dir=$(prefix)/lib/authbind
libexec_dir=$(lib_dir)

share_dir=$(prefix)/share
man_dir=$(share_dir)/man
man1_dir=$(man_dir)/man1
man8_dir=$(man_dir)/man8

etc_dir=/etc/authbind

INSTALL_FILE	?= install -o root -g root -m 644 
INSTALL_PROGRAM ?= install -o root -g root -m 755 -s
INSTALL_DIR	?= install -o root -g root -m 755 -d
STRIP		?= strip

OPTIMISE=	-O2
LDFLAGS=	-g
LIBS=		-ldl -lc
CFLAGS=		-g $(OPTIMISE) \
		-Wall -Wwrite-strings -Wpointer-arith -Wimplicit \
		-Wnested-externs -Wmissing-prototypes -Wstrict-prototypes
CPPFLAGS=	-DMAJOR_VER='"$(MAJOR)"' -DMINOR_VER='"$(MINOR)"' \
		-DLIBAUTHBIND='"$(lib_dir)/$(LIBCANON)"' \
		-DHELPER='"$(libexec_dir)/$(HELPER)"' -DCONFIGDIR='"$(etc_dir)"' \
		-D_GNU_SOURCE

MAJOR=1
MINOR=0
LIBCANON=	libauthbind.so.$(MAJOR)
LIBTARGET=	$(LIBCANON).$(MINOR)
BINTARGETS=	authbind
HELPER=		helper

TARGETS=		$(BINTARGETS) $(HELPER) $(LIBTARGET)
MANPAGES_1=		authbind.1
MANPAGES_8=		authbind-helper.8

all:			$(TARGETS)

install:		$(TARGETS)
		$(INSTALL_DIR) $(lib_dir) $(man1_dir) $(man8_dir)
		$(INSTALL_PROGRAM) $(BINTARGETS) $(bin_dir)/.
		$(INSTALL_FILE) $(LIBTARGET) $(lib_dir)/.
		$(STRIP) --strip-unneeded $(lib_dir)/$(LIBTARGET)
		ln -sf $(LIBTARGET) $(lib_dir)/$(LIBCANON)
		$(INSTALL_PROGRAM) $(HELPER) $(libexec_dir)/.
		chmod u+s $(libexec_dir)/$(HELPER)
		$(INSTALL_DIR) $(etc_dir) \
			$(etc_dir)/byport $(etc_dir)/byaddr $(etc_dir)/byuid

install_man:		$(MANPAGES_1) $(MANPAGES_8)
		$(INSTALL_FILE) $(MANPAGES_1) $(man1_dir)/.
		$(INSTALL_FILE) $(MANPAGES_8) $(man8_dir)/.

libauthbind.o:		libauthbind.c authbind.h
		$(CC) -D_REENTRANT $(CFLAGS) $(CPPFLAGS) -c -o $@ -fPIC $<

authbind:		authbind.o
helper:			helper.o

helper.o authbind.o:	authbind.h

$(LIBTARGET):		libauthbind.o
		$(LD) -shared -soname $(LIBCANON) -o $@ $< $(LIBS)

clean distclean:
		rm -f $(TARGETS) *.o *~ ./#*# *.bak *.new core
		rm -f libauthbind.so* *.core
