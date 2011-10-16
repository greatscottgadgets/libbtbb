# Copyright 2010 Michael Ossmann, Dominic Spill
#
# This file is part of Project Ubertooth.
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
# along with this program; see the file COPYING.  If not, write to
# the Free Software Foundation, Inc., 51 Franklin Street,
# Boston, MA 02110-1301, USA.

CC       = gcc
INSTALL  = /usr/bin/install
LDCONFIG = /sbin/ldconfig

INSTALL_DIR ?= /usr/lib
INCLUDE_DIR ?= /usr/include

LIB_NAME = libbtbb.so
SONAME   = $(LIB_NAME).0
LIB_FILE = $(SONAME).1

SOURCE_FILES = bluetooth_packet.c bluetooth_piconet.c
OBJECT_FILES = $(SOURCE_FILES:%.c=%.o)
HEADER_FILES = $(SOURCE_FILES:%.c=%.h)

all: libbtbb

libbtbb: $(LIB_FILE)

$(LIB_FILE):
	$(CC) $(CFLAGS) $(CPPFLAGS) -g -O2 -Wall -fPIC  -c $(SOURCE_FILES)
	$(CC) $(CFLAGS) $(LDFLAGS) -shared -Wl,-soname,$(SONAME) -o $(LIB_FILE) $(OBJECT_FILES)

clean:
	rm -f *.o $(LIB_FILE)

install: $(LIB_FILE)
	$(INSTALL) -m 0644 $(LIB_FILE) $(INSTALL_DIR)
	$(INSTALL) -m 0644 $(HEADER_FILES) $(INCLUDE_DIR)
	$(LDCONFIG)
	ln -fs $(LIB_FILE) $(INSTALL_DIR)/$(LIB_NAME)
	ln -fs $(LIB_FILE) $(INSTALL_DIR)/$(SONAME)

.PHONY: all clean install libbtbb
