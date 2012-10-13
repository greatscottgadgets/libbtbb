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

CC      ?= gcc
AR      ?= ar
INSTALL  = /usr/bin/install
LDCONFIG = /sbin/ldconfig

INSTALL_DIR ?= /usr/lib
INCLUDE_DIR ?= /usr/include

LIB_NAME = libbtbb.so
SONAME   = $(LIB_NAME).0
LIB_FILE = $(SONAME).1
STATIC_LIB_FILE = libbtbb.a

SOURCE_FILES = bluetooth_packet.c bluetooth_piconet.c bluetooth_le_packet.c
OBJECT_FILES = $(SOURCE_FILES:%.c=%.o)
HEADER_FILES = $(SOURCE_FILES:%.c=%.h)

all: $(LIB_FILE)

$(OBJECT_FILES): $(SOURCE_FILES) $(HEADER_FILES)
	$(CC) $(CFLAGS) -fPIC -c $(SOURCE_FILES)

$(LIB_FILE): $(OBJECT_FILES)
	$(CC) $(CFLAGS) $(LDFLAGS) -shared -Wl,-soname,$(SONAME) -o $(LIB_FILE) $(OBJECT_FILES)

osx: $(OBJECT_FILES)
	$(CC) $(CFLAGS) $(LDFLAGS) -shared -Wl -install_name $(INSTALL_DIR)/$(LIB_FILE) -o $(LIB_FILE) $(OBJECT_FILES)

$(STATIC_LIB_FILE): $(LIB_FILE)
	$(AR) rcs $(STATIC_LIB_FILE) $(OBJECT_FILES)

clean:
	rm -f *.o $(LIB_FILE) $(STATIC_LIB_FILE)

install: $(LIB_FILE)
	$(INSTALL) -m 0644 $(LIB_FILE) $(INSTALL_DIR)
	$(INSTALL) -m 0644 $(HEADER_FILES) $(INCLUDE_DIR)
	ln -fs $(LIB_FILE) $(INSTALL_DIR)/$(LIB_NAME)
	ln -fs $(LIB_FILE) $(INSTALL_DIR)/$(SONAME)
	$(LDCONFIG)

cygwin-install: $(LIB_FILE) $(STATIC_LIB_FILE)
	$(INSTALL) -m 0644 $(LIB_FILE) $(INSTALL_DIR)
	$(INSTALL) -m 0644 $(HEADER_FILES) $(INCLUDE_DIR)
	$(INSTALL) -m 0644 $(STATIC_LIB_FILE) $(INSTALL_DIR)
	ln -fs $(LIB_FILE) $(INSTALL_DIR)/$(LIB_NAME)
	ln -fs $(LIB_FILE) $(INSTALL_DIR)/$(SONAME)

osx-install: osx
	$(INSTALL) -m 0644 $(LIB_FILE) $(INSTALL_DIR)
	$(INSTALL) -m 0644 $(HEADER_FILES) $(INCLUDE_DIR)
	ln -fs $(LIB_FILE) $(INSTALL_DIR)/$(LIB_NAME)
	ln -fs $(LIB_FILE) $(INSTALL_DIR)/$(SONAME)

.PHONY: all clean install cygwin-install osx osx-install
