#
#Copyright 2013 Dominic Spill
#
#This file is part of libbtbb
#
#This program is free software; you can redistribute it and/or modify
#it under the terms of the GNU General Public License as published by
#the Free Software Foundation; either version 2, or (at your option)
#any later version.
#
#This program is distributed in the hope that it will be useful,
#but WITHOUT ANY WARRANTY; without even the implied warranty of
#MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#GNU General Public License for more details.
#
#You should have received a copy of the GNU General Public License
#along with libbtbb; see the file COPYING.  If not, write to
#the Free Software Foundation, Inc., 51 Franklin Street,
#Boston, MA 02110-1301, USA.
#

Summary: Bluetooth baseband library
Name: libbtbb
Version: 2012.10
Release: 3
License: GPL-2.0+
Source: http://sourceforge.net/projects/libbtbb/files/libbtbb-2012-10-R3.tar.gz
URL: http://libbtbb.sf.net
#BuildRoot: %{_tmppath}/%{name}-%{version}-build

%description
A library for decoding and processing Bluetooth baseband packets.
It can be used with any raw bitstream receiver, such as Ubertooth or
gr-bluetooth.
%prep
%setup
mv libbtbb-2012-10-R3 libbtbb-2012.10

%build
make %{?_smp_mflags}

%install
make DESTDIR=%{buildroot} install

%files
/usr/lib/libbtbb.so
/usr/lib/libbtbb.so.0
/usr/lib/libbtbb.so.0.1
