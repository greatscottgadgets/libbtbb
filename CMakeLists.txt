#
# Copyright 2013 Dominic Spill
#
# This file is part of Libbtbb.
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
#
#top level cmake project for libbtbb lib + tools

cmake_minimum_required(VERSION 2.8)
set(MAJOR_VERSION 0)
set(MINOR_VERSION 3)
project(libbtbb_all)
set(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake/modules)

set(INSTALL_DEFAULT_BINDIR "bin" CACHE STRING "Appended to CMAKE_INSTALL_PREFIX")

## Instruct user to remove previous versions, unless using a package manager
#if(NOT PACKAGE_MANAGER)
#  # Unset variables to force the recheck next time
#  # (there has to be a better way to do it than this)
#  UNSET(LIBBTBB_FOUND CACHE)
#  UNSET(LIBBTBB_INCLUDE_DIR CACHE)
#  UNSET(LIBBTBB_LIBRARIES CACHE)
#
#  find_package(BTBB)
#  if(LIBBTBB_FOUND)
#    message( FATAL_ERROR
#      "An existing installation of libbtbb is already present on this system. Please remove it, and any depending applications before building. A helper script is provided, run\n$ sudo ../cmake/cleanup.sh -d\nto find and remove libbtbb and libubertooth and the ubertooth tools")
#  endif()
#endif()

# automatic git version when working out of git
execute_process(COMMAND git log --pretty=format:%h -n 1
                OUTPUT_VARIABLE GIT_VERSION)

MESSAGE(STATUS "Git version set to ${GIT_VERSION}")

execute_process(COMMAND git status -s --untracked-files=no | grep modified
                RESULT_VARIABLE DIRTY)

if( ${DIRTY} EQUAL "0" )
	MESSAGE(STATUS "Modifications found since last commit")
	set(DIRTY_FLAG "*")
endif( ${DIRTY} EQUAL "0" )

set( VERSION ${MAJOR_VERSION}.${MINOR_VERSION} )
set( RELEASE git-${GIT_VERSION}${DIRTY_FLAG} )

add_definitions( -DVERSION="${VERSION}" )
add_definitions( -DRELEASE="${RELEASE}" )

# Comment the following out for releases.
set(CMAKE_C_FLAGS "$ENV{CFLAGS}")

add_subdirectory(lib)
if(NOT DISABLE_PYTHON)
	add_subdirectory(python)
endif()

# Create uninstall target
configure_file(
    ${PROJECT_SOURCE_DIR}/cmake/cmake_uninstall.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake
@ONLY)

add_custom_target(uninstall
    ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake
)
