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
# Based slightly upon the hackrf cmake setup.

# FIXME Set static release version here to avoid pulling from git
set(RELEASE "")
set(DIRTY_FLAG "")

if ( "${RELEASE}" STREQUAL "" )
	# automatic git version when working out of git
	include(GetGitRevisionDescription)
	get_git_head_revision(GIT_REFSPEC RELEASE)

	execute_process(COMMAND git status -s --untracked-files=no OUTPUT_VARIABLE DIRTY)
	if ( NOT "${DIRTY}" STREQUAL "" )
		set(DIRTY_FLAG "*")
	endif()
endif()

add_definitions( -DRELEASE="${RELEASE}${DIRTY_FLAG}" )

# Source
set(c_sources ${CMAKE_CURRENT_SOURCE_DIR}/bluetooth_packet.c
              ${CMAKE_CURRENT_SOURCE_DIR}/bluetooth_piconet.c
              ${CMAKE_CURRENT_SOURCE_DIR}/bluetooth_le_packet.c
              ${CMAKE_CURRENT_SOURCE_DIR}/companies.c
              ${CMAKE_CURRENT_SOURCE_DIR}/pcap.c
              ${CMAKE_CURRENT_SOURCE_DIR}/pcapng.c
              ${CMAKE_CURRENT_SOURCE_DIR}/pcapng-bt.c
			  CACHE INTERNAL "List of C sources")
set(c_headers ${CMAKE_CURRENT_SOURCE_DIR}/btbb.h
			  CACHE INTERNAL "List of C headers")

if( NOT ${BUILD_SHARED_LIB} AND NOT ${BUILD_STATIC} )
	message( FATAL_ERROR "Not building static or shared library - at least one must be built")
endif( NOT ${BUILD_SHARED_LIB} AND NOT ${BUILD_STATIC} )

if( ${BUILD_SHARED_LIB} )
	# Shared library
	message(STATUS "Building shared library")
	add_library(btbb SHARED ${c_sources})
	set_target_properties(btbb PROPERTIES VERSION ${MAJOR_VERSION}.${MINOR_VERSION} SOVERSION 0)
	set_target_properties(btbb PROPERTIES CLEAN_DIRECT_OUTPUT 1)
endif( ${BUILD_SHARED_LIB} )

if( ${BUILD_STATIC_LIB} )
	# Static library
	message(STATUS "Building static library")
	add_library(btbb-static STATIC ${c_sources})
	set_target_properties(btbb-static PROPERTIES OUTPUT_NAME "btbb")
	set_target_properties(btbb-static PROPERTIES CLEAN_DIRECT_OUTPUT 1)
endif( ${BUILD_STATIC_LIB} )

if( ${BUILD_SHARED_LIB} )
   install(TARGETS btbb
           LIBRARY DESTINATION lib${LIB_SUFFIX}
           COMPONENT sharedlibs
           )
endif( ${BUILD_SHARED_LIB} )

if( ${BUILD_STATIC_LIB} )
   install(TARGETS btbb-static
           DESTINATION lib${LIB_SUFFIX}
           COMPONENT staticlibs
           )
endif( ${BUILD_STATIC_LIB} )

install(FILES ${c_headers}
        DESTINATION include
        COMPONENT headers
        )
