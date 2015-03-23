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

if ( "${RELEASE}" STREQUAL "" )
	# automatic git version when working out of git
	include(GetGitRevisionDescription)
	get_git_head_revision(GIT_REFSPEC RELEASE)
endif()

add_definitions( -DRELEASE="${RELEASE}" )

configure_file("${CMAKE_CURRENT_SOURCE_DIR}/version.c.in"
               "${CMAKE_CURRENT_BINARY_DIR}/version.c"
               @ONLY)

# Source
set(c_sources ${CMAKE_CURRENT_SOURCE_DIR}/bluetooth_packet.c
              ${CMAKE_CURRENT_SOURCE_DIR}/bluetooth_piconet.c
              ${CMAKE_CURRENT_SOURCE_DIR}/bluetooth_le_packet.c
              ${CMAKE_CURRENT_SOURCE_DIR}/pcap.c
              ${CMAKE_CURRENT_SOURCE_DIR}/pcapng.c
              ${CMAKE_CURRENT_SOURCE_DIR}/pcapng-bt.c
			  ${CMAKE_CURRENT_BINARY_DIR}/version.c
			  CACHE INTERNAL "List of C sources")
set(c_headers ${CMAKE_CURRENT_SOURCE_DIR}/btbb.h
			  CACHE INTERNAL "List of C headers")

# For cygwin just force UNIX OFF and WIN32 ON
if( ${CYGWIN} )
	SET(UNIX OFF)
	SET(WIN32 ON)
endif( ${CYGWIN} )

# FIXME: This may be a hack
# perhaps there should be separate libbtbb and libbtbb-static targets?
if( ${WIN32} )
	# Static library
	add_library(btbb STATIC ${c_sources})
	set_target_properties(btbb PROPERTIES OUTPUT_NAME "btbb_static")
else()
	# Dynamic library
	add_library(btbb SHARED ${c_sources})
	set_target_properties(btbb PROPERTIES VERSION ${MAJOR_VERSION}.${MINOR_VERSION} SOVERSION 0)
endif()

set_target_properties(btbb PROPERTIES CLEAN_DIRECT_OUTPUT 1)

# PCAP Support
if( (NOT DEFINED USE_PCAP) OR USE_PCAP )
	find_package(PCAP)

	if( USE_PCAP AND NOT ${PCAP_FOUND} )
		message( FATAL_ERROR
			"Cannot find libpcap, which is required for USE_PCAP")
	endif()

	if( ${PCAP_FOUND} )
		include_directories(${PCAP_INCLUDE_DIRS})
		target_link_libraries(btbb ${PCAP_LIBRARIES})
		add_definitions( -DENABLE_PCAP )
	endif( ${PCAP_FOUND} )
endif( (NOT DEFINED USE_PCAP) OR USE_PCAP )

if( ${UNIX} )
   install(TARGETS btbb
           LIBRARY DESTINATION lib${LIB_SUFFIX}
           COMPONENT sharedlibs
           )
   install(FILES ${c_headers}
           DESTINATION include
           COMPONENT headers
           )
endif( ${UNIX} )

if( ${WIN32} )
   install(TARGETS btbb
           DESTINATION bin
           COMPONENT staticlibs
           )
   install(FILES ${c_headers}
           DESTINATION include
           COMPONENT headers
           )
endif( ${WIN32} )
