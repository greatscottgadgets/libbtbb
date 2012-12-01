/* -*- c -*- */
/*
 * Copyright 2007 - 2010 Dominic Spill, Michael Ossmann                                                                                            
 * Copyright 2005, 2006 Free Software Foundation, Inc.
 * 
 * This file is part of libbtbb
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with libbtbb; see the file COPYING.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street,
 * Boston, MA 02110-1301, USA.
 */
#ifndef INCLUDED_BLUETOOTH_PACKET_H
#define INCLUDED_BLUETOOTH_PACKET_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

/* maximum number of symbols */
#define MAX_SYMBOLS 3125

/* Defaut maximum AC bit errors for unknown ACs, this can be overridden at runtime */
#define MAX_AC_ERRORS 3

/* maximum number of bit errors for for known syncwords */
#define MAX_SYNCWORD_ERRS 5

/* default codeword modified for PN sequence and barker code */
#define DEFAULT_CODEWORD 0xb0000002c7820e7eULL

/* Default access code, used for calculating syndromes */
#define DEFAULT_AC 0xcc7b7268ff614e1bULL

/* minimum header bit errors to indicate that this is an ID packet */
#define ID_THRESHOLD 5

typedef struct bt_packet {
	/* the raw symbol stream (less the preamble), one bit per char */
	//FIXME maybe this should be a vector so we can grow it only to the size
	//needed and later shrink it if we find we have more symbols than necessary
	char symbols[MAX_SYMBOLS];

	/* Bluetooth channel */
	uint8_t channel;

	/* lower address part found in access code */
	uint32_t LAP;
	
	/* upper address part */
	uint8_t UAP;
	
	/* non-significant address part */
	uint16_t NAP;
	
	/* number of symbols */
	int length;
	
	/* packet type */
	int packet_type;
	
	/* LLID field of payload header (2 bits) */
	uint8_t packet_lt_addr;
	
	/* packet header, one bit per char */
	char packet_header[18];
	
	/* payload header, one bit per char */
	/* the packet may have a payload header of 0, 1, or 2 bytes, reserving 2 */
	char payload_header[16];
	
	/* number of payload header bytes */
	/* set to 0, 1, 2, or -1 for unknown */
	int payload_header_length;
	
	/* LLID field of payload header (2 bits) */
	uint8_t payload_llid;
	
	/* flow field of payload header (1 bit) */
	uint8_t payload_flow;
	
	/* payload length: the total length of the asynchronous data in bytes.
	* This does not include the length of synchronous data, such as the voice
	* field of a DV packet.
	* If there is a payload header, this payload length is payload body length
	* (the length indicated in the payload header's length field) plus
	* payload_header_length plus 2 bytes CRC (if present).
	*/
	int payload_length;
	
	/* The actual payload data in host format
	* Ready for passing to wireshark
	* 2744 is the maximum length, but most packets are shorter.
	* Dynamic allocation would probably be better in the long run but is
	* problematic in the short run.
	*/
	char payload[2744];
	
	/* is the packet whitened? */
	int whitened;
	
	/* do we know the UAP/NAP? */
	int have_UAP;
	int have_NAP;
	
	/* do we know the master clock? */
	int have_clk6;
	int have_clk27;
	
	int have_payload;
	
	/* 1 if crc is correct
	 * 0 if crc is incorrect
	 * -1 if packet type has no payload
	 */
	int payload_crc;
	uint16_t crc;

	/* Set to 1 when we know it's an EDR packet */
	int is_edr;
	
	/* CLK1-27 of master */
	uint32_t clock;

	/* native (local) clock, CLK0-27 */
	uint32_t clkn;

	/* Number of bit errors in the AC */
	uint8_t ac_errors;
} bt_packet;

/* type-specific CRC checks and decoding */
int fhs(int clock, bt_packet* p);
int DM(int clock, bt_packet* p);
int DH(int clock, bt_packet* p);
int EV3(int clock, bt_packet* p);
int EV4(int clock, bt_packet* p);
int EV5(int clock, bt_packet* p);
int HV(int clock, bt_packet* p);

/* decode payload header, return value indicates success */
int decode_payload_header(char *stream, int clock, int header_bytes, int size, int fec, bt_packet* p);

/* Search for a packet with specified LAP (or LAP_ANY). The stream
 * must be at least of length serch_length + 72. Limit to
 * 'max_ac_errors' bit errors.
 *
 * Returns offset into 'stream' at which packet was found. If no
 * packet was found, returns a negative number. If LAP_ANY was
 * specified, fills lap. 'ac_errors' must be set as an input, replaced
 * by actual number of errors on output. */
int bt_find_ac(char *stream,
	       int search_length,
	       uint32_t lap,
	       int max_ac_errors,
	       bt_packet *pkt);
#define LAP_ANY 0xffffffffUL

void bt_packet_set_data(bt_packet *pkt,
			char *syms,      // Symbol data
			int length,      // Number of symbols
			uint8_t channel, // Bluetooth channel 0-79
			uint32_t clkn);  // 312.5us clock (CLK27-0)

/* Generate Sync Word from an LAP */
uint64_t gen_syncword(int LAP);

/* extract UAP by reversing the HEC computation */
int UAP_from_hec(uint16_t data, uint8_t hec);

/* check if the packet's CRC is correct for a given clock (CLK1-6) */
int crc_check(int clock, bt_packet* p);

/* decode the packet header */
int decode_header(bt_packet* p);

/* decode the packet header */
int decode_payload(bt_packet* p);

/* print packet information */
void btbb_print_packet(bt_packet* p);

/* format payload for tun interface */
char *tun_format(bt_packet* p);

/* try a clock value (CLK1-6) to unwhiten packet header,
 * sets resultant d_packet_type and d_UAP, returns UAP.
 */
uint8_t try_clock(int clock, bt_packet* p);

/* check to see if the packet has a header */
int header_present(bt_packet* p);

/* extract LAP from FHS payload */
uint32_t lap_from_fhs(bt_packet* p);

/* extract UAP from FHS payload */
uint8_t uap_from_fhs(bt_packet* p);

/* extract NAP from FHS payload */
uint16_t nap_from_fhs(bt_packet* p);

/* extract clock from FHS payload */
uint32_t clock_from_fhs(bt_packet* p);

#endif /* INCLUDED_BLUETOOTH_PACKET_H */
