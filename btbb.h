/* -*- c -*- */
/*
 * Copyright 2007 - 2013 Dominic Spill, Michael Ossmann, Will Code
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
#ifndef INCLUDED_BTBB_H
#define INCLUDED_BTBB_H

#include <stdint.h>

/* maximum number of symbols */
#define MAX_SYMBOLS 3125

/* maximum number of payload bits */
#define MAX_PAYLOAD_LENGTH 2744

/* minimum header bit errors to indicate that this is an ID packet */
#define ID_THRESHOLD 5

/* maximum number of hops to remember */
#define MAX_PATTERN_LENGTH 1000

/* number of channels in use */
#define BT_NUM_CHANNELS 79

#define BTBB_WHITENED    0
#define BTBB_NAP_VALID   1
#define BTBB_UAP_VALID   2
#define BTBB_LAP_VALID   3
#define BTBB_CLK6_VALID  4
#define BTBB_CLK27_VALID 5
#define BTBB_CRC_CORRECT 6
#define BTBB_HAS_PAYLOAD 7
#define BTBB_IS_EDR      8

#define BTBB_HOP_REVERSAL_INIT 9
#define BTBB_GOT_FIRST_PACKET  10
#define BTBB_IS_AFH            11
#define BTBB_LOOKS_LIKE_AFH    12
#define BTBB_IS_ALIASED        13
#define BTBB_FOLLOWING         14

typedef struct btbb_packet btbb_packet;

/* Initialize the library. Compute the syndrome. Return 0 on success,
 * negative on error.
 *
 * The library limits max_ac_errors to 5. Using a larger value will
 * take up a lot of memory (several GB), without decoding many useful
 * packets. Even a limit of 5 results in a syndrome table of several
 * hundred MB and lots of noise. For embedded targets, a value of 2 is
 * reasonable. */
int btbb_init(int max_ac_errors);

btbb_packet *btbb_packet_new(void);
void btbb_packet_ref(btbb_packet *pkt);
void btbb_packet_unref(btbb_packet *pkt);

/* Search for a packet with specified LAP (or LAP_ANY). The stream
 * must be at least of length serch_length + 72. Limit to
 * 'max_ac_errors' bit errors.
 *
 * Returns offset into 'stream' at which packet was found. If no
 * packet was found, returns a negative number. If LAP_ANY was
 * specified, fills lap. 'ac_errors' must be set as an input, replaced
 * by actual number of errors on output. */
int btbb_find_ac(char *stream,
	       int search_length,
	       uint32_t lap,
	       int max_ac_errors,
	       btbb_packet **pkt);
#define LAP_ANY 0xffffffffUL

void btbb_packet_set_flag(btbb_packet *pkt, int flag, int val);
int btbb_packet_get_flag(btbb_packet *pkt, int flag);

uint32_t btbb_packet_get_lap(btbb_packet *pkt);
void btbb_packet_set_uap(btbb_packet *pkt, uint8_t uap);
uint8_t btbb_packet_get_uap(btbb_packet *pkt);

uint8_t btbb_packet_get_channel(btbb_packet *pkt);
uint8_t btbb_packet_get_ac_errors(btbb_packet *pkt);
uint32_t btbb_packet_get_clkn(btbb_packet *pkt);

void btbb_packet_set_data(btbb_packet *pkt,
			  char *syms,      // Symbol data
			  int length,      // Number of symbols
			  uint8_t channel, // Bluetooth channel 0-79
			  uint32_t clkn);  // 312.5us clock (CLK27-0)

/* Get a pointer to packet symbols. */
const char *btbb_get_symbols(btbb_packet* pkt);

int btbb_packet_get_payload_length(btbb_packet* pkt);

/* Get a pointer to payload. */
const char *btbb_get_payload(btbb_packet* pkt);

int btbb_packet_get_type(btbb_packet* pkt);

/* Generate Sync Word from an LAP */
uint64_t btbb_gen_syncword(int LAP);

/* decode the packet header */
int btbb_decode_header(btbb_packet* pkt);

/* decode the packet header */
int btbb_decode_payload(btbb_packet* pkt);

/* print packet information */
void btbb_print_packet(btbb_packet* pkt);

/* check to see if the packet has a header */
int btbb_header_present(btbb_packet* pkt);

/* Packet queue (linked list) */
typedef struct pkt_queue {
	btbb_packet *pkt;

	struct pkt_queue *next;

} pkt_queue;

typedef struct btbb_piconet btbb_piconet;

btbb_piconet *btbb_piconet_new(void);
void btbb_piconet_ref(btbb_piconet *pn);
void btbb_piconet_unref(btbb_piconet *pn);

void btbb_piconet_set_uap(btbb_piconet *pn, uint8_t uap);
uint8_t btbb_piconet_get_uap(btbb_piconet *pn);
void btbb_piconet_set_lap(btbb_piconet *pn, uint32_t lap);
uint32_t btbb_piconet_get_lap(btbb_piconet *pn);
uint16_t btbb_piconet_get_nap(btbb_piconet *pn);
int btbb_piconet_get_clk_offset(btbb_piconet *pn);

void btbb_piconet_set_flag(btbb_piconet *pn, int flag, int val);
int btbb_piconet_get_flag(btbb_piconet *pn, int flag);

void btbb_piconet_set_channel_seen(btbb_piconet *pn, uint8_t channel);
uint8_t *btbb_piconet_get_afh_map(btbb_piconet *pn);

/* Extract as much information (LAP/UAP/CLK) as possible from received packet */
int btbb_process_packet(btbb_packet *pkt, btbb_piconet *pn);

/* use packet headers to determine UAP */
int btbb_uap_from_header(btbb_packet *pkt, btbb_piconet *pn);

/* Print hexadecimal representation of the derived AFH map */
void btbb_print_afh_map(btbb_piconet *pn);

/* decode a whole packet from the given piconet */
int btbb_decode(btbb_packet* pkt, btbb_piconet *pn);

/* initialize the piconet struct */
void btbb_init_piconet(btbb_piconet *pn);

/* initialize the hop reversal process */
/* returns number of initial candidates for CLK1-27 */
int btbb_init_hop_reversal(int aliased, btbb_piconet *pn);

void try_hop(btbb_packet *pkt, btbb_piconet *pn);

/* narrow a list of candidate clock values based on all observed hops */
int btbb_winnow(btbb_piconet *pn);

int btbb_init_survey(void);
/* Iterate over survey results - optionally remove elements */
btbb_piconet *btbb_next_survey_result(int remove);

/* Print AFH map from observed packets */
void btbb_piconet_print_afh_map(btbb_piconet *pn);

#endif /* INCLUDED_BTBB_H */
