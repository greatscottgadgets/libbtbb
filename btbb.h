/* -*- c -*- */
/*
 * Copyright 2007 - 2012 Dominic Spill, Michael Ossmann                                                                                            
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

/* minimum header bit errors to indicate that this is an ID packet */
#define ID_THRESHOLD 5

/* maximum number of hops to remember */
#define MAX_PATTERN_LENGTH 1000

/* number of channels in use */
#define BT_NUM_CHANNELS 79

typedef struct btbb_packet_flags {
	uint32_t is_whitened:1;
	uint32_t uap_valid:1;
	uint32_t nap_valid:1;
	uint32_t lap_valid:1;
	uint32_t clk6_valid:1;
	uint32_t clk27_valid:1;
	uint32_t crc_correct:1;  /* WC4: watch for dual use as has_payload */
	uint32_t has_payload:1;
	uint32_t is_edr:1;
} btbb_packet_flags;

typedef struct btbb_packet {

	btbb_packet_flags flags;

	uint8_t channel; /* Bluetooth channel (0-79) */
	uint8_t UAP;     /* upper address part */
	uint16_t NAP;    /* non-significant address part */
	uint32_t LAP;    /* lower address part found in access code */
	
	int packet_type;
	uint8_t packet_lt_addr; /* LLID field of payload header (2 bits) */
	
	/* packet header, one bit per char */
	char packet_header[18];
	
	/* number of payload header bytes: 0, 1, 2, or -1 for
	 * unknown */
	int payload_header_length;
	
	/* payload header, one bit per char */
	char payload_header[16];
	
	/* LLID field of payload header (2 bits) */
	uint8_t payload_llid;
	
	/* flow field of payload header (1 bit) */
	uint8_t payload_flow;

	/* WC4: move payload out of structure. Maybe return
	 * dynamically. That way there is only one variable length
	 * field. */

	/* payload length: the total length of the asynchronous data
	* in bytes.  This does not include the length of synchronous
	* data, such as the voice field of a DV packet.  If there is a
	* payload header, this payload length is payload body length
	* (the length indicated in the payload header's length field)
	* plus payload_header_length plus 2 bytes CRC (if present).
	*/
	int payload_length;
	
	/* The actual payload data in host format
	* Ready for passing to wireshark
	* 2744 is the maximum length, but most packets are shorter.
	* Dynamic allocation would probably be better in the long run but is
	* problematic in the short run.
	*/
	char payload[2744];

	uint16_t crc;
	uint32_t clock; /* CLK1-27 of master */
	uint32_t clkn;  /* native (local) clock, CLK0-27 */
	uint8_t ac_errors; /* Number of bit errors in the AC */

        /* WC4: make this a zero-length field at the end of the packet
	 * to allow for variable size. */

	/* the raw symbol stream (less the preamble), one bit per char */
	//FIXME maybe this should be a vector so we can grow it only
	//to the size needed and later shrink it if we find we have
	//more symbols than necessary
	uint16_t length; /* number of symbols */
	char symbols[MAX_SYMBOLS];

} btbb_packet;

/* Initialize the library. Compute the syndrome. Return 0 on success,
 * negative on error.
 *
 * The library limits max_ac_errors to 5. Using a larger value will
 * take up a lot of memory (several GB), without decoding many useful
 * packets. Even a limit of 5 results in a syndrome table of several
 * hundred MB and lots of noise. For embedded targets, a value of 2 is
 * reasonable. */
int btbb_init(int max_ac_errors);

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
	       btbb_packet *pkt);
#define LAP_ANY 0xffffffffUL

void btbb_packet_set_data(btbb_packet *pkt,
			char *syms,      // Symbol data
			int length,      // Number of symbols
			uint8_t channel, // Bluetooth channel 0-79
			uint32_t clkn);  // 312.5us clock (CLK27-0)

/* Generate Sync Word from an LAP */
uint64_t btbb_gen_syncword(int LAP);

/* decode the packet header */
int btbb_decode_header(btbb_packet* p);

/* decode the packet header */
int btbb_decode_payload(btbb_packet* p);

/* print packet information */
void btbb_print_packet(btbb_packet* p);

/* check to see if the packet has a header */
int btbb_header_present(btbb_packet* p);

/* Packet queue (linked list) */
typedef struct pkt_queue {
	btbb_packet *pkt;

	struct pkt_queue *next;

} pkt_queue;

typedef struct btbb_piconet {
	/* true if using a particular aliased receiver implementation */
	int aliased;

	/* using adaptive frequency hopping (AFH) */
	int afh;

	/* observed pattern that looks like AFH */
	int looks_like_afh;

	/* AFH channel map - either read or derived from observed packets */
	uint8_t afh_map[10];

	/* lower address part (of master's BD_ADDR) */
	uint32_t LAP;

	/* upper address part (of master's BD_ADDR) */
	uint8_t UAP;

	/* non-significant address part (of master's BD_ADDR) */
	uint16_t NAP;

	/* CLK1-27 candidates */
	uint32_t *clock_candidates;

	/* these values for hop() can be precalculated */
	int b, e;

	/* these values for hop() can be precalculated in part (e.g. a1 is the
	 * precalculated part of a) */
	int a1, c1, d1;

	/* frequency register bank */
	int bank[BT_NUM_CHANNELS];

	/* this holds the entire hopping sequence */
	char *sequence;

	/* number of candidates for CLK1-27 */
	int num_candidates;

	/* have we collected the first packet in a UAP discovery attempt? */
	int got_first_packet;

	/* number of packets observed during one attempt at UAP/clock discovery */
	int packets_observed;

	/* total number of packets observed */
	int total_packets_observed;

	/* number of observed packets that have been used to winnow the candidates */
	int winnowed;

	/* CLK1-6 candidates */
	int clock6_candidates[64];

	/* remember patterns of observed hops */
	int pattern_indices[MAX_PATTERN_LENGTH];
	uint8_t pattern_channels[MAX_PATTERN_LENGTH];

	int hop_reversal_inited;

	/* offset between CLKN (local) and CLK of piconet */
	int clk_offset;

	/* local clock (clkn) at time of first packet */
	uint32_t first_pkt_time;

	/* Whether LAP is valid */
	int have_LAP;

	/* discovery status */
	int have_UAP;
	int have_NAP;
	int have_clk6;
	int have_clk27;

	/* queue of packets to be decoded */
	pkt_queue *queue;
} btbb_piconet;

/* use packet headers to determine UAP */
int btbb_uap_from_header(btbb_packet *pkt, btbb_piconet *pnet);

/* Print hexadecimal representation of the derived AFH map */
void btbb_print_afh_map(btbb_piconet *pnet);

/* decode a whole packet from the given piconet */
int btbb_decode(btbb_packet* p, btbb_piconet *pnet);

/* initialize the piconet struct */
void btbb_init_piconet(btbb_piconet *pnet);

/* initialize the hop reversal process */
/* returns number of initial candidates for CLK1-27 */
int btbb_init_hop_reversal(int aliased, btbb_piconet *pnet);

/* narrow a list of candidate clock values based on all observed hops */
int btbb_winnow(btbb_piconet *pnet);

#endif /* INCLUDED_BTBB_H */
