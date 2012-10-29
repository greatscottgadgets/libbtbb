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
#define MAX_AC_ERRORS 4

/* maximum number of bit errors for for known syncwords */
#define MAX_SYNCWORD_ERRS 5

/* default codeword modified for PN sequence and barker code */
#define DEFAULT_CODEWORD 0xb0000002c7820e7eULL

/* Default access code, used for calculating syndromes */
#define DEFAULT_AC 0xcc7b7268ff614e1bULL

/* minimum header bit errors to indicate that this is an ID packet */
static const int ID_THRESHOLD = 5;

/* index into whitening data array */
static const uint8_t INDICES[] = {99, 85, 17, 50, 102, 58, 108, 45, 92, 62, 32, 118, 88, 11, 80, 2, 37, 69, 55, 8, 20, 40, 74, 114, 15, 106, 30, 78, 53, 72, 28, 26, 68, 7, 39, 113, 105, 77, 71, 25, 84, 49, 57, 44, 61, 117, 10, 1, 123, 124, 22, 125, 111, 23, 42, 126, 6, 112, 76, 24, 48, 43, 116, 0};

/* whitening data */
static const uint8_t WHITENING_DATA[] = {1, 1, 1, 0, 0, 0, 1, 1, 1, 0, 1, 1, 0, 0, 0, 1, 0, 1, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 0, 0, 1, 1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 1, 1, 0, 1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 1, 1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1};

/* lookup table for barker code hamming distance */
static const uint8_t BARKER_DISTANCE[] = {
	3,3,3,2,3,2,2,1,2,3,3,3,3,3,3,2,2,3,3,3,3,3,3,2,1,2,2,3,2,3,3,3,
	3,2,2,1,2,1,1,0,3,3,3,2,3,2,2,1,3,3,3,2,3,2,2,1,2,3,3,3,3,3,3,2,
	2,3,3,3,3,3,3,2,1,2,2,3,2,3,3,3,1,2,2,3,2,3,3,3,0,1,1,2,1,2,2,3,
	3,3,3,2,3,2,2,1,2,3,3,3,3,3,3,2,2,3,3,3,3,3,3,2,1,2,2,3,2,3,3,3};

/* string representations of packet type */
static const char * const TYPE_NAMES[] = {
	"NULL", "POLL", "FHS", "DM1", "DH1/2-DH1", "HV1", "HV2/2-EV3", "HV3/EV3/3-EV3",
	"DV/3-DH1", "AUX1", "DM3/2-DH3", "DH3/3-DH3", "EV4/2-EV5", "EV5/3-EV5", "DM5/2-DH5", "DH5/3-DH5"
};

/*
 * generator matrix for sync word (64,30) linear block code
 * based on polynomial 0260534236651
 * thanks to http://www.ee.unb.ca/cgi-bin/tervo/polygen.pl
 * modified for barker code
 */
static const uint64_t sw_matrix[] = {
	0xfe000002a0d1c014ULL, 0x01000003f0b9201fULL, 0x008000033ae40edbULL, 0x004000035fca99b9ULL,
	0x002000036d5dd208ULL, 0x00100001b6aee904ULL, 0x00080000db577482ULL, 0x000400006dabba41ULL,
	0x00020002f46d43f4ULL, 0x000100017a36a1faULL, 0x00008000bd1b50fdULL, 0x000040029c3536aaULL,
	0x000020014e1a9b55ULL, 0x0000100265b5d37eULL, 0x0000080132dae9bfULL, 0x000004025bd5ea0bULL,
	0x00000203ef526bd1ULL, 0x000001033511ab3cULL, 0x000000819a88d59eULL, 0x00000040cd446acfULL,
	0x00000022a41aabb3ULL, 0x0000001390b5cb0dULL, 0x0000000b0ae27b52ULL, 0x0000000585713da9ULL};

static const uint64_t syndrome_matrix[] = {
	0x4be2573a00000000ULL, 0x25f12b9d00000000ULL, 0x591ac2f480000000ULL, 0x676f364040000000ULL,
	0x33b79b2020000000ULL, 0x19dbcd9010000000ULL, 0x0cede6c808000000ULL, 0x0676f36404000000ULL,
	0x48d92e8802000000ULL, 0x246c974401000000ULL, 0x59d41c9800800000ULL, 0x2cea0e4c00400000ULL,
	0x5d97501c00200000ULL, 0x6529ff3400100000ULL, 0x7976a8a000080000ULL, 0x3cbb545000040000ULL,
	0x1e5daa2800020000ULL, 0x0f2ed51400010000ULL, 0x4c753db000008000ULL, 0x263a9ed800004000ULL,
	0x131d4f6c00002000ULL, 0x426cf08c00001000ULL, 0x6ad42f7c00000800ULL, 0x7e88408400000400ULL,
	0x74a6777800000200ULL, 0x3a533bbc00000100ULL, 0x56cbcae400000080ULL, 0x6087b24800000040ULL,
	0x3043d92400000020ULL, 0x53c3bba800000010ULL, 0x29e1ddd400000008ULL, 0x5f12b9d000000004ULL,
	0x2f895ce800000002ULL, 0x97c4ae7400000001ULL};

static const uint64_t barker_correct[] = {
	0xb000000000000000ULL, 0x4e00000000000000ULL, 0x4e00000000000000ULL, 0x4e00000000000000ULL,
	0x4e00000000000000ULL, 0x4e00000000000000ULL, 0x4e00000000000000ULL, 0x4e00000000000000ULL,
	0xb000000000000000ULL, 0xb000000000000000ULL, 0xb000000000000000ULL, 0x4e00000000000000ULL,
	0xb000000000000000ULL, 0x4e00000000000000ULL, 0x4e00000000000000ULL, 0x4e00000000000000ULL,
	0xb000000000000000ULL, 0xb000000000000000ULL, 0xb000000000000000ULL, 0x4e00000000000000ULL,
	0xb000000000000000ULL, 0x4e00000000000000ULL, 0x4e00000000000000ULL, 0x4e00000000000000ULL,
	0xb000000000000000ULL, 0xb000000000000000ULL, 0xb000000000000000ULL, 0xb000000000000000ULL,
	0xb000000000000000ULL, 0xb000000000000000ULL, 0xb000000000000000ULL, 0x4e00000000000000ULL,
	0x4e00000000000000ULL, 0x4e00000000000000ULL, 0x4e00000000000000ULL, 0x4e00000000000000ULL,
	0x4e00000000000000ULL, 0x4e00000000000000ULL, 0x4e00000000000000ULL, 0x4e00000000000000ULL,
	0xb000000000000000ULL, 0x4e00000000000000ULL, 0x4e00000000000000ULL, 0x4e00000000000000ULL,
	0x4e00000000000000ULL, 0x4e00000000000000ULL, 0x4e00000000000000ULL, 0x4e00000000000000ULL,
	0xb000000000000000ULL, 0x4e00000000000000ULL, 0x4e00000000000000ULL, 0x4e00000000000000ULL,
	0x4e00000000000000ULL, 0x4e00000000000000ULL, 0x4e00000000000000ULL, 0x4e00000000000000ULL,
	0xb000000000000000ULL, 0xb000000000000000ULL, 0xb000000000000000ULL, 0x4e00000000000000ULL,
	0xb000000000000000ULL, 0x4e00000000000000ULL, 0x4e00000000000000ULL, 0x4e00000000000000ULL,
	0xb000000000000000ULL, 0xb000000000000000ULL, 0xb000000000000000ULL, 0x4e00000000000000ULL,
	0xb000000000000000ULL, 0x4e00000000000000ULL, 0x4e00000000000000ULL, 0x4e00000000000000ULL,
	0xb000000000000000ULL, 0xb000000000000000ULL, 0xb000000000000000ULL, 0xb000000000000000ULL,
	0xb000000000000000ULL, 0xb000000000000000ULL, 0xb000000000000000ULL, 0x4e00000000000000ULL,
	0xb000000000000000ULL, 0xb000000000000000ULL, 0xb000000000000000ULL, 0xb000000000000000ULL,
	0xb000000000000000ULL, 0xb000000000000000ULL, 0xb000000000000000ULL, 0x4e00000000000000ULL,
	0xb000000000000000ULL, 0xb000000000000000ULL, 0xb000000000000000ULL, 0xb000000000000000ULL,
	0xb000000000000000ULL, 0xb000000000000000ULL, 0xb000000000000000ULL, 0xb000000000000000ULL,
	0xb000000000000000ULL, 0x4e00000000000000ULL, 0x4e00000000000000ULL, 0x4e00000000000000ULL,
	0x4e00000000000000ULL, 0x4e00000000000000ULL, 0x4e00000000000000ULL, 0x4e00000000000000ULL,
	0xb000000000000000ULL, 0xb000000000000000ULL, 0xb000000000000000ULL, 0x4e00000000000000ULL,
	0xb000000000000000ULL, 0x4e00000000000000ULL, 0x4e00000000000000ULL, 0x4e00000000000000ULL,
	0xb000000000000000ULL, 0xb000000000000000ULL, 0xb000000000000000ULL, 0x4e00000000000000ULL,
	0xb000000000000000ULL, 0x4e00000000000000ULL, 0x4e00000000000000ULL, 0x4e00000000000000ULL,
	0xb000000000000000ULL, 0xb000000000000000ULL, 0xb000000000000000ULL, 0xb000000000000000ULL,
	0xb000000000000000ULL, 0xb000000000000000ULL, 0xb000000000000000ULL, 0x4e00000000000000ULL};

static const uint64_t pn = 0x83848D96BBCC54FCULL;

static const uint16_t fec23_gen_matrix[] = {
	0x2c01, 0x5802, 0x1c04, 0x3808, 0x7010,
	0x4c20, 0x3440, 0x6880, 0x7d00, 0x5600};

/* Need to return more than just the offset,
 * this allows us to correct the data too
 */
typedef struct access_code {
	/* AC offset from start of data */
	int offset;

	/* Corrected LAP */
	uint32_t LAP;

	/* Number of error bits corrected */
	uint8_t error_count;
} access_code;

typedef struct packet {
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

	/* native (local) clock */
	uint32_t clkn;

	/* Number of bit errors in the AC */
	uint8_t ac_errors;
} packet;

/* type-specific CRC checks and decoding */
int fhs(int clock, packet* p);
int DM(int clock, packet* p);
int DH(int clock, packet* p);
int EV3(int clock, packet* p);
int EV4(int clock, packet* p);
int EV5(int clock, packet* p);
int HV(int clock, packet* p);

/* decode payload header, return value indicates success */
int decode_payload_header(char *stream, int clock, int header_bytes, int size, int fec, packet* p);

/* Remove the whitening from an air order array */
void unwhiten(char* input, char* output, int clock, int length, int skip, packet* p);

/* verify the payload CRC */
int payload_crc(packet* p);

/*
 * Search for known LAP and return the index.  The length of the stream must be
 * at least search_length + 72.
 */
int find_ac(char *stream, int search_length, uint32_t LAP, access_code *ac);

/*
 * Search a symbol stream to find a packet with arbitrary LAP, return index.
 * The length of the stream must be at least search_length + 72.
 */
int sniff_ac(char *stream, int search_length, access_code *ac);

/* Reverse the bits in a byte */
uint8_t reverse(char byte);

/* Generate syndrome from the AC codeword */
uint64_t gen_syndrome(uint64_t codeword);

/* Generate the syndrome map for up to 0 to bit_errors */
void gen_syndrome_map(int bit_errors);

/* Generate Sync Word from an LAP */
uint64_t gen_syncword(int LAP);

/* Decode 1/3 rate FEC, three like symbols in a row */
int unfec13(char *input, char *output, int length);

/* encode 10 bits with 2/3 rate FEC code, a (15,10) shortened Hamming code */
uint16_t fec23(uint16_t data);

/* Decode 2/3 rate FEC, a (15,10) shortened Hamming code */
char *unfec23(char *input, int length);

/* Compare stream with sync word */
int check_syncword(uint64_t streamword, uint64_t syncword);

/* Convert some number of bits of an air order array to a host order integer */
uint8_t air_to_host8(char *air_order, int bits);
uint16_t air_to_host16(char *air_order, int bits);
uint32_t air_to_host32(char *air_order, int bits);
uint64_t air_to_host64(char *air_order, int bits);
// hmmm, maybe these should have pointer output so they can be overloaded

/* Convert some number of bits in a host order integer to an air order array */
void host_to_air(uint8_t host_order, char *air_order, int bits);

/* Create the 16bit CRC for packet payloads - input air order stream */
uint16_t crcgen(char *payload, int length, int UAP);

/* extract UAP by reversing the HEC computation */
int UAP_from_hec(uint16_t data, uint8_t hec);

/* check if the packet's CRC is correct for a given clock (CLK1-6) */
int crc_check(int clock, packet* p);

/* decode the packet header */
int decode_header(packet* p);

/* decode the packet header */
int decode_payload(packet* p);

/* print packet information */
void btbb_print_packet(packet* p);

/* format payload for tun interface */
char *tun_format(packet* p);

/* try a clock value (CLK1-6) to unwhiten packet header,
 * sets resultant d_packet_type and d_UAP, returns UAP.
 */
uint8_t try_clock(int clock, packet* p);

/* check to see if the packet has a header */
int header_present(packet* p);

/* extract LAP from FHS payload */
uint32_t lap_from_fhs(packet* p);

/* extract UAP from FHS payload */
uint8_t uap_from_fhs(packet* p);

/* extract NAP from FHS payload */
uint16_t nap_from_fhs(packet* p);

/* extract clock from FHS payload */
uint32_t clock_from_fhs(packet* p);

void init_packet(packet *p, char *syms, int len);

/* count the number of 1 bits in a uint64_t */
uint8_t count_bits(uint64_t n);

#endif /* INCLUDED_BLUETOOTH_PACKET_H */
