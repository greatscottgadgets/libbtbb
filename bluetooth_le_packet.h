/* -*- c -*- */
/*
 * Copyright 2007 - 2012 Mike Ryan, Dominic Spill, Michael Ossmann
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
#ifndef INCLUDED_BLUETOOTH_LE_PACKET_H
#define INCLUDED_BLUETOOTH_LE_PACKET_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define MAX_LE_SYMBOLS 64

/* string representations of advertising packet type */
static const char *ADV_TYPE_NAMES[] = {
	"ADV_IND", "ADV_DIRECT_IND", "ADV_NONCONN_IND", "SCAN_REQ",
	"SCAN_RSP", "CONNECT_REQ", "ADV_SCAN_IND",
};

#define ADV_IND			0
#define ADV_DIRECT_IND	1
#define ADV_NONCONN_IND	2
#define SCAN_REQ		3
#define SCAN_RSP		4
#define CONNECT_REQ		5
#define ADV_SCAN_IND	6

/* source clock accuracy in a connect packet */
static const char *CONNECT_SCA[] = {
	"251 ppm to 500 ppm", "151 ppm to 250 ppm", "101 ppm to 150 ppm",
	"76 ppm to 100 ppm", "51 ppm to 75 ppm", "31 ppm to 50 ppm",
	"21 ppm to 30 ppm", "0 ppm to 20 ppm",
};

typedef struct _le_packet_t {
	// raw unwhitened bytes of packet, including access address
	uint8_t symbols[MAX_LE_SYMBOLS];

	uint32_t access_address;

	// channel index
	uint8_t channel_idx;

	// number of symbols
	int length;

	uint32_t clk100ns;

	// advertising packet header info
	uint8_t adv_type;
	int adv_tx_add;
	int adv_rx_add;
} le_packet_t;

/* decode payload */
void decode_le(uint8_t *stream, uint16_t phys_channel, uint32_t clk100ns, le_packet_t *p);

/* returns true if this is a data packet, false if advertising */
int le_packet_is_data(le_packet_t *p);

/* returns the channel index of a physical channel */
uint8_t le_channel_index(uint16_t phys_channel);

/* returns a string representing advertising packet type */
const char *le_adv_type(le_packet_t *p);

/* print LE packet information */
void le_print(le_packet_t *p);

#endif /* INCLUDED_BLUETOOTH_LE_PACKET_H */
