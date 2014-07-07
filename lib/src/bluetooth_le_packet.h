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

#define ADV_IND			0
#define ADV_DIRECT_IND	1
#define ADV_NONCONN_IND	2
#define SCAN_REQ		3
#define SCAN_RSP		4
#define CONNECT_REQ		5
#define ADV_SCAN_IND	6

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

typedef struct _le_air_packet_t {
	// raw unwhitened bytes of packet, no access address
	uint8_t symbols[MAX_LE_SYMBOLS];
	size_t length;
	uint32_t access_address;
	uint8_t channel_idx;
} le_air_packet_t;

typedef struct _le_adv_ind_t {
	uint8_t  AdvA[6];
	uint8_t *data;
	uint8_t data_len;
} le_adv_ind_t;

typedef le_adv_ind_t le_adv_nonconn_ind_t;
typedef le_adv_ind_t le_scan_ind_t;

typedef struct _le_adv_direct_ind_t {
	uint8_t  AdvA[6];
	uint8_t  InitA[6];
} le_adv_direct_ind_t;

typedef struct _le_scan_req_t {
	uint8_t ScanA[6];
	uint8_t AdvA[6];
} le_scan_req_t;

typedef struct _le_scan_rsp_t {
	uint8_t AdvA[6];
	uint8_t *data;
	uint8_t data_len;
} le_scan_rsp_t;

typedef struct _le_connect_req_t {
	uint8_t  InitA[6];
	uint8_t  AdvA[6];
	uint32_t AA;
	uint32_t CRCInit;
	uint8_t  WinSize;
	uint16_t WinOffset;
	uint16_t Interval;
	uint16_t Latency;
	uint16_t Timeout;
	uint8_t  ChM[5];
	uint8_t  Hop;
	uint8_t  SCA;
} le_connect_req_t;

typedef struct _le_adv_t {
	uint8_t PDU_Type;
	uint8_t TxAdd;
	uint8_t RxAdd;
	uint8_t Length;
	union {
		le_adv_ind_t adv_ind;
		le_adv_direct_ind_t adv_direct_ind;
		le_adv_nonconn_ind_t adv_nonconn_ind;
		le_scan_ind_t scan_ind;
		le_scan_req_t scan_req;
		le_scan_rsp_t scan_rsp;
		le_connect_req_t connect_req;
	} payload;
} le_adv_t;

/* decode payload */
void decode_le(uint8_t *stream, uint16_t phys_channel, uint32_t clk100ns, le_packet_t *p);

/* returns true if this is a data packet, false if advertising */
int le_packet_is_data(le_packet_t *p);

/* returns the channel index of a physical channel */
uint8_t le_channel_index(uint16_t phys_channel);

/* returns the channel number given a channel index */
uint8_t le_channel_number(uint8_t channel_index);

/* returns a string representing advertising packet type */
const char *le_adv_type(le_packet_t *p);

/* print LE packet information */
void le_print(le_packet_t *p);


///////////
// API v2

int le_air_packet_init(le_air_packet_t *p, uint8_t *packet, size_t length, uint8_t channel);

/* parse an LE advertising packet into adv */
int le_parse_advertising(le_air_packet_t *p, le_adv_t *adv);

/* print a parsed advertising packet */
void le_adv_print(le_adv_t *adv);

#endif /* INCLUDED_BLUETOOTH_LE_PACKET_H */
