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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>
#include "bluetooth_le_packet.h"

// count of objects in an array, shamelessly stolen from Chrome
#define COUNT_OF(x) ((sizeof(x)/sizeof(0[x])) / ((size_t)(!(sizeof(x) % sizeof(0[x])))))

void decode_le(uint8_t *stream, uint16_t phys_channel, uint32_t clk100ns, le_packet_t *p) {
	memcpy(p->symbols, stream, MAX_LE_SYMBOLS);

	p->channel_idx = le_channel_index(phys_channel);
	p->clk100ns = clk100ns;

	p->access_address = 0;
	p->access_address |= p->symbols[0];
	p->access_address |= p->symbols[1] << 8;
	p->access_address |= p->symbols[2] << 16;
	p->access_address |= p->symbols[3] << 24;

	if (le_packet_is_data(p)) {
		// data PDU
		p->length = p->symbols[5] & 0x1f;
	} else {
		// advertising PDU
		p->length = p->symbols[5] & 0x3f;
		p->adv_type = p->symbols[4] & 0xf;
		p->adv_tx_add = p->symbols[4] & 0x40 ? 1 : 0;
		p->adv_rx_add = p->symbols[4] & 0x80 ? 1 : 0;
	}
}

int le_packet_is_data(le_packet_t *p) {
	return p->channel_idx < 37;
}

uint8_t le_channel_index(uint16_t phys_channel) {
	uint8_t ret;
	if (phys_channel == 2402) {
		ret = 37;
	} else if (phys_channel < 2426) { // 0 - 10
		ret = (phys_channel - 2404) / 2;
	} else if (phys_channel == 2426) {
		ret = 38;
	} else if (phys_channel < 2480) { // 11 - 36
		ret = 11 + (phys_channel - 2428) / 2;
	} else {
		ret = 39;
	}
	return ret;
}

const char *le_adv_type(le_packet_t *p) {
	if (le_packet_is_data(p))
		return NULL;
	if (p->adv_type < COUNT_OF(ADV_TYPE_NAMES))
		return ADV_TYPE_NAMES[p->adv_type];
	return "UNKNOWN";
}

static void _dump_addr(char *name, uint8_t *buf, int offset, int random) {
	int i;
	printf("    %s%02x", name, buf[offset+5]);
	for (i = 4; i >= 0; --i)
		printf(":%02x", buf[offset+i]);
	printf(" (%s)\n", random ? "random" : "public");
}

static void _dump_8(char *name, uint8_t *buf, int offset) {
	printf("    %s%02x (%d)\n", name, buf[offset], buf[offset]);
}

static void _dump_16(char *name, uint8_t *buf, int offset) {
	uint16_t val = buf[offset+1] << 8 | buf[offset];
	printf("    %s%04x (%d)\n", name, val, val);
}

static void _dump_24(char *name, uint8_t *buf, int offset) {
	uint16_t val = buf[offset+2] << 16 | buf[offset+1] << 8 | buf[offset];
	printf("    %s%06x\n", name, val);
}

static void _dump_32(char *name, uint8_t *buf, int offset) {
	uint32_t val = buf[offset+3] << 24 |
				   buf[offset+2] << 16 |
				   buf[offset+1] << 8 |
				   buf[offset+0];
	printf("    %s%08x\n", name, val);
}

void le_print(le_packet_t *p) {
	int i;
	if (le_packet_is_data(p)) {
		printf("Data / AA %08x / %2d bytes\n", p->access_address, p->length);
		printf("    Channel Index: %d\n", p->channel_idx);
	} else {
		printf("Advertising / AA %08x / %2d bytes\n", p->access_address, p->length);
		printf("    Channel Index: %d\n", p->channel_idx);
		printf("    Type:  %s\n", le_adv_type(p));

		switch(p->adv_type) {
			case ADV_IND:
				_dump_addr("AdvA:  ", p->symbols, 6, p->adv_tx_add);
				_dump_addr("InitA: ", p->symbols, 12, p->adv_rx_add);
				break;
			case SCAN_REQ:
				_dump_addr("ScanA: ", p->symbols, 6, p->adv_tx_add);
				_dump_addr("AdvA:  ", p->symbols, 12, p->adv_rx_add);
				break;
			case SCAN_RSP:
				_dump_addr("AdvA:  ", p->symbols, 6, p->adv_tx_add);
				printf("    ScanRspData:");
				for (i = 0; i < p->length - 12; ++i)
					printf(" %02x", p->symbols[12+i]);
				printf("\n");
				break;
			case CONNECT_REQ:
				_dump_addr("InitA: ", p->symbols, 6, p->adv_tx_add);
				_dump_addr("AdvA:  ", p->symbols, 12, p->adv_rx_add);
				_dump_32("AA:    ", p->symbols, 18);
				_dump_24("CRCInit: ", p->symbols, 22);
				_dump_8("WinSize: ", p->symbols, 25);
				_dump_16("WinOffset: ", p->symbols, 26);
				_dump_16("Interval: ", p->symbols, 28);
				_dump_16("Latency: ", p->symbols, 30);
				_dump_16("Timeout: ", p->symbols, 32);

				printf("    ChM:");
				for (i = 0; i < 5; ++i)
					printf(" %02x", p->symbols[34+i]);
				printf("\n");

				printf("    Hop: %d\n", p->symbols[37] & 0x1f);
				printf("    SCA: %d, %s\n",
						p->symbols[37] >> 5,
						CONNECT_SCA[p->symbols[37] >> 5]);
				break;
		}

		printf("\n");
		printf("    Data: ");
		for (i = 6; i < 6 + p->length; ++i)
			printf(" %02x", p->symbols[i]);
		printf("\n");

		printf("    CRC:  ");
		for (i = 0; i < 3; ++i)
			printf(" %02x", p->symbols[6 + p->length + i]);
		printf("\n");
	}
}
