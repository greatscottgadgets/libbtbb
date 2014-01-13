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
#include <ctype.h>

/* string representations of advertising packet type */
static const char *ADV_TYPE_NAMES[] = {
	"ADV_IND", "ADV_DIRECT_IND", "ADV_NONCONN_IND", "SCAN_REQ",
	"SCAN_RSP", "CONNECT_REQ", "ADV_SCAN_IND",
};

/* source clock accuracy in a connect packet */
static const char *CONNECT_SCA[] = {
	"251 ppm to 500 ppm", "151 ppm to 250 ppm", "101 ppm to 150 ppm",
	"76 ppm to 100 ppm", "51 ppm to 75 ppm", "31 ppm to 50 ppm",
	"21 ppm to 30 ppm", "0 ppm to 20 ppm",
};

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

static void _dump_uuid(uint8_t *uuid) {
	int i;
	for (i = 0; i < 4; ++i)
		printf("%02x", uuid[i]);
	printf("-");
	for (i = 4; i < 6; ++i)
		printf("%02x", uuid[i]);
	printf("-");
	for (i = 6; i < 8; ++i)
		printf("%02x", uuid[i]);
	printf("-");
	for (i = 8; i < 10; ++i)
		printf("%02x", uuid[i]);
	printf("-");
	for (i = 10; i < 16; ++i)
		printf("%02x", uuid[i]);
}

// Refer to pg 1735 of Bluetooth Core Spec 4.0
static void _dump_scan_rsp_data(uint8_t *buf, int len) {
	int pos = 0;
	int sublen, i;
	uint8_t type;
	uint16_t val;
	char *cval;

	while (pos < len) {
		sublen = buf[pos];
		++pos;
		if (pos + sublen > len) {
			printf("Error: attempt to read past end of buffer (%d + %d > %d)\n", pos, sublen, len);
			return;
		}
		if (sublen == 0) {
			printf("Early return due to 0 length\n");
			return;
		}
		type = buf[pos];
		printf("        Type %02x", type);
		switch (type) {
			case 0x01:
				printf(" (Flags)\n");
				printf("           ");
				for (i = 0; i < 8; ++i)
					printf("%d", buf[pos+1] & (1 << (7-i)) ? 1 : 0);
				printf("\n");
				break;
			case 0x06:
				printf(" (128-bit Service UUIDs, more available)\n");
				goto print128;
			case 0x07:
				printf(" (128-bit Service UUIDs)\n");
print128:
				if ((sublen - 1) % 16 == 0) {
					uint8_t uuid[16];
					for (i = 0; i < sublen - 1; ++i) {
						uuid[15 - (i % 16)] = buf[pos+1+i];
						if ((i & 15) == 15) {
							printf("           ");
							_dump_uuid(uuid);
							printf("\n");
						}
					}
				}
				else {
					printf("Wrong length (%d, must be divisible by 16)\n", sublen-1);
				}
				break;
			case 0x09:
				printf(" (Complete Local Name)\n");
				printf("           ");
				for (i = 1; i < sublen; ++i)
					printf("%c", isprint(buf[pos+i]) ? buf[pos+i] : '.');
				printf("\n");
				break;
			case 0x0a:
				printf(" (Tx Power Level)\n");
				printf("           ");
				if (sublen-1 == 1) {
					cval = (char *)&buf[pos+1];
					printf("%d dBm\n", *cval);
				} else {
					printf("Wrong length (%d, should be 1)\n", sublen-1);
				}
				break;
			case 0x12:
				printf(" (Slave Connection Interval Range)\n");
				printf("           ");
				if (sublen-1 == 4) {
					val = (buf[pos+2] << 8) | buf[pos+1];
					printf("(%0.2f, ", val * 1.25);
					val = (buf[pos+4] << 8) | buf[pos+3];
					printf("%0.2f) ms\n", val * 1.25);
				}
				else {
					printf("Wrong length (%d, should be 4)\n", sublen-1);
				}
				break;
			case 0x16:
				printf(" (Service Data)\n");
				printf("           ");
				if (sublen-1 >= 2) {
					val = (buf[pos+2] << 8) | buf[pos+1];
					printf("UUID: %02x", val);
					if (sublen-1 > 2) {
						printf(", Additional:");
						for (i = 3; i < sublen; ++i)
							printf(" %02x", buf[pos+i]);
					}
					printf("\n");
				}
				else {
					printf("Wrong length (%d, should be >= 2)\n", sublen-1);
				}
				break;
			default:
				printf("\n");
				printf("           ");
				for (i = 1; i < sublen; ++i)
					printf(" %02x", buf[pos+i]);
				printf("\n");
		}
		pos += sublen;
	}
}

void le_print(le_packet_t *p) {
	int i;
	if (le_packet_is_data(p)) {
		int llid = p->symbols[4] & 0x3;
		static const char *llid_str[] = {
			"Reserved",
			"LL Data PDU / empty or L2CAP continuation",
			"LL Data PDU / L2CAP start",
			"LL Control PDU",
		};

		printf("Data / AA %08x / %2d bytes\n", p->access_address, p->length);
		printf("    Channel Index: %d\n", p->channel_idx);
		printf("    LLID: %d / %s\n", llid, llid_str[llid]);
		printf("    NESN: %d  SN: %d  MD: %d\n", (p->symbols[4] >> 2) & 1,
												 (p->symbols[4] >> 3) & 1,
												 (p->symbols[4] >> 4) & 1);
	} else {
		printf("Advertising / AA %08x / %2d bytes\n", p->access_address, p->length);
		printf("    Channel Index: %d\n", p->channel_idx);
		printf("    Type:  %s\n", le_adv_type(p));

		switch(p->adv_type) {
			case ADV_IND:
				_dump_addr("AdvA:  ", p->symbols, 6, p->adv_tx_add);
				if (p->length-6 > 0) {
					printf("    AdvData:");
					for (i = 0; i < p->length - 6; ++i)
						printf(" %02x", p->symbols[12+i]);
					printf("\n");
					_dump_scan_rsp_data(&p->symbols[12], p->length-6);
				}
				break;
			case SCAN_REQ:
				_dump_addr("ScanA: ", p->symbols, 6, p->adv_tx_add);
				_dump_addr("AdvA:  ", p->symbols, 12, p->adv_rx_add);
				break;
			case SCAN_RSP:
				_dump_addr("AdvA:  ", p->symbols, 6, p->adv_tx_add);
				printf("    ScanRspData:");
				for (i = 0; i < p->length - 6; ++i)
					printf(" %02x", p->symbols[12+i]);
				printf("\n");
				_dump_scan_rsp_data(&p->symbols[12], p->length-6);
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

				printf("    Hop: %d\n", p->symbols[39] & 0x1f);
				printf("    SCA: %d, %s\n",
						p->symbols[39] >> 5,
						CONNECT_SCA[p->symbols[39] >> 5]);
				break;
		}
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
