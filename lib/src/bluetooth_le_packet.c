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

uint8_t le_channel_number(uint8_t channel_index) {
	uint8_t ret = 0;
	if (channel_index <= 10) {
		ret = channel_index + 1;
	} else if (channel_index <= 36) {
		ret = channel_index + 2;
	} else if (channel_index == 37) {
		ret = 0;
	} else if (channel_index == 38) {
		ret  = 12;
	} else if (channel_index == 39) {
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

static void _dump_addr_norev(char *name, uint8_t *buf, int random) {
	int i;
	printf("    %s%02x", name, buf[0]);
	for (i = 1; i < 6; ++i)
		printf(":%02x", buf[i]);
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
	uint32_t val = buf[offset+2] << 16 | buf[offset+1] << 8 | buf[offset];
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
	int i, opcode;
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
		switch (llid) {
		case 3: // LL Control PDU
			opcode = p->symbols[6];
			static const char *opcode_str[] = {
				"LL_CONNECTION_UPDATE_REQ",
				"LL_CHANNEL_MAP_REQ",
				"LL_TERMINATE_IND",
				"LL_ENC_REQ",
				"LL_ENC_RSP",
				"LL_START_ENC_REQ",
				"LL_START_ENC_RSP",
				"LL_UNKNOWN_RSP",
				"LL_FEATURE_REQ",
				"LL_FEATURE_RSP",
				"LL_PAUSE_ENC_REQ",
				"LL_PAUSE_ENC_RSP",
				"LL_VERSION_IND",
				"LL_REJECT_IND",
				"LL_SLAVE_FEATURE_REQ",
				"LL_CONNECTION_PARAM_REQ",
				"LL_CONNECTION_PARAM_RSP",
				"LL_REJECT_IND_EXT",
				"LL_PING_REQ",
				"LL_PING_RSP",
				"Reserved for Future Use",
			};
			printf("    Opcode: %d / %s\n", opcode, opcode_str[(opcode<0x14)?opcode:0x14]);
			break;
		default:
			break;
		}
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

static void memcpy_reverse(void *dst, void *src, size_t len) {
	size_t i;
	for (i = 0; i < len; ++i)
		((uint8_t *)dst)[i] = ((uint8_t *)src)[len - i - 1];
}


int le_air_packet_init(le_air_packet_t *p, uint8_t *packet, size_t length, uint8_t channel) {
	if (length > MAX_LE_SYMBOLS)
		return 0;

	memset(p, 0, sizeof(*p));
	memcpy(p->symbols, packet, length);
	p->length = length;
	p->channel_idx = le_channel_index(2402 + channel * 2);

	return 1;
}

#define GRAB8(dst, offset)  (dst) = data[offset]
#define GRAB16(dst, offset) (dst) = *(uint16_t *)&data[offset]
#define GRAB32(dst, offset) (dst) = *(uint32_t *)&data[offset]

const char *pdu_type_str(uint8_t PDU_Type) {
	static const char *type_str[] = {
		"ADV_IND", "ADV_DIRECT_IND", "ADV_NONCONN_IND",
		"SCAN_REQ", "SCAN_RSP", "CONNECT_REQ",
		"ADV_SCAN_IND",
	};

	if (PDU_Type < sizeof(type_str) / sizeof(*type_str)) {
		return type_str[PDU_Type];
	}
	return "Reserved";
}

void le_adv_print(le_adv_t *adv) {
	int i;
	le_adv_ind_t *ai;
	le_scan_req_t *scan_req;
	le_scan_rsp_t *scan_rsp;
	le_adv_direct_ind_t *adi;
	le_connect_req_t *c;

	printf("    Type: %s\n", pdu_type_str(adv->PDU_Type));

	switch (adv->PDU_Type) {
		case ADV_IND:
		case ADV_NONCONN_IND:
		case ADV_SCAN_IND:
			ai = &adv->payload.adv_ind;
			_dump_addr_norev("AdvA:  ", ai->AdvA, adv->TxAdd);
			if (ai->data_len > 0) {
				printf("    AdvData:");
				for (i = 0; i < ai->data_len; ++i)
					printf(" %02x", ai->data[i]);
				printf("\n");
				_dump_scan_rsp_data(ai->data, ai->data_len);
			}
			break;
		case ADV_DIRECT_IND:
			adi = &adv->payload.adv_direct_ind;
			_dump_addr_norev("AdvA:  ", adi->AdvA,  adv->TxAdd);
			_dump_addr_norev("InitA: ", adi->InitA, adv->RxAdd);
			break;
		case SCAN_REQ:
			scan_req = &adv->payload.scan_req;
			_dump_addr_norev("ScanA: ", scan_req->ScanA, adv->TxAdd);
			_dump_addr_norev("AdvA:  ", scan_req->AdvA,  adv->RxAdd);
			break;
		case SCAN_RSP:
			scan_rsp = &adv->payload.scan_rsp;
			_dump_addr_norev("AdvA:  ", scan_rsp->AdvA,  adv->TxAdd);
			if (scan_rsp->data_len > 0) {
				printf("    ScanData:");
				for (i = 0; i < scan_rsp->data_len; ++i)
					printf(" %02x", scan_rsp->data[i]);
				printf("\n");
				_dump_scan_rsp_data(scan_rsp->data, scan_rsp->data_len);
			}
			break;
		case CONNECT_REQ:
			c = &adv->payload.connect_req;
			_dump_addr_norev("InitA: ", c->InitA, adv->TxAdd);
			_dump_addr_norev("Adva:  ", c->AdvA,  adv->RxAdd);
			printf("    AA:    %08x\n", c->AA);
			printf("    CRCInit: %06x\n", c->CRCInit);
			printf("    WinSize: %02x (%u)\n", c->WinSize, c->WinSize);
			printf("    WinOffset: %04x (%u)\n", c->WinOffset, c->WinOffset);
			printf("    Interval: %04x (%u)\n", c->Interval, c->Interval);
			printf("    Latency: %04x (%u)\n", c->Latency, c->Latency);
			printf("    Timeout: %04x (%u)\n", c->Timeout, c->Timeout);

			printf("    ChM:");
			for (i = 0; i < 5; ++i)
				printf(" %02x", c->ChM[i]);
			printf("\n");

			printf("    Hop: %d\n", c->Hop);
			printf("    SCA: %d, %s\n", c->SCA, CONNECT_SCA[c->SCA]);
			break;
	}
}

int le_parse_advertising(le_air_packet_t *p, le_adv_t *adv) {
	le_adv_ind_t *ai;
	le_adv_direct_ind_t *adi;
	le_scan_req_t *scan_req;
	le_scan_rsp_t *scan_rsp;
	le_connect_req_t *c;

	if (p->length < 2)
		return 0;

	uint8_t *data = p->symbols;

	adv->Length = data[1] & 0x3f;
	if (adv->Length > p->length)
		return 0;

	adv->PDU_Type = data[0] & 0xf;
	adv->TxAdd = data[0] & 0x40 ? 1 : 0;
	adv->RxAdd = data[0] & 0x80 ? 1 : 0;

	switch (adv->PDU_Type) {
		case ADV_IND:
		case ADV_NONCONN_IND:
		case ADV_SCAN_IND:
			if (adv->Length < 6)
				return 0;
			ai = &adv->payload.adv_ind;
			memcpy_reverse(ai->AdvA, &data[2], 6);
			ai->data_len = adv->Length - 6;
			ai->data = ai->data_len > 0 ? &data[8] : NULL;
			break;
		case ADV_DIRECT_IND:
			if (adv->Length != 6 + 6)
				return 0;
			adi = &adv->payload.adv_direct_ind;
			memcpy_reverse(adi->AdvA,  &data[2], 6);
			memcpy_reverse(adi->InitA, &data[8], 6);
			break;
		case SCAN_REQ:
			if (adv->Length != 6 + 6)
				return 0;
			scan_req = &adv->payload.scan_req;
			memcpy_reverse(scan_req->ScanA, &data[2], 6);
			memcpy_reverse(scan_req->AdvA,  &data[8], 6);
			break;
		case SCAN_RSP:
			if (adv->Length < 6)
				return 0;
			scan_rsp = &adv->payload.scan_rsp;
			memcpy_reverse(scan_rsp->AdvA, &data[2], 6);
			scan_rsp->data_len = adv->Length - 6;
			scan_rsp->data = scan_rsp->data_len > 0 ? &data[8] : NULL;
			break;
		case CONNECT_REQ:
			if (adv->Length != 34)
				return 0;
			c = &adv->payload.connect_req;
			memcpy_reverse(c->InitA, &data[2], 6);
			memcpy_reverse(c->AdvA, &data[8], 6);
			GRAB32(c->AA, 14);
			GRAB32(c->CRCInit, 18);
			c->CRCInit &= 0xffffff; // hack, because it's on 24 bits long
			GRAB8 (c->WinSize, 21);
			GRAB16(c->WinOffset, 22);
			GRAB16(c->Interval, 24);
			GRAB16(c->Latency, 26);
			GRAB16(c->Timeout, 28);
			memcpy_reverse(c->ChM, &data[30], 5);
			c->Hop = data[35] & 0x1f;
			c->SCA = data[35] >> 5;
			break;
		default:
			return 0;
	}

	return 1;
}
