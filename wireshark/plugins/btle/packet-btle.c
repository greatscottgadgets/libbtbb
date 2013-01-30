/* packet-btle.c
 * Routines for Bluetooth Low Energy dissection
 * Copyright 2013, Mike Ryan, mikeryan /at/ isecpartners /dot/ com
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <wireshark/config.h> /* needed for epan/gcc-4.x */
#include <epan/packet.h>
#include <epan/prefs.h>

/* function prototypes */
void proto_reg_handoff_btle(void);

/* initialize the protocol and registered fields */
static int proto_btle = -1;
static int hf_btle_pkthdr = -1;
static int hf_btle_aa = -1;
static int hf_btle_type = -1;
static int hf_btle_randomized_tx = -1;
static int hf_btle_randomized_rx = -1;
static int hf_btle_length = -1;
static int hf_btle_adv_addr = -1;
static int hf_btle_adv_data = -1;
static int hf_btle_init_addr = -1;
static int hf_btle_scan_addr = -1;
static int hf_btle_scan_rsp_data = -1;
static int hf_btle_connect = -1;
static int hf_btle_connect_aa = -1;
static int hf_btle_crc_init = -1;
static int hf_btle_win_size = -1;
static int hf_btle_win_offset = -1;
static int hf_btle_interval = -1;
static int hf_btle_latency = -1;
static int hf_btle_timeout = -1;
static int hf_btle_crc = -1;

static const value_string packet_types[] = {
	{ 0x0, "ADV_IND" },
	{ 0x1, "ADV_DIRECT_IND" },
	{ 0x2, "ADV_NONCONN_IND" },
	{ 0x3, "SCAN_REQ" },
	{ 0x4, "SCAN_RSP" },
	{ 0x5, "CONNECT_REQ" },
	{ 0x6, "ADV_SCAN_IND" },
	{ 0, NULL }
};

static const value_string llid_codes[] = {
	{ 0x0, "undefined" },
	{ 0x1, "Continuation fragment of an L2CAP message (ACL-U)" },
	{ 0x2, "Start of an L2CAP message or no fragmentation (ACL-U)" },
	{ 0x3, "LMP message (ACL-C)" },
	{ 0, NULL }
};

/* initialize the subtree pointers */
static gint ett_btle = -1;
static gint ett_btle_pkthdr = -1;
static gint ett_btle_connect = -1;

/* subdissectors */
static dissector_handle_t btl2cap_handle = NULL;

void
dissect_adv_ind_or_nonconn_or_scan(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int offset, int datalen)
{
	const guint8 *adv_addr;

	DISSECTOR_ASSERT(tvb_length_remaining(tvb, offset) >= 1);

	adv_addr = tvb_get_ptr(tvb, offset, 6);
	SET_ADDRESS(&pinfo->src, AT_ETHER, 6, adv_addr);

	proto_tree_add_ether(tree, hf_btle_adv_addr, tvb, offset, 6, adv_addr);
	proto_tree_add_item(tree, hf_btle_adv_data, tvb, offset + 6, datalen, TRUE);
}

void
dissect_adv_direct_ind(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int offset)
{
	const guint8 *adv_addr, *init_addr;

	DISSECTOR_ASSERT(tvb_length_remaining(tvb, offset) >= 1);

	adv_addr = tvb_get_ptr(tvb, offset, 6);
	SET_ADDRESS(&pinfo->src, AT_ETHER, 6, adv_addr);
	init_addr = tvb_get_ptr(tvb, offset+6, 6);
	SET_ADDRESS(&pinfo->dst, AT_ETHER, 6, init_addr);

	proto_tree_add_ether(tree, hf_btle_adv_addr, tvb, offset, 6, adv_addr);
	proto_tree_add_ether(tree, hf_btle_init_addr, tvb, offset + 6, 6, init_addr);
}

void
dissect_scan_req(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int offset)
{
	const guint8 *scan_addr, *adv_addr;

	DISSECTOR_ASSERT(tvb_length_remaining(tvb, offset) >= 1);

	scan_addr = tvb_get_ptr(tvb, offset, 6);
	SET_ADDRESS(&pinfo->src, AT_ETHER, 6, scan_addr);
	adv_addr = tvb_get_ptr(tvb, offset+6, 6);
	SET_ADDRESS(&pinfo->dst, AT_ETHER, 6, adv_addr);

	proto_tree_add_ether(tree, hf_btle_scan_addr, tvb, offset, 6, scan_addr);
	proto_tree_add_ether(tree, hf_btle_adv_addr, tvb, offset+6, 6, adv_addr);
}

void
dissect_scan_rsp(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int offset, int datalen)
{
	const guint8 *adv_addr;

	DISSECTOR_ASSERT(tvb_length_remaining(tvb, offset) >= 1);

	adv_addr = tvb_get_ptr(tvb, offset, 6);
	SET_ADDRESS(&pinfo->src, AT_ETHER, 6, adv_addr);

	proto_tree_add_ether(tree, hf_btle_adv_addr, tvb, offset, 6, adv_addr);
	proto_tree_add_item(tree, hf_btle_scan_rsp_data, tvb, offset + 6, datalen, TRUE);
}

void
dissect_connect_req(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int offset)
{
	proto_item *connect_item;
	proto_tree *connect_tree;
	const guint8 *adv_addr, *init_addr;


	DISSECTOR_ASSERT(tvb_length_remaining(tvb, offset) >= 1);

	init_addr = tvb_get_ptr(tvb, offset, 6);
	SET_ADDRESS(&pinfo->src, AT_ETHER, 6, init_addr);
	adv_addr = tvb_get_ptr(tvb, offset+6, 6);
	SET_ADDRESS(&pinfo->dst, AT_ETHER, 6, adv_addr);

	proto_tree_add_ether(tree, hf_btle_init_addr, tvb, offset, 6, init_addr);
	proto_tree_add_ether(tree, hf_btle_adv_addr, tvb, offset + 6, 6, adv_addr);
	offset += 12;

	connect_item = proto_tree_add_item(tree, hf_btle_connect, tvb, offset, 22, TRUE);
	connect_tree = proto_item_add_subtree(connect_item, ett_btle_connect);

	proto_tree_add_item(connect_tree, hf_btle_connect_aa,	tvb, offset+ 0, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(connect_tree, hf_btle_crc_init,		tvb, offset+ 4, 3, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(connect_tree, hf_btle_win_size,		tvb, offset+ 7, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(connect_tree, hf_btle_win_offset,	tvb, offset+ 8, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(connect_tree, hf_btle_interval,		tvb, offset+10, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(connect_tree, hf_btle_latency,		tvb, offset+12, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(connect_tree, hf_btle_timeout,		tvb, offset+14, 2, ENC_LITTLE_ENDIAN);
}

/* dissect a packet */
static void
dissect_btle(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item *btle_item, *pkthdr_item, *pld_item;
	proto_tree *btle_tree, *pkthdr_tree;
	int offset;
	guint8 type, length;

#if 0
	/* sanity check: length */
	if (tvb_length(tvb) > 0 && tvb_length(tvb) < 9)
		/* bad length: look for a different dissector */
		return 0;
#endif

	/* make entries in protocol column and info column on summary display */
	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "Bluetooth LE");

	type = tvb_get_guint8(tvb, 4) & 0xf;
	length = tvb_get_guint8(tvb, 5) & 0x3f;

	/* see if we are being asked for details */
	if (tree) {

		/* create display subtree for the protocol */
		offset = 0;
		btle_item = proto_tree_add_item(tree, proto_btle, tvb, offset, -1, TRUE);
		btle_tree = proto_item_add_subtree(btle_item, ett_btle);

		proto_tree_add_item(btle_tree, hf_btle_aa, tvb, offset, 4, TRUE);
		offset += 4;

		/* packet header */
		pkthdr_item = proto_tree_add_item(btle_tree, hf_btle_pkthdr, tvb, offset, 2, TRUE);
		pkthdr_tree = proto_item_add_subtree(pkthdr_item, ett_btle_pkthdr);

		proto_tree_add_item(pkthdr_tree, hf_btle_type, tvb, offset, 1, TRUE);
		proto_tree_add_item(pkthdr_tree, hf_btle_randomized_tx, tvb, offset, 1, TRUE);
		proto_tree_add_item(pkthdr_tree, hf_btle_randomized_rx, tvb, offset, 1, TRUE);
		offset += 1;

		proto_tree_add_item(pkthdr_tree, hf_btle_length, tvb, offset, 1, TRUE);
		offset += 1;

		if (check_col(pinfo->cinfo, COL_INFO)) {
			if (type <= 0x6) {
				col_set_str(pinfo->cinfo, COL_INFO, packet_types[type].strptr);
			} else {
				col_set_str(pinfo->cinfo, COL_INFO, "Unknown");
			}
		}

		/* payload */
		switch (type) {
		case 0x0: // ADV_IND
		case 0x2: // ADV_NONCONN_IND
		case 0x6: // ADV_SCAN_IND
			dissect_adv_ind_or_nonconn_or_scan(btle_tree, tvb, pinfo, offset, length - 6);
			break;
		case 0x1: // ADV_DIRECT_IND
			dissect_adv_direct_ind(btle_tree, tvb, pinfo, offset);
			break;
		case 0x3:
			dissect_scan_req(btle_tree, tvb, pinfo, offset);
			break;
		case 0x4: // SCAN_RSP
			dissect_scan_rsp(btle_tree, tvb, pinfo, offset, length - 6);
			break;
		case 0x5: // CONNECT_REQ
			dissect_connect_req(btle_tree, tvb, pinfo, offset);
			break;
		default:
			break;
		}

		offset += length;
		proto_tree_add_item(btle_tree, hf_btle_crc, tvb, offset, 3, TRUE);
	}

	return;
}

/* register the protocol with Wireshark */
void
proto_register_btle(void)
{

	/* list of fields */
	static hf_register_info hf[] = {
		{ &hf_btle_aa,
			{ "Access Address", "btle.aa",
			FT_UINT32, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},

		{ &hf_btle_pkthdr,
			{ "Packet Header", "btle.pkthdr",
			FT_NONE, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},

		{ &hf_btle_type,
			{ "TYPE", "btle.type",
			FT_UINT8, BASE_HEX, VALS(packet_types), 0x0,
			"Packet Type", HFILL }
		},
		{ &hf_btle_randomized_tx,
			{ "Randomized TX Address", "btle.randomized_tx",
			FT_BOOLEAN, 8, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_btle_randomized_rx,
			{ "Randomized RX Address", "btle.randomized_rx",
			FT_BOOLEAN, 8, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_btle_length,
			{ "Length", "btle.length",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_btle_adv_addr,
			{ "Advertising Address", "btle.adv_addr",
			FT_ETHER, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_btle_init_addr,
			{ "Init Address", "btle.init_addr",
			FT_ETHER, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_btle_scan_addr,
			{ "Scan Address", "btle.scan_addr",
			FT_ETHER, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_btle_adv_data,
			{ "Advertising Data", "btle.adv_data",
			FT_BYTES, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_btle_scan_rsp_data,
			{ "Scan Response Data", "btle.scan_rsp_data",
			FT_BYTES, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},

		// connection packet fields
		{ &hf_btle_connect,
			{ "Connection Request", "btle.connect",
			FT_NONE, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_btle_connect_aa,
			{ "Connection AA", "btle.connect.aa",
			FT_UINT32, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_btle_crc_init,
			{ "CRC Init", "btle.connect.crc_init",
			FT_UINT24, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_btle_win_size,
			{ "Window Size", "btle.connect.win_size",
			FT_UINT8, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_btle_win_offset,
			{ "Window Offset", "btle.connect.win_offset",
			FT_UINT16, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_btle_interval,
			{ "Interval", "btle.connect.interval",
			FT_UINT16, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_btle_latency,
			{ "Latency", "btle.connect.latency",
			FT_UINT16, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_btle_timeout,
			{ "Timeout", "btle.connect.timeout",
			FT_UINT16, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},

		{ &hf_btle_crc,
			{ "CRC", "btle.crc",
			FT_UINT24, BASE_HEX, NULL, 0x0,
			"Ticklish Redundancy Check", HFILL }
		},
	};

	/* protocol subtree arrays */
	static gint *ett[] = {
		&ett_btle,
		&ett_btle_pkthdr,
		&ett_btle_connect,
	};

	/* register the protocol name and description */
	proto_btle = proto_register_protocol(
		"Bluetooth Low Energy",	/* full name */
		"BTLE",			/* short name */
		"btle"			/* abbreviation (e.g. for filters) */
		);

	register_dissector("btle", dissect_btle, proto_btle);

	/* register the header fields and subtrees used */
	proto_register_field_array(proto_btle, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_btle(void)
{
	static gboolean inited = FALSE;

	if (!inited) {
		dissector_handle_t btle_handle;

		// btle_handle = new_create_dissector_handle(dissect_btle, proto_btle);
		// dissector_add("ppi.dlt", 147, btle_handle);

		btl2cap_handle = find_dissector("btl2cap");

		inited = TRUE;
	}
}
