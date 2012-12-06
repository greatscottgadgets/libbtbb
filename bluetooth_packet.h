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
#include "btbb.h"

/* type-specific CRC checks and decoding */
int fhs(int clock, btbb_packet* p);
int DM(int clock, btbb_packet* p);
int DH(int clock, btbb_packet* p);
int EV3(int clock, btbb_packet* p);
int EV4(int clock, btbb_packet* p);
int EV5(int clock, btbb_packet* p);
int HV(int clock, btbb_packet* p);

/* check if the packet's CRC is correct for a given clock (CLK1-6) */
int crc_check(int clock, btbb_packet* p);

/* format payload for tun interface */
char *tun_format(btbb_packet* p);

/* try a clock value (CLK1-6) to unwhiten packet header,
 * sets resultant d_packet_type and d_UAP, returns UAP.
 */
uint8_t try_clock(int clock, btbb_packet* p);

/* extract LAP from FHS payload */
uint32_t lap_from_fhs(btbb_packet* p);

/* extract UAP from FHS payload */
uint8_t uap_from_fhs(btbb_packet* p);

/* extract NAP from FHS payload */
uint16_t nap_from_fhs(btbb_packet* p);

/* extract clock from FHS payload */
uint32_t clock_from_fhs(btbb_packet* p);

#endif /* INCLUDED_BLUETOOTH_PACKET_H */
