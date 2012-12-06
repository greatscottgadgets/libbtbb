/* -*- c -*- */
/*
 * Copyright 2007 - 2010 Dominic Spill, Michael Ossmann                                                                                            
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
#ifndef INCLUDED_BLUETOOTH_PICONET_H
#define INCLUDED_BLUETOOTH_PICONET_H
#include "btbb.h"

/* number of hops in the hopping sequence (i.e. number of possible values of CLK1-27) */
#define SEQUENCE_LENGTH 134217728

/* number of aliased channels received */
#define ALIASED_CHANNELS 25

/* do all the precalculation that can be done before knowing the address */
void precalc(btbb_piconet *pnet);

/* do precalculation that requires the address */
void address_precalc(int address, btbb_piconet *pnet);

/* drop-in replacement for perm5() using lookup table */
int fast_perm(int z, int p_high, int p_low, btbb_piconet *pnet);

/* 5 bit permutation */
/* assumes z is constrained to 5 bits, p_high to 5 bits, p_low to 9 bits */
int perm5(int z, int p_high, int p_low);

/* determine channel for a particular hop */
/* replaced with gen_hops() for a complete sequence but could still come in handy */
char single_hop(int clock, btbb_piconet *pnet);

/* look up channel for a particular hop */
char hop(int clock, btbb_piconet *pnet);

#endif /* INCLUDED_BLUETOOTH_PICONET_H */
