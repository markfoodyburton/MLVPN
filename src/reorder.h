/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2014 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *   Adapted for mlvpn by Laurent Coustet (c) 2015
 * 
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef MLVPN_REORDER_H
#define MLVPN_REORDER_H

#include "pkt.h"

/**
 * @file
 * mlvpn reorder
 *
 * Reorder library is a component which is designed to
 * provide ordering of out of ordered packets based on
 * sequence number present in pkt.
 *
 */


/**
 * Initializes reorder buffer, called once (from main)
 * (initially disabled)
 */
void mlvpn_reorder_init();

/**
 * Reset the reorder buffer instance with initial values.
 * (initially disabled)
 */
void mlvpn_reorder_reset();

/**
 * adjust timeout
 */
void mlvpn_reorder_adjust_timeout(double t);


/**
 * ENABLE reorder buffer.
 *
 */
void mlvpn_reorder_enable();

/**
 * Insert given pkt in reorder buffer in its correct position
 *
 * The given pkt is to be reordered relative to other pkts in the system.
 * The pkt must contain a sequence number which is then used to place
 * the buffer in the correct position in the reorder buffer. Reordered
 * packets can later be taken from the buffer using the mlvpn_reorder_drain()
 * API.
 *
 * @param pkt
 *   pkt that needs to be inserted in reorder buffer.
 */
void mlvpn_reorder_insert(mlvpn_pkt_t *pkt);


#endif /* MLVPN_REORDER_H */
