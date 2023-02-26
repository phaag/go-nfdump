/*
 *  Copyright (c) 2022, Peter Haag
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *   * Neither the name of the author nor the names of its contributors may be
 *     used to endorse or promote products derived from this software without
 *     specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifndef _EXPORTER_H
#define _EXPORTER_H 1

#include <stdint.h>

// single IP addr for next hop and bgp next hop
typedef struct ip_addr_s {
    union {
        struct {
            uint32_t fill1[2];
            uint32_t _v4;
            uint32_t fill2;
        };
        uint64_t _v6[2];
    } ip_addr;
} ip_addr_t;

typedef struct exporter_info_record_s {
    uint16_t type;
    uint16_t size;

    // exporter version
    uint32_t version;

    // IP address
    uint64_t ip[2];
    uint16_t sa_family;

    // internal assigned ID
    uint16_t sysid;

    // exporter ID/Domain ID/Observation Domain ID assigned by the device
    uint32_t id;

} exporter_info_record_t;

typedef struct exporter_stats_record_s {
    uint16_t type;
    uint16_t size;

    uint32_t stat_count;  // number of stat records

    struct exporter_stat_s {
        uint32_t sysid;             // identifies the exporter
        uint32_t sequence_failure;  // number of sequence failures
        uint64_t packets;           // number of packets sent by this exporter
        uint64_t flows;             // number of flow records sent by this exporter
    } stat;

} exporter_stats_record_t;

typedef struct sampler_record_s {
    // record header
    uint16_t type;
    uint16_t size;

    // sampler data
    uint16_t exporter_sysid;  // internal reference to exporter
    uint16_t algorithm;       // #304 sampling algorithm
    int64_t id;               // #302 id assigned by the exporting device or
#define SAMPLER_OVERWRITE -3
#define SAMPLER_DEFAULT -2
#define SAMPLER_GENERIC -1
    uint32_t packetInterval;  // #305 packet interval
    uint32_t spaceInterval;   // #306 packet space
} sampler_record_t;

#endif