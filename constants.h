/*
 * Copyright (c) 2012, Yahoo! Inc All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *     Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.  Redistributions
 *     in binary form must reproduce the above copyright notice, this list
 *     of conditions and the following disclaimer in the documentation and/or
 *     other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Author: John Eaglesham
 */

#define DEFAULT_TIMEOUT_SECONDS 10
#define IP_FLAGS_OFFSET 13
#define SOURCE_PORT 44128
#define BIG_PACKET_SIZE 1500
#define PCAP_CAPTURE_LEN BIG_PACKET_SIZE
#define TCP_WINDOW 65535
#define MAC_ADDRESS_STRING_LENGTH 17 /* Length of 00:00:00:00:00:00 */
/*
 * If this is ever big enough to exceed BIG_PACKET_SIZE when added with the
 * sizes of the other (IPv4/IPv6+destination options+fragmentation+padding)
 * headers, a buffer will overflow. So don't do that.
 */
#define FRAGMENT_OFFSET_TO_BYTES 8
#define MINIMUM_FRAGMENT_SIZE FRAGMENT_OFFSET_TO_BYTES
#define MINIMUM_PACKET_SIZE 68
#define DEFAULT_SRCPORT 44129

/* Save time typing/screen real estate. */
#define SIZEOF_ICMP6 sizeof( struct icmp6_hdr )
#define SIZEOF_TCP sizeof( struct tcphdr )
#define SIZEOF_IPV4 sizeof( struct ip )
#define SIZEOF_IPV6 sizeof( struct ip6_hdr )
#define SIZEOF_ETHER sizeof( struct ether_header )
#define SIZEOF_FRAG sizeof( struct ip6_frag )
/* SIZEOF_DESTOPT be < 8 as per RFC2460 */
#define SIZEOF_DESTOPT sizeof( struct ip6_dest )
/* This size is fixed but extends past the standard basic icmp header. */
#define SIZEOF_PING 8
