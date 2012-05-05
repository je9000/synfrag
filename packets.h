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

void build_ethernet( struct ether_header *, char *, char *, short int );
void *append_tcp_syn( void *, struct tcphdr *, unsigned short, unsigned short );
void *append_icmp_ping( void *, struct icmp *, unsigned short );
void *append_icmp6_ping( void *, struct icmp6_hdr *, unsigned short );
void *append_bare_ipv4( struct ip *, char *, char *, unsigned char );
void *append_ipv4( struct ip *, char *, char *, unsigned char );
void *append_ipv4_short_frag1( struct ip *, char *, char *, unsigned char, unsigned short );
void *append_ipv4_frag2( struct ip *, char *, char *, unsigned char, unsigned short, unsigned short );
void *append_ipv4_optioned_frag1( struct ip *, char *, char *, unsigned char, unsigned short, unsigned short );
void *append_ipv6( struct ip6_hdr *, char *, char *, unsigned char, unsigned short );
void *append_ipv6_short_frag1( struct ip6_hdr *, char *, char *, unsigned char, unsigned short );
void *append_ipv6_optioned_frag1( struct ip6_hdr *, char *, char *, unsigned char, unsigned short, unsigned short );
void *append_ipv6_optioned2_frag1( struct ip6_hdr *, char *, char *, unsigned char, unsigned short, unsigned short );
void *append_ipv6_frag2( struct ip6_hdr *, char *, char *, unsigned char, unsigned short, unsigned short );
void *append_ipv6_frag2_offset( struct ip6_hdr *, char *, char *, unsigned char, unsigned short, unsigned short, unsigned short );
