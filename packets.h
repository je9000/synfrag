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

void *append_ethernet( void *, char *, char *, unsigned short );
void *append_tcp( void *, unsigned short, unsigned short, int, uint32_t, uint32_t );
void *append_tcp_syn( void *, unsigned short, unsigned short, uint32_t );
void *append_icmp_ping( void *, unsigned short );
void *append_icmp6_ping( void *, unsigned short );
void *append_ipv4( void *, char *, char *, unsigned char );
void *append_ipv4_short_frag1( void *, char *, char *, unsigned char, unsigned short );
void *append_ipv4_frag2( void *, char *, char *, unsigned char, unsigned short, unsigned short );
void *append_ipv4_optioned_frag1( void *, char *, char *, unsigned char, unsigned short, unsigned short );
void *append_ipv6( void *, char *, char *, unsigned char, unsigned short );
void *append_frag( void *, unsigned char, unsigned short, unsigned short, int );
void *append_dest( void *, unsigned char, unsigned int );

#define append_frag_first( buf, proto, fragid ) append_frag( buf, proto, 0, fragid, 1 )
#define append_frag_last( buf, proto, offset, fragid ) append_frag( buf, proto, offset, fragid, 0 )
