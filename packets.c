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

#define __USE_BSD

#include <stdio.h>
#include <stdlib.h>
#include <err.h>
#include <string.h>

#ifdef __FreeBSD__
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in_systm.h>
#endif

#ifdef __linux
#define ETHERTYPE_IPV6 ETH_P_IPV6
#define __FAVOR_BSD
#endif

#include <arpa/inet.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <netinet/tcp.h>
#include <netinet/if_ether.h>
#include "checksums.h"
#include "constants.h"
#include "packets.h"

#define IP_FLAGS_OFFSET 13
#define SOURCE_PORT 44128
#define TCP_WINDOW 65535
 
#define FRAGMENT_OFFSET_TO_BYTES 8
#define MINIMUM_FRAGMENT_SIZE FRAGMENT_OFFSET_TO_BYTES
#define MINIMUM_PACKET_SIZE 68

/* Save time typing/screen real estate. */
#define SIZEOF_ICMP6 sizeof( struct icmp6_hdr )
#define SIZEOF_TCP sizeof( struct tcphdr )
#define SIZEOF_IPV4 sizeof( struct ip )
#define SIZEOF_IPV6 sizeof( struct ip6_hdr )
#define SIZEOF_ETHER sizeof( struct ether_header )
/* This size is fixed but extends past the standard basic icmp header. */
#define SIZEOF_PING 8

void build_ethernet( struct ether_header *ethh, char *srcmac, char *dstmac, short int ethertype )
{
    if ( sscanf( srcmac, "%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx",
            &ethh->ether_shost[0],
            &ethh->ether_shost[1],
            &ethh->ether_shost[2],
            &ethh->ether_shost[3],
            &ethh->ether_shost[4],
            &ethh->ether_shost[5] ) != 6 ) {
        errx( 1, "Unable to parse source MAC address" );
    }

    if ( sscanf( dstmac, "%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx",
            &ethh->ether_dhost[0],
            &ethh->ether_dhost[1],
            &ethh->ether_dhost[2],
            &ethh->ether_dhost[3],
            &ethh->ether_dhost[4],
            &ethh->ether_dhost[5] ) != 6 ) {
        errx( 1, "Unable to parse destination MAC address" );
    }

    ethh->ether_type = htons( ethertype );
}

void *append_tcp_syn( void *iph, struct tcphdr *tcph, unsigned short srcport, unsigned short dstport )
{
    tcph->th_sport = htons( srcport );
    tcph->th_dport = htons( dstport );
    tcph->th_seq = htonl( rand() );
    tcph->th_ack = 0;
    tcph->th_x2 = 0;
    tcph->th_off = SIZEOF_TCP / 4;
    tcph->th_flags = TH_SYN;
    tcph->th_win = TCP_WINDOW;
    tcph->th_sum = 0;
    tcph->th_urp = 0;

    return (char *)tcph + SIZEOF_TCP;
}

void *append_icmp_ping( void *iph, struct icmp *icmph, unsigned short payload_length )
{
    icmph->icmp_type = ICMP_ECHO;
    icmph->icmp_code = 0;
    icmph->icmp_cksum = 0;
    icmph->icmp_id = htons( SOURCE_PORT );
    icmph->icmp_seq = htons( 1 );
    memset( (char *) icmph + SIZEOF_PING, 0x01, payload_length );

    return (char *)icmph + SIZEOF_PING + payload_length;
}

void *append_icmp6_ping( void *iph, struct icmp6_hdr *icmp6h, unsigned short payload_length )
{
    icmp6h->icmp6_type = ICMP6_ECHO_REQUEST;
    icmp6h->icmp6_code = 0;
    icmp6h->icmp6_cksum = 0;
    icmp6h->icmp6_id = htons( SOURCE_PORT );
    icmp6h->icmp6_seq = htons( 1 );
    memset( (char *) icmp6h + SIZEOF_ICMP6, 0x01, payload_length );

    return (char *)icmp6h + SIZEOF_ICMP6 + payload_length;
}

void *append_bare_ipv4( struct ip *iph, char *srcip, char *dstip, unsigned char protocol )
{
    iph->ip_v = 4;
    iph->ip_hl = 5;
    iph->ip_tos = 0;
    iph->ip_len = htons( SIZEOF_IPV4 + SIZEOF_TCP );
    iph->ip_id = 0;
    iph->ip_off = 0;
    iph->ip_ttl = IPDEFTTL;
    iph->ip_p = protocol;
    iph->ip_sum = 0;
    iph->ip_src.s_addr = inet_addr(srcip);
    iph->ip_dst.s_addr = inet_addr(dstip);

    return (char *)iph + SIZEOF_IPV4;
}

void *append_ipv4( struct ip *iph, char *srcip, char *dstip, unsigned char protocol )
{
    return append_bare_ipv4( iph, srcip, dstip, protocol );
}

void *append_ipv4_short_frag1( struct ip *iph, char *srcip, char *dstip, unsigned char protocol, unsigned short fragid )
{
    append_bare_ipv4( iph, srcip, dstip, protocol );
    iph->ip_off = htons( 1 << IP_FLAGS_OFFSET ); /* Set More Fragments (MF) bit */
    iph->ip_id = htons( fragid );
    iph->ip_len = htons( SIZEOF_IPV4 + MINIMUM_FRAGMENT_SIZE );

    return (char *)iph + SIZEOF_IPV4;
}

void *append_ipv4_frag2( struct ip *iph, char *srcip, char *dstip, unsigned char protocol, unsigned short fragid, unsigned short payload_length )
{
    append_bare_ipv4( iph, srcip, dstip, protocol );
    iph->ip_off = htons( 1 );
    iph->ip_id = htons( fragid );
    iph->ip_len = htons( SIZEOF_IPV4 + payload_length );

    return (char *)iph + SIZEOF_IPV4;
}

void *append_ipv4_optioned_frag1( struct ip *iph, char *srcip, char *dstip, unsigned char protocol, unsigned short fragid, unsigned short optlen )
{
    append_bare_ipv4( iph, srcip, dstip, protocol );
    iph->ip_off = htons( 1 << IP_FLAGS_OFFSET ); /* Set More Fragments (MF) bit */
    iph->ip_id = htons( fragid );
    iph->ip_len = htons( SIZEOF_IPV4 + optlen + MINIMUM_FRAGMENT_SIZE );

    if ( optlen % 4 != 0 ) errx( 1, "optlen must be a multiple of 4" );
    iph->ip_hl = 5 + ( optlen / 4 );

    /* Pad with NOP's and then end-of-padding option. */
    memset( (char *) iph + SIZEOF_IPV4, 0x01, optlen );
    *( (char *) iph + SIZEOF_IPV4 + optlen ) = 0;

    return (char *)iph + SIZEOF_IPV4 + optlen;
}

void *append_ipv6( struct ip6_hdr *ip6h, char *srcip, char *dstip, unsigned char protocol, unsigned short payload_length )
{
    /* 4 bits version, 8 bits TC, 20 bits flow-ID. We only set the version bits. */
    ip6h->ip6_flow = htonl( 0x06 << 28 );
    ip6h->ip6_plen = htons( payload_length );
    ip6h->ip6_hlim = 64;
    ip6h->ip6_nxt = protocol;
    if ( !inet_pton( AF_INET6, srcip, &ip6h->ip6_src ) ) errx( 1, "Invalid source address" );
    if ( !inet_pton( AF_INET6, dstip, &ip6h->ip6_dst ) ) errx( 1, "Invalid source address" );

    return (char *)ip6h + SIZEOF_IPV6;
}

void *append_ipv6_short_frag1( struct ip6_hdr *ip6h, char *srcip, char *dstip, unsigned char protocol, unsigned short fragid )
{
    struct ip6_frag *fragh = (struct ip6_frag *) ( (char *)ip6h + SIZEOF_IPV6 );

    /* 4 bits version, 8 bits TC, 20 bits flow-ID. We only set the version bits. */
    ip6h->ip6_flow = htonl( 0x06 << 28 );
    ip6h->ip6_plen = htons( sizeof( struct ip6_frag ) + MINIMUM_FRAGMENT_SIZE );
    ip6h->ip6_hlim = 64;
    ip6h->ip6_nxt = IPPROTO_FRAGMENT;
    if ( !inet_pton( AF_INET6, srcip, &ip6h->ip6_src ) ) errx( 1, "Invalid source address" );
    if ( !inet_pton( AF_INET6, dstip, &ip6h->ip6_dst ) ) errx( 1, "Invalid source address" );

    fragh->ip6f_reserved = 0;
    fragh->ip6f_nxt = protocol;
    fragh->ip6f_ident = htons( fragid );
    fragh->ip6f_offlg = IP6F_MORE_FRAG;

    return (char *)ip6h + SIZEOF_IPV6 + sizeof( struct ip6_frag );
}

void *append_ipv6_optioned_frag1( struct ip6_hdr *ip6h, char *srcip, char *dstip, unsigned char protocol, unsigned short fragid, unsigned short optlen )
{
    struct ip6_dest *desth = (struct ip6_dest *) ( (char *)ip6h + SIZEOF_IPV6 );
    struct ip6_frag *fragh = (struct ip6_frag *) ( (char *)ip6h + SIZEOF_IPV6 + sizeof( struct ip6_dest ) + optlen );

    /* 4 bits version, 8 bits TC, 20 bits flow-ID. We only set the version bits. */
    ip6h->ip6_flow = htonl( 0x06 << 28 );
    ip6h->ip6_plen = htons( sizeof( struct ip6_dest ) + optlen + sizeof( struct ip6_frag ) + MINIMUM_FRAGMENT_SIZE );
    ip6h->ip6_hlim = 64;
    ip6h->ip6_nxt = IPPROTO_DSTOPTS;
    if ( !inet_pton( AF_INET6, srcip, &ip6h->ip6_src ) ) errx( 1, "Invalid source address" );
    if ( !inet_pton( AF_INET6, dstip, &ip6h->ip6_dst ) ) errx( 1, "Invalid source address" );

    if ( optlen == 0 || optlen % 8 != 6 ) errx( 1, "optlen value not supported" );
    desth->ip6d_nxt = IPPROTO_FRAGMENT;
    desth->ip6d_len = optlen / 8;

    *( (char *) desth + sizeof( struct ip6_dest ) ) = 1;
    *( (char *) desth + sizeof( struct ip6_dest ) + 1 ) = optlen - 2;
    memset( (char *) desth + sizeof( struct ip6_dest ) + 2, 0, optlen - 2 );

    fragh->ip6f_reserved = 0;
    fragh->ip6f_nxt = protocol;
    fragh->ip6f_ident = htons( fragid );
    fragh->ip6f_offlg = IP6F_MORE_FRAG;

    return (char *)ip6h + SIZEOF_IPV6 + sizeof( struct ip6_frag ) + sizeof( struct ip6_dest ) + optlen;
}

void *append_ipv6_optioned2_frag1( struct ip6_hdr *ip6h, char *srcip, char *dstip, unsigned char protocol, unsigned short fragid, unsigned short optlen )
{
    struct ip6_dest *desth = (struct ip6_dest *) ( (char *)ip6h + SIZEOF_IPV6 + sizeof( struct ip6_frag ));
    struct ip6_frag *fragh = (struct ip6_frag *) ( (char *)ip6h + SIZEOF_IPV6);

    /* 4 bits version, 8 bits TC, 20 bits flow-ID. We only set the version bits. */
    ip6h->ip6_flow = htonl( 0x06 << 28 );
    ip6h->ip6_plen = htons( sizeof( struct ip6_dest ) + optlen + sizeof( struct ip6_frag ) + MINIMUM_FRAGMENT_SIZE );
    ip6h->ip6_hlim = 64;
    ip6h->ip6_nxt = IPPROTO_FRAGMENT;
    if ( !inet_pton( AF_INET6, srcip, &ip6h->ip6_src ) ) errx( 1, "Invalid source address" );
    if ( !inet_pton( AF_INET6, dstip, &ip6h->ip6_dst ) ) errx( 1, "Invalid source address" );

    fragh->ip6f_reserved = 0;
    fragh->ip6f_nxt = IPPROTO_DSTOPTS;
    fragh->ip6f_ident = htons( fragid );
    fragh->ip6f_offlg = IP6F_MORE_FRAG;

    if ( optlen == 0 || optlen % 8 != 6 ) errx( 1, "optlen value not supported" );
    desth->ip6d_nxt = protocol;
    desth->ip6d_len = optlen / 8;

    *( (char *) desth + sizeof( struct ip6_dest ) ) = 1;
    *( (char *) desth + sizeof( struct ip6_dest ) + 1 ) = optlen - 2;
    memset( (char *) desth + sizeof( struct ip6_dest ) + 2, 0, optlen - 2 );

    return (char *)ip6h + SIZEOF_IPV6 + sizeof( struct ip6_frag ) + sizeof( struct ip6_dest ) + optlen;
}

void *append_ipv6_frag2( struct ip6_hdr *ip6h, char *srcip, char *dstip, unsigned char protocol, unsigned short fragid, unsigned short payload_length )
{
    return append_ipv6_frag2_offset( ip6h, srcip, dstip, protocol, fragid, payload_length, 8 );
}

void *append_ipv6_frag2_offset( struct ip6_hdr *ip6h, char *srcip, char *dstip, unsigned char protocol, unsigned short fragid, unsigned short payload_length, unsigned short optlen )
{
    struct ip6_frag *fragh = (struct ip6_frag *) ( (char *)ip6h + SIZEOF_IPV6 );
    unsigned short offset = optlen + sizeof( struct ip6_dest ) + MINIMUM_FRAGMENT_SIZE;

    if ( offset % 8 != 0 ) errx( 1, "wrong size" );
    offset = offset / 8;

    /* 4 bits version, 8 bits TC, 20 bits flow-ID. We only set the version bits. */
    ip6h->ip6_flow = htonl( 0x06 << 28 );
    ip6h->ip6_plen = htons( payload_length + sizeof( struct ip6_frag ) );
    ip6h->ip6_hlim = 64;
    ip6h->ip6_nxt = IPPROTO_FRAGMENT;
    if ( !inet_pton( AF_INET6, srcip, &ip6h->ip6_src ) ) errx( 1, "Invalid source address" );
    if ( !inet_pton( AF_INET6, dstip, &ip6h->ip6_dst ) ) errx( 1, "Invalid source address" );

    fragh->ip6f_reserved = 0;
    fragh->ip6f_nxt = IPPROTO_DSTOPTS;
    fragh->ip6f_ident = htons( fragid );
    fragh->ip6f_offlg = htons( offset << 3 );

    return (char *)ip6h + SIZEOF_IPV6 + sizeof( struct ip6_frag );
}

