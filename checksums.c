/*
 * This file originally appeared as part of libnet. This version has been
 * modified.
 *
 *  Copyright (c) 1998 - 2001 Mike D. Schiffman <mike@infonexus.com>
 *  Copyright (c) 1999, 2000 Dug Song <dugsong@monkey.org>
 *  Copyright (c) 2005, 2012 John Eaglesham
 *  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <unistd.h>

#ifdef __FreeBSD__
#include <netinet/in_systm.h>
#endif

#ifdef __linux
#define __FAVOR_BSD
#endif

#include <arpa/inet.h>
#include <sys/types.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include "checksums.h"

int in_cksum(unsigned short *addr, int len)
{
    int sum;
    int nleft;
    unsigned short ans;
    unsigned short *w;

    sum = 0;
    ans = 0;
    nleft = len;
    w = addr;

    while (nleft > 1)
    {
        sum += *w++;
        nleft -= 2;
    }
    if (nleft == 1)
    {
        *(unsigned char *)(&ans) = *(unsigned char *)w;
        sum += ans;
    }
    return (sum);
}

int do_checksum(char *buf, int protocol, int len)
{
    /* Set to NULL to avoid compiler warnings. */
    struct ip *iph_p = NULL;
    struct ip6_hdr *ip6h_p = NULL;
    int ip_hl;
    int sum = 0;
    int ip_version = buf[0] >> 4;

    if ( ip_version == 6 ) {
        int next_header;
        ip6h_p = (struct ip6_hdr *)buf;
        next_header = ip6h_p->ip6_ctlun.ip6_un1.ip6_un1_nxt;
        ip_hl = sizeof( struct ip6_hdr );

        while( next_header != protocol ) {
            switch ( next_header )
            {
                case IPPROTO_FRAGMENT:
                    next_header = ( (struct ip6_frag *) ( buf + ip_hl ) )->ip6f_nxt;
                    ip_hl += sizeof( struct ip6_frag );
                    break;
                case IPPROTO_DSTOPTS:
                case IPPROTO_HOPOPTS:
                    next_header = ( (struct ip6_dest *) ( buf + ip_hl ) )->ip6d_nxt;
                    ip_hl += ( ( (struct ip6_dest *) ( buf + ip_hl ) )->ip6d_len * 8 ) + 8;
                    break;
                default:
                    return 0;
            }
        }
    } else if ( ip_version == 4 ) {
        iph_p = (struct ip *)buf;
        /*
         * This should mask off the top 4 bits first, but we know they are
         * 0100 so shifting left by 2 means the top 2 bits are ignored.
         */
        ip_hl = iph_p->ip_hl << 2;
    } else {
        return (0);
    }
    if ( ip_hl < 0 ) return -2;

    /*
     *  Dug Song came up with this very cool checksuming implementation
     *  eliminating the need for explicit psuedoheader use.  Check it out.
     */
    switch (protocol)
    {
        /*
         *  Style note: normally I don't advocate declaring variables inside
         *  blocks of control, but it makes good sense here. -- MDS
         */
        case IPPROTO_UDP:
        {
            struct udphdr *udph_p =
                (struct udphdr *)(buf + ip_hl);
            //if ( ip_hl + sizeof( struct udphdr ) > len ) return -2;

            udph_p->uh_sum = 0;
            if (ip_version == 6)
            {
                sum = in_cksum((unsigned short *)&ip6h_p->ip6_src, 32);
            }
            else /* If not 6 we know it's 4 as we only allow 6 and 4 above. */
            {
                sum = in_cksum((void *)&iph_p->ip_src, 8);
            }
            sum += ntohs(IPPROTO_UDP + len);
            sum += in_cksum((unsigned short *)udph_p, len);
            udph_p->uh_sum = CKSUM_CARRY(sum);
            break;
        }
        case IPPROTO_TCP:
        {
            struct tcphdr *tcph_p =
                (struct tcphdr *)(buf + ip_hl);
            //if ( ip_hl + sizeof( struct tcphdr ) > len ) return -2;

            tcph_p->th_sum = 0;
            if (ip_version == 6)
            {
                sum = in_cksum((unsigned short *)&ip6h_p->ip6_src, 32);
            }
            else /* If not 6 we know it's 4 as we only allow 6 and 4 above. */
            {
                sum = in_cksum((void *)&iph_p->ip_src, 8);
            }
            sum += ntohs(IPPROTO_TCP + len);
            sum += in_cksum((unsigned short *)tcph_p, len);
            tcph_p->th_sum = CKSUM_CARRY(sum);
            break;
        }
        case IPPROTO_ICMP:
        {
            struct icmp *icmph_p =
                (struct icmp *)(buf + ip_hl);
            //if ( ip_hl + sizeof( struct icmphdr ) > len ) return -2;

            icmph_p->icmp_cksum = 0;
            sum = in_cksum((unsigned short *)icmph_p, len);
            icmph_p->icmp_cksum = CKSUM_CARRY(sum);
            break;
        }
        case IPPROTO_ICMPV6:
        {
            struct icmp6_hdr *icmp6h_p =
                (struct icmp6_hdr *)(buf + ip_hl);
            //if ( ip_hl + sizeof( struct icmp6_hdr ) > len ) return -2;

            if (ip_version == 6)
            {
                sum = in_cksum((unsigned short *)&ip6h_p->ip6_src, 32);
            }
            else
            {
                return 0;
            }
            sum += ntohs(IPPROTO_ICMPV6 + len);
            icmp6h_p->icmp6_cksum = 0;
            sum += in_cksum((unsigned short *)icmp6h_p, len);
            icmp6h_p->icmp6_cksum = CKSUM_CARRY(sum);
            break;
        }
        case IPPROTO_IP:
        {
            iph_p->ip_sum = 0;
            sum = in_cksum((unsigned short *)iph_p, len);
            iph_p->ip_sum = CKSUM_CARRY(sum);
            break;
        }
        default:
        {
            return (-1);
        }
    }
    return (1);
}

