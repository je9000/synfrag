/*
 * Copyright (c) 2012-2013, Yahoo! Inc All rights reserved.
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

#ifdef __FreeBSD__
#define DO_TAP
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <err.h>
#include <string.h>
#include <netdb.h>

#if defined(__FreeBSD__) || ( defined(__APPLE__) && defined(__MACH__) )
#include <netinet/in_systm.h>
#include <ifaddrs.h>
#include <net/if_dl.h>
#endif

#ifdef DO_TAP
#include <net/if_tap.h>
#endif

#ifdef __linux
#define ETHERTYPE_IPV6 ETH_P_IPV6
#define __FAVOR_BSD
#endif

#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/time.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <netinet/tcp.h>
#include <netinet/if_ether.h>
#include <net/if.h>
#include <pcap.h>
#include <signal.h>
#include <sys/wait.h>
#include <getopt.h>
#include "flag_names.h"
#include "packets.h"
#include "constants.h"
#include "checksums.h"

/*
 * XXX We don't close the pcap device on failure anywhere. The OS will do it
 * for us, but it's impolite.
 */

/*
 * This might turn out to be stupid, but lets try having TCP tests be odd
 * numbered and ICMP even numbered. IPv4 tests will be <= 10 and IPv6 > 10.
 */
#define IS_TEST_TCP(x) ( x % 2 == 1 )
#define IS_TEST_ICMP(x) ( x % 2 == 0 )
#define IS_TEST_IPV4(x) ( x <= 10 )
#define IS_TEST_IPV6(x) ( x > 10 )
enum TEST_TYPE {
    TEST_IPV4_TCP = 1,
    TEST_IPV4_FRAG_TCP = 3,
    TEST_IPV4_DSTOPT_FRAG_TCP = 5,

    TEST_IPV4_FRAG_ICMP = 2,
    TEST_IPV4_DSTOPT_FRAG_ICMP = 4,

    TEST_IPV6_TCP = 11,
    TEST_IPV6_FRAG_TCP = 13,
    TEST_IPV6_DSTOPT_FRAG_TCP = 15,
    TEST_IPV6_FRAG_DSTOPT_TCP = 17,
    TEST_IPV6_FRAG_FRAG_TCP = 19,
    TEST_IPV6_FRAG_NOMORE_TCP = 21,
    TEST_IPV6_MANY_FRAG_NOMORE_TCP = 23,
    TEST_IPV6_BIG_DSTOPT_TCP = 25,
    TEST_IPV6_SMALL_DSTOPT_TCP = 27,
    TEST_IPV6_MANY_SMALL_DSTOPT_TCP = 29,
    TEST_IPV6_MANY_BIG_DSTOPT_TCP = 31,
    TEST_IPV6_FRAG_DSTOPT2_TCP = 33,
    TEST_IPV6_FRAGGED_DSTOPT_TCP = 35,

    TEST_IPV6_FRAG_ICMP6 = 12,
    TEST_IPV6_DSTOPT_FRAG_ICMP6 = 14,

    TEST_INVALID = 0
};

/*
 * Items and their order in test_indexes needs to match test_names (but not
 * enum TEST_TYPE). 
 */
enum TEST_TYPE test_indexes[] = {
    TEST_IPV4_TCP,
    TEST_IPV4_FRAG_TCP,
    TEST_IPV4_FRAG_ICMP,
    TEST_IPV4_DSTOPT_FRAG_TCP,
    TEST_IPV4_DSTOPT_FRAG_ICMP,

    TEST_IPV6_TCP,
    TEST_IPV6_FRAG_TCP,
    TEST_IPV6_FRAG_ICMP6,
    TEST_IPV6_DSTOPT_FRAG_TCP,
    TEST_IPV6_FRAG_DSTOPT_TCP,
    TEST_IPV6_FRAG_DSTOPT2_TCP,
    TEST_IPV6_FRAG_FRAG_TCP,
    TEST_IPV6_FRAG_NOMORE_TCP,
    TEST_IPV6_MANY_FRAG_NOMORE_TCP,
    TEST_IPV6_MANY_SMALL_DSTOPT_TCP,
    TEST_IPV6_MANY_BIG_DSTOPT_TCP,
    TEST_IPV6_BIG_DSTOPT_TCP,
    TEST_IPV6_SMALL_DSTOPT_TCP,
    TEST_IPV6_FRAGGED_DSTOPT_TCP,
    TEST_IPV6_DSTOPT_FRAG_ICMP6,

    0
};

const char *test_names[] = {
    "v4-tcp",
    "v4-frag-tcp",
    "v4-frag-icmp",
    "v4-dstopt-frag-tcp",
    "v4-dstopt-frag-icmp",

    "v6-tcp",
    "v6-frag-tcp",
    "v6-frag-icmp6",
    "v6-dstopt-frag-tcp",
    "v6-frag-dstopt-tcp",
    "v6-frag-dstopt2-tcp",
    "v6-frag-frag-tcp",
    "v6-frag-nomore-tcp",
    "v6-many-frag-nomore-tcp",
    "v6-many-small-dstopt-tcp",
    "v6-many-big-dstopt-tcp",
    "v6-big-dstopt-tcp",
    "v6-small-dstopt-tcp",
    "v6-fragged-dstopt-tcp",
    "v6-dstopt-frag-icmp6",

    NULL
};

/* Globals */
char *tapname;
int tapfd = -1;
pcap_t *pcap;
pid_t listener_pid;
int pfd[2];
int interface_type;

#ifdef SIOCGIFHWADDR
char *get_interface_mac( char *interface )
{
    int fd;
    struct ifreq ifr;
    char *dest = malloc( MAC_ADDRESS_STRING_LENGTH + 1 );

    if ( dest == NULL ) return NULL;

    if ( ( fd = socket( AF_INET, SOCK_DGRAM, 0 ) ) == -1 )
        return NULL;

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy( ifr.ifr_name, interface, IFNAMSIZ - 1 );

    if ( ioctl( fd, SIOCGIFHWADDR, &ifr ) == -1 ) {
        close( fd );
        return NULL;
    }
    close( fd );

    sprintf( dest, "%02X:%02X:%02X:%02X:%02X:%02X",
        (unsigned char) ifr.ifr_hwaddr.sa_data[0],
        (unsigned char) ifr.ifr_hwaddr.sa_data[1],
        (unsigned char) ifr.ifr_hwaddr.sa_data[2],
        (unsigned char) ifr.ifr_hwaddr.sa_data[3],
        (unsigned char) ifr.ifr_hwaddr.sa_data[4],
        (unsigned char) ifr.ifr_hwaddr.sa_data[5]
    );
    return dest;
}
#elif defined(__FreeBSD__) || ( defined(__APPLE__) && defined(__MACH__) )
char *get_interface_mac( char *interface )
{
    struct ifaddrs *ifap;
    char *dest = malloc( MAC_ADDRESS_STRING_LENGTH + 1 );

    if ( dest == NULL ) return NULL;

    if ( getifaddrs( &ifap ) == 0 ) {
        struct ifaddrs *p;
        for ( p = ifap; p; p = p->ifa_next ) {
            if ( ( p->ifa_addr->sa_family == AF_LINK ) && ( strcmp( p->ifa_name, interface ) == 0 ) ) {
                struct sockaddr_dl* sdp = (struct sockaddr_dl *) p->ifa_addr;
                unsigned char *mac_ptr = (unsigned char *) sdp->sdl_data + sdp->sdl_nlen;
                sprintf( dest, "%02X:%02X:%02X:%02X:%02X:%02X",
                    mac_ptr[0],
                    mac_ptr[1],
                    mac_ptr[2],
                    mac_ptr[3],
                    mac_ptr[4],
                    mac_ptr[5]
                );
                freeifaddrs( ifap );
                return dest;
            }
        }
        freeifaddrs(ifap);
    }
    return NULL;
}
#else
#error Do not know how to get MAC address on this platform.
#endif

void *malloc_check( int size )
{
    void *r = malloc( size );
    if ( r == NULL ) err( 1, "malloc" );
    return r;
}

unsigned short fix_up_destination_options_length( unsigned short optlen )
{
    /*
     * Per RFC 2460, a destination options header must have a payload size
     * that is: ( multiple of 8 ) - 2. We fix that up here by only ever
     * increasing the size (though the algorithm would be simpler if we were
     * willing to decrease it. There's no good reason not to decrease it, I
     * just made a decision.
     */
    if ( optlen % 8 != 6 ) {
        int x = 6 - ( optlen % 8 );
        if ( x < 0 ) x += 8;
        optlen += x;
    }
    return optlen;
}

void calc_checksum( void *iph, int protocol, int len )
{
    if ( do_checksum( iph, protocol, len ) != 1 ) {
        fprintf(
            stderr,
            "Warning: Failed to calculate checksum for protocol %i. This is probably a bug.\n",
            protocol
        );
    }
}

/*
 * I know this is undesirable, but I'm not sure I want to keep the structure
 * of the code this way, and until I do this out of place function definition
 * will work okay.
 */
char *print_a_packet( char *, int, unsigned short, int );
void synfrag_send( void *packet, int len )
{
    static unsigned int packets_sent = 1;
    printf( "Sending packet %u:\n\n", packets_sent++ );
    print_a_packet( packet, len, 0, 1 );
    putchar( '\n' );
    if ( tapfd >= 0 ) {
        if ( write( tapfd, packet, len ) != len ) err( 1, "tap write failed" );
    } else {
        if ( pcap_inject( pcap, packet, len ) != len ) errx( 1, "pcap_inject failed: %s", pcap_geterr( pcap ) );
    }
}

void print_ethh( struct ether_header *ethh )
{
    printf( "Ethernet Frame: \n Ethertype: 0x%04X (%s)\n",
        ntohs( ethh->ether_type ), ether_protocol_to_name( ntohs( ethh->ether_type ) )
    );

    printf( " Src MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
        ethh->ether_shost[0],
        ethh->ether_shost[1],
        ethh->ether_shost[2],
        ethh->ether_shost[3],
        ethh->ether_shost[4],
        ethh->ether_shost[5] );

    printf( " Dest MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
        ethh->ether_dhost[0],
        ethh->ether_dhost[1],
        ethh->ether_dhost[2],
        ethh->ether_dhost[3],
        ethh->ether_dhost[4],
        ethh->ether_dhost[5] );
}

void print_iph( struct ip *iph )
{
    char srcbuf[INET_ADDRSTRLEN];
    char dstbuf[INET_ADDRSTRLEN];
    char *flag_names = ip_flags_to_names( ntohs( iph->ip_off ) >> IP_FLAGS_OFFSET );

    if ( inet_ntop( AF_INET, &iph->ip_src, (char *) &srcbuf, INET_ADDRSTRLEN ) == NULL ) errx( 1, "inet_ntop failed" );
    if ( inet_ntop( AF_INET, &iph->ip_dst, (char *) &dstbuf, INET_ADDRSTRLEN ) == NULL ) errx( 1, "inet_ntop failed" );

    printf( "IPv4 Packet:\n\
 Src IP: %s\n\
 Dst IP: %s\n\
 Protocol: %i (%s)\n\
 Frag Offset: %i (%i bytes)\n\
 Flags: %i (%s)\n\
 Iphl: %i (%i bytes)\n\
 Length: %i (%i counting IP header)\n",
        (char *) &srcbuf,
        (char *) &dstbuf,
        iph->ip_p, ip_protocol_to_name( iph->ip_p ),
        ntohs( iph->ip_off ) & 0x1FFF, ( ntohs( iph->ip_off ) & 0x1FFF ) * FRAGMENT_OFFSET_TO_BYTES,
        ntohs( iph->ip_off ) >> IP_FLAGS_OFFSET, flag_names,
        iph->ip_hl, iph->ip_hl * 4,
        ntohs( iph->ip_len ), ntohs( iph->ip_len ) + iph->ip_hl * 4
    );
    free( flag_names );
}

void print_ip6h( struct ip6_hdr *ip6h )
{
    char srcbuf[INET6_ADDRSTRLEN];
    char dstbuf[INET6_ADDRSTRLEN];

    if ( inet_ntop( AF_INET6, &ip6h->ip6_src, (char *) &srcbuf, INET6_ADDRSTRLEN ) == NULL ) err( 1, "inet_ntop failed" );
    if ( inet_ntop( AF_INET6, &ip6h->ip6_dst, (char *) &dstbuf, INET6_ADDRSTRLEN ) == NULL ) err( 1, "inet_ntop failed" );

    printf( "IPv6 Packet:\n\
 Src IP: %s\n\
 Dst IP: %s\n\
 Protocol: %i (%s)\n\
 Length: %i (%lu counting IP header)\n",
        (char *) &srcbuf,
        (char *) &dstbuf,
        ip6h->ip6_nxt, ip_protocol_to_name( ip6h->ip6_nxt ),
        ntohs( ip6h->ip6_plen ),
        ntohs( ip6h->ip6_plen ) + SIZEOF_IPV6
    );
}

void print_icmph( struct icmp *icmph )
{
    printf( "ICMP Packet:\n\
 Type: %i (%s)\n\
 Code: %i (%s)\n",
        icmph->icmp_type, icmp_type_to_name( icmph->icmp_type ),
        icmph->icmp_code, icmp_code_to_name( icmph->icmp_type, icmph->icmp_code )
    );
    if ( ( icmph->icmp_type == ICMP_ECHO || icmph->icmp_type == ICMP_ECHOREPLY ) && ( icmph->icmp_code == 0 ) ) {
        printf( " Echo id: %i\n", htons( icmph->icmp_id ) );
    }
}

void print_icmp6h( struct icmp6_hdr *icmp6h )
{
    printf( "ICMPv6 Packet:\n\
 Type: %i (%s)\n\
 Code: %i (%s)\n",
        icmp6h->icmp6_type, icmp6_type_to_name( icmp6h->icmp6_type ),
        icmp6h->icmp6_code, icmp6_code_to_name( icmp6h->icmp6_type, icmp6h->icmp6_code )
    );
    if ( ( icmp6h->icmp6_type == ICMP6_ECHO_REQUEST || icmp6h->icmp6_type == ICMP6_ECHO_REPLY ) && ( icmp6h->icmp6_code == 0 ) ) {
        printf( " Echo id: %i\n", htons( icmp6h->icmp6_id ) );
    }
}

void print_tcph( struct tcphdr *tcph )
{
    char *tcp_flags = tcp_flags_to_names( tcph->th_flags );
    printf( "TCP Packet:\n\
 Src Port: %u\n\
 Dst Port: %u\n\
 Seq Num: %u\n\
 Ack Num: %u\n\
 Flags: 0x%02X (%s)\n",
        ntohs( tcph->th_sport ),
        ntohs( tcph->th_dport ),
        ntohl( tcph->th_seq ),
        ntohl( tcph->th_ack ),
        tcph->th_flags, tcp_flags
    );
    free( tcp_flags );
}

void print_fragh( struct ip6_frag *fragh )
{
    printf( "Fragment Header:\n\
 Next Header: %i (%s)\n\
 Ident: %i\n\
 Offlg: 0x%04x\n\
 Offset: %i (%i bytes)\n\
 More Frags: %s\n",
        fragh->ip6f_nxt, ip_protocol_to_name( fragh->ip6f_nxt ),
        ntohs( fragh->ip6f_ident ),
        ntohs( fragh->ip6f_offlg ),
        ntohs( fragh->ip6f_offlg ) >> 3, ( ntohs( fragh->ip6f_offlg ) >> 3 ) * 8,
        fragh->ip6f_offlg & IP6F_MORE_FRAG ? "Yes" : "No"
    );
}

void print_dstopth( struct ip6_dest *desth )
{
    printf( "Destination Options Header:\n\
 Next Header: %i (%s)\n\
 Header Length: %i (%i bytes)\n\
 Options Length: %i bytes\n",
        desth->ip6d_nxt,
        ip_protocol_to_name( desth->ip6d_nxt ),
        desth->ip6d_len,
        8 + ( desth->ip6d_len * 8 ),
        8 - 2 + ( desth->ip6d_len * 8 )
    );
}

/* Returns the layer 4 header if we found one. */
char *print_a_packet( char *packet_data, int len, unsigned short wanted_type, int sent )
{
    struct ip *iph;
    struct ip6_hdr *ip6h;
    struct ether_header *ethh = (struct ether_header *) packet_data;
    uint32_t *nullh = (uint32_t *) packet_data;
    int found_type = -1;
    char *found_header = NULL;
    unsigned short ether_type;
    size_t wire_offset;

    if ( len < SIZEOF_ETHER ) {
        printf( "Ethernet Frame: \nToo short\n" );
        return NULL;
    }

    if ( interface_type == DLT_EN10MB || sent ) {
        print_ethh( ethh );
        ether_type = ntohs( ethh->ether_type );
        wire_offset = SIZEOF_ETHER;
    } else if ( interface_type == DLT_NULL ) {
        if ( nullh[0] == PF_INET ) {
            ether_type = ETHERTYPE_IP;
        } else if ( nullh[0] == PF_INET6 ) {
            ether_type = ETHERTYPE_IPV6;
        } else {
            errx(1, "unsupported protocol %u", nullh[0]);
        }
        wire_offset = 4;
    } else {
        errx(1, "unknown interface type");
    }

    if ( ether_type == ETHERTYPE_IP ) {
        size_t s = wire_offset;
        iph = (struct ip *) ( packet_data + wire_offset );
        s += ( iph->ip_hl * 4 );
        if ( s > len ) {
            printf( "IPv4 Header:\n Too short\n" );
            return NULL;
        }
        print_iph( iph );
        /* If this packet is a fragment (ie, has an offset) or has more fragments following... */
        if ( ( ntohs( iph->ip_off ) & 0x1FFF ) || ntohs( iph->ip_off ) & ( 1 << IP_FLAGS_OFFSET ) ) {
            printf( "[ Not parsing data fragment. ]\n" );
            found_type = -1;
            found_header = NULL;
        } else if ( iph->ip_p == IPPROTO_TCP ) {
            if ( s + SIZEOF_TCP > len ) {
                printf( "TCP Header:\n Too short. Got %lu bytes, expected %lu\n", len - s, SIZEOF_TCP );
                return NULL;
            }
            print_tcph( (struct tcphdr *) ( packet_data + s ) );
            found_type = IPPROTO_TCP;
            found_header = packet_data + s;
        } else if ( iph->ip_p == IPPROTO_ICMP ) {
            if ( s + SIZEOF_PING > len ) {
                printf( "UDP Header:\n Too short\n" );
                return NULL;
            }
            print_icmph( (struct icmp *) ( packet_data + s ) );
            found_type = IPPROTO_ICMP;
            found_header = packet_data + s;
        } else {
            printf( "Unsupported protocol:\n IP Protocol %i (%s)\n", iph->ip_p, ip_protocol_to_name( iph->ip_p ) );
            return NULL;
        }

    } else if ( ether_type == ETHERTYPE_IPV6 ) {
        int ipv6_next_header_type = IPPROTO_IPV6;
        int depth = 0;
        size_t s = wire_offset;

        while( 1 ) {
            if ( depth >= 20 ) {
                printf( "Too many headers, stopping parsing after %i.\n", depth );
                return NULL;
            }
            if ( ipv6_next_header_type == IPPROTO_IPV6 ) {
                ip6h = (struct ip6_hdr *) ( packet_data + wire_offset );
                s += SIZEOF_IPV6;
                if ( s > len ) {
                    printf( "IPv6 Header:\n Too short. Got %lu bytes, expected %lu\n", len - s, SIZEOF_IPV6 );
                    return NULL;
                }
                print_ip6h( ip6h );
                ipv6_next_header_type = ip6h->ip6_nxt;
            } else if ( ipv6_next_header_type == IPPROTO_TCP ) {
                if ( s + SIZEOF_TCP > len ) {
                    printf( "TCP Header:\n Too short. Got %lu bytes, expected %lu\n", len - s, SIZEOF_TCP );
                    return NULL;
                }
                print_tcph( (struct tcphdr *) ( packet_data + s ) );
                found_type = IPPROTO_TCP;
                found_header = packet_data + s;
                s += SIZEOF_TCP;
                break;
            } else if ( ipv6_next_header_type == IPPROTO_ICMPV6 ) {
                if ( s + SIZEOF_ICMP6 > len ) {
                    printf( "ICMP6 Header:\n Too short. Got %lu bytes, expected %lu\n", len - s, SIZEOF_ICMP6 );
                    return NULL;
                }
                print_icmp6h( (struct icmp6_hdr *) ( packet_data + s ) );
                found_type = IPPROTO_ICMPV6;
                found_header = packet_data + s;
                s += SIZEOF_ICMP6;
                break;
            } else if ( ipv6_next_header_type == IPPROTO_FRAGMENT ) {
                if ( s + SIZEOF_FRAG > len ) {
                    printf( "Fragment Header:\n Too short. Got %lu bytes, expected %lu\n", len - s, SIZEOF_FRAG );
                    return NULL;
                }
                print_fragh( (struct ip6_frag *) ( packet_data + s ) );
                found_type = IPPROTO_FRAGMENT;
                found_header = packet_data + s;
                if ( ntohs( ( (struct ip6_frag *) ( packet_data + s ) )->ip6f_offlg ) >> 3 > 0 ) {
                    printf( "[ Not parsing data fragment. ]\n" );
                    break;
                }
                ipv6_next_header_type = ( (struct ip6_frag *) ( packet_data + s ) )->ip6f_nxt;
                s += SIZEOF_FRAG;
            } else if ( ipv6_next_header_type == IPPROTO_DSTOPTS ) {
                /*
                 * Wow, this is ugly! First check if we have enough room in the
                 * buffer to read the destopts header, then check we have to check
                 * again to see if we have the complete header.
                 */
                if ( s + SIZEOF_DESTOPT > len ) {
                    printf( "Destination Options Header:\n Too short. Got %lu bytes, expected %lu\n", len - s, SIZEOF_DESTOPT );
                    return NULL;
                }
                if ( 
                    (
                        s
                        + 8 /*
                             * The Destination Options header length field is
                             * the total header length in 8 byte octets + 
                             * another 8 bytes. See RFC 2460.
                             */
                        + ( ( (struct ip6_dest *) ( packet_data + s ) )->ip6d_len * 8 )
                    )
                    > len ) {
                    printf( "Destination Options Header:\n Too short (options truncated)\n" );
                    return NULL;
                }
                print_dstopth( (struct ip6_dest *) ( packet_data + s ) );
                found_type = IPPROTO_DSTOPTS;
                found_header = packet_data + s;
                ipv6_next_header_type = ( (struct ip6_dest *) ( packet_data + s ) )->ip6d_nxt;
                s += 8 + ( ( (struct ip6_dest *) ( packet_data + s ) )->ip6d_len * 8 );
            } else if ( ipv6_next_header_type == IPPROTO_NONE ) {
                printf( "[ No header. ]\n" );
                break;
            } else {
                printf( "Unsupported IPv6 Header:\n Next header: %i (%s)\n",
                    ipv6_next_header_type,
                    ip_protocol_to_name( ipv6_next_header_type )
                );
                return NULL;
            }
        }

    } else { /* ETHERTYPE_IPV6 */
        printf( "Unsupported Protocol:\n Ethertype: %i (%s)\n",
            ether_type,
            ether_protocol_to_name( ether_type )
        );
        return NULL;
    }

    if ( wanted_type == found_type ) return found_header;
    return NULL;
}

int receive_a_packet( const char *filter_str, char **packet_buf, long receive_timeout, int signal_pipe )
{
    struct pcap_pkthdr *received_packet_pcap;
    struct bpf_program pcap_filter;
    unsigned char *received_packet_data;
    int r, fd;
    fd_set select_me;
    struct timeval ts;

    if ( pcap_compile( pcap, &pcap_filter, filter_str, 1, 0 ) == -1 )
        errx( 1, "pcap_compile failed: %s", pcap_geterr( pcap ) );
    if ( pcap_setfilter( pcap, &pcap_filter ) == -1 )
        errx( 1, "pcap_setfilter failed: %s", pcap_geterr( pcap ) );
    pcap_freecode( &pcap_filter );

    if ( ( fd = pcap_fileno( pcap ) ) == -1 )
        errx( 1, "pcap_fileno failed" );

    FD_ZERO( &select_me );
    FD_SET( fd, &select_me );

    ts.tv_sec = receive_timeout;
    ts.tv_usec = 0;

    if ( signal_pipe ) {
        /*
         * Signal we're ready to go. Still a race condition. I don't see how to
         * work around this with pcap. 
         */
        write( pfd[1], ".", 1 );
    }

    r = select( fd + 1, &select_me, NULL, NULL, receive_timeout ? &ts : NULL );
    /* Timed out */
    if ( r == 0 ) return 0;

    r = pcap_next_ex( pcap, &received_packet_pcap, (const unsigned char **) &received_packet_data );

    /* Error or pcap_next_ex timed out (should never happen) */
    if ( r < 1 ) return 0;
    if ( received_packet_pcap->len > received_packet_pcap->caplen ) errx( 1, "pcap didn't capture the whole packet." );

    *packet_buf = (char *) received_packet_data;
    return received_packet_pcap->len;
}

int receive_synfrag_reply( char *srcip, char *dstip, unsigned short srcport, unsigned short dstport, enum TEST_TYPE test_type, char **packet_buf, long receive_timeout )
{
    /*
     * My back-of-the-napkin for the maximum length for the ipv6 filter string
     * below + 1 byte for the trailing NULL 
     */
    const int FILTER_STR_LEN = 203;
    char filter_str[FILTER_STR_LEN];
    int r;

    /*
     * Something prior to now should have validated srcip and dstip are valid
     * IP addresses, we hope. Napkin math says we shouldn't even be close to
     * overflowing our buffer.
     */
    if ( IS_TEST_IPV4( test_type ) ) {
        r = snprintf(
            (char *) &filter_str,
            FILTER_STR_LEN,
            "ip src %s and dst %s and (icmp or (tcp and src port %i and dst port %i))",
            srcip,
            dstip,
            srcport,
            dstport
        );
    } else {
        r = snprintf(
            (char *) &filter_str,
            FILTER_STR_LEN,
            /* Attempt to ignore ICMP6 neighbor solicitation/advertisement */
            "ip6 src %s and dst %s and ((icmp6 and ip6[40] != 135 and ip6[40] != 136) or (tcp and src port %i and dst port %i))",
            srcip,
            dstip,
            srcport,
            dstport
        );
    }
    if ( r < 0 || r >= FILTER_STR_LEN ) errx( 1, "snprintf for pcap filter failed" );
    return receive_a_packet( filter_str, packet_buf, receive_timeout, 1 );
}

int get_isn_for_replay( char *interface, char *srcip, char *dstip, unsigned short dstport, enum TEST_TYPE test_type, uint32_t *isn, unsigned short *srcport )
{
    const int FILTER_STR_LEN = 100;
    char filter_str[FILTER_STR_LEN];
    int r;
    char *packet_buf;
    struct tcphdr *tcph;

    /*
     * Something prior to now should have validated srcip and dstip are valid
     * IP addresses, we hope. Napkin math says we shouldn't even be close to
     * overflowing our buffer.
     */
    if ( IS_TEST_IPV4( test_type ) ) {
        r = snprintf(
            (char *) &filter_str,
            FILTER_STR_LEN,
            "ip src %s and dst %s and tcp dst port %i",
            srcip,
            dstip,
            dstport
        );
    } else {
        r = snprintf(
            (char *) &filter_str,
            FILTER_STR_LEN,
            "ip6 src %s and dst %s and tcp dst port %i",
            srcip,
            dstip,
            dstport
        );
    }
    if ( r < 0 || r >= FILTER_STR_LEN ) errx( 1, "snprintf for pcap filter failed" );
    r = receive_a_packet( filter_str, &packet_buf, 0, 0 );
    if ( !r ) return 0;
    printf( "Found a matching outgoing TCP SYN:\n\n" );
    tcph = (struct tcphdr *) print_a_packet( (char *) packet_buf, r, IPPROTO_TCP, 0 );
    if ( !tcph ) return 0;
    printf( "\nLooks good, sending replay.\n\n" );
    *isn = ntohl( tcph->th_seq );
    *srcport = ntohs( tcph->th_sport );
    free( packet_buf );
    return 1;
}

int check_received_packet( int buf_len, char *packet_buf, enum TEST_TYPE test_type ) {
    struct ether_header *received_packet_data = (struct ether_header *) packet_buf;
    struct tcphdr *tcph;
    struct icmp *icmph;
    struct icmp6_hdr *icmp6h;

    printf( "Received packet 1:\n\n" );

    if ( IS_TEST_IPV4( test_type ) && IS_TEST_ICMP( test_type ) ) {
        icmph = (struct icmp *) print_a_packet( (char *) received_packet_data, buf_len, IPPROTO_ICMP, 0 );
        if ( !icmph ) return 0;
        if ( icmph->icmp_type == ICMP_ECHOREPLY && icmph->icmp_id == htons( ICMP_ID ) ) return 1;
    } else if ( IS_TEST_IPV6( test_type ) && IS_TEST_ICMP( test_type ) ) {
        icmp6h = (struct icmp6_hdr *) print_a_packet( (char *) received_packet_data, buf_len, IPPROTO_ICMPV6, 0 );
        if ( !icmp6h ) return 0;
        if ( icmp6h->icmp6_type == ICMP6_ECHO_REPLY && icmp6h->icmp6_id == htons( ICMP_ID ) ) return 1;
    } else { /* Assume pcap picked the right address family for our packet. */
        tcph = (struct tcphdr *) print_a_packet( (char *) received_packet_data, buf_len, IPPROTO_TCP, 0 );
        if ( !tcph ) return 0;
        if ( ( tcph->th_flags & ( TH_SYN|TH_ACK ) ) && !( tcph->th_flags & TH_RST ) ) {
            return 1;
        }
    }
    printf( "\nReceived reply but it wasn't what we were hoping for.\n" );
    return 0;
}

/* IPv4 tests. */
void do_ipv4_syn( char *interface, char *srcip, char *dstip, char *srcmac, char *dstmac, unsigned short srcport, unsigned short dstport, uint32_t isn )
{
    struct ip *iph;
    struct tcphdr *tcph;
    struct ether_header *ethh;
    int packet_size;

    packet_size = SIZEOF_ETHER + SIZEOF_TCP + SIZEOF_IPV4;

    ethh = (struct ether_header *) malloc_check( BIG_PACKET_SIZE );
    iph = (struct ip *) ( (char *) ethh + SIZEOF_ETHER );
    tcph = (struct tcphdr *) ( (char *) iph + SIZEOF_IPV4 );

    append_ethernet( ethh, srcmac, dstmac, ETHERTYPE_IP );
    append_ipv4( iph, srcip, dstip, IPPROTO_TCP );
    append_tcp_syn( tcph, srcport, dstport, isn );
    calc_checksum( iph, IPPROTO_TCP, SIZEOF_TCP );
    calc_checksum( iph, IPPROTO_IP, SIZEOF_IPV4 );

    synfrag_send( ethh, packet_size );
    free( ethh );
}

void do_ipv4_frag_tcp( char *interface, char *srcip, char *dstip, char *srcmac, char *dstmac, unsigned short srcport, unsigned short dstport, uint32_t isn )
{
    struct ip *iph;
    struct tcphdr *tcph;
    struct ether_header *ethh;
    int packet_size;
    unsigned short fragid = rand();

    packet_size = SIZEOF_ETHER + SIZEOF_IPV4 + MINIMUM_FRAGMENT_SIZE;

    ethh = (struct ether_header *) malloc_check( BIG_PACKET_SIZE );
    iph = (struct ip *) ( (char *) ethh + SIZEOF_ETHER );
    tcph = (struct tcphdr *) ( (char *) iph + SIZEOF_IPV4 );

    append_ethernet( ethh, srcmac, dstmac, ETHERTYPE_IP );
    append_ipv4_short_frag1( iph, srcip, dstip, IPPROTO_TCP, fragid );
    append_tcp_syn( tcph, srcport, dstport, isn );
    calc_checksum( iph, IPPROTO_TCP, SIZEOF_TCP );
    calc_checksum( iph, IPPROTO_IP, SIZEOF_IPV4 );

    synfrag_send( ethh, packet_size );

    packet_size = SIZEOF_ETHER + SIZEOF_IPV4 + SIZEOF_TCP - MINIMUM_FRAGMENT_SIZE;

    append_ipv4_frag2( iph, srcip, dstip, IPPROTO_TCP, fragid, SIZEOF_TCP - MINIMUM_FRAGMENT_SIZE );
    memmove( tcph, (char *) tcph + MINIMUM_FRAGMENT_SIZE, SIZEOF_TCP - MINIMUM_FRAGMENT_SIZE );
    calc_checksum( iph, IPPROTO_IP, SIZEOF_IPV4 );

    synfrag_send( ethh, packet_size );
    free( ethh );
}

void do_ipv4_frag_icmp( char *interface, char *srcip, char *dstip, char *srcmac, char *dstmac )
{
    struct ip *iph;
    struct icmp *icmph;
    struct ether_header *ethh;
    int packet_size;
    unsigned short fragid = rand();
    unsigned short pinglen = 40;

    packet_size = SIZEOF_ETHER + SIZEOF_IPV4 + MINIMUM_FRAGMENT_SIZE;

    ethh = (struct ether_header *) malloc_check( BIG_PACKET_SIZE );
    iph = (struct ip *) ( (char *) ethh + SIZEOF_ETHER );
    icmph = (struct icmp *) ( (char *) iph + SIZEOF_IPV4 );

    append_ethernet( ethh, srcmac, dstmac, ETHERTYPE_IP );
    append_ipv4_short_frag1( iph, srcip, dstip, IPPROTO_ICMP, fragid );
    append_icmp_ping( icmph, pinglen );
    calc_checksum( iph, IPPROTO_IP, SIZEOF_IPV4 );
    calc_checksum( iph, IPPROTO_ICMP, SIZEOF_PING + pinglen );

    synfrag_send( ethh, packet_size );

    packet_size = SIZEOF_ETHER + SIZEOF_IPV4 + SIZEOF_PING + pinglen - MINIMUM_FRAGMENT_SIZE;

    append_ipv4_frag2( iph, srcip, dstip, IPPROTO_ICMP, fragid, SIZEOF_PING + pinglen - MINIMUM_FRAGMENT_SIZE );
    memmove( icmph, (char *) icmph + MINIMUM_FRAGMENT_SIZE, SIZEOF_PING + pinglen - MINIMUM_FRAGMENT_SIZE );
    calc_checksum( iph, IPPROTO_IP, SIZEOF_IPV4 );

    synfrag_send( ethh, packet_size );
    free( ethh );
}

void do_ipv4_options_tcp_frag( char *interface, char *srcip, char *dstip, char *srcmac, char *dstmac, unsigned short srcport, unsigned short dstport, uint32_t isn )
{
    struct ip *iph;
    struct tcphdr *tcph, *tcph_optioned;
    struct ether_header *ethh;
    int packet_size;
    unsigned short fragid = rand();
    unsigned short optlen = 40; /* Multiple of 4. */

    packet_size = SIZEOF_ETHER + SIZEOF_IPV4 + optlen + MINIMUM_FRAGMENT_SIZE;

    ethh = (struct ether_header *) malloc_check( BIG_PACKET_SIZE );
    iph = (struct ip *) ( (char *) ethh + SIZEOF_ETHER );
    tcph = (struct tcphdr *) ( (char *) iph + SIZEOF_IPV4 );
    tcph_optioned = (struct tcphdr *) ( (char *) tcph + optlen );

    append_ethernet( ethh, srcmac, dstmac, ETHERTYPE_IP );
    append_ipv4_optioned_frag1( iph, srcip, dstip, IPPROTO_TCP, fragid, optlen );
    append_tcp_syn( tcph_optioned, srcport, dstport, isn );
    calc_checksum( iph, IPPROTO_TCP, SIZEOF_TCP );
    calc_checksum( iph, IPPROTO_IP, SIZEOF_IPV4 + optlen );

    synfrag_send( ethh, packet_size );

    packet_size = SIZEOF_ETHER + SIZEOF_IPV4 + SIZEOF_TCP - MINIMUM_FRAGMENT_SIZE;

    append_ipv4_frag2( iph, srcip, dstip, IPPROTO_TCP, fragid, SIZEOF_TCP - MINIMUM_FRAGMENT_SIZE );
    memmove( tcph, (char *) tcph_optioned + MINIMUM_FRAGMENT_SIZE, SIZEOF_TCP - MINIMUM_FRAGMENT_SIZE );
    calc_checksum( iph, IPPROTO_IP, SIZEOF_IPV4 );

    synfrag_send( ethh, packet_size );
    free( ethh );
}

void do_ipv4_options_icmp_frag( char *interface, char *srcip, char *dstip, char *srcmac, char *dstmac )
{
    struct ip *iph;
    struct icmp *icmph, *icmph_optioned;
    struct ether_header *ethh;
    int packet_size;
    unsigned short fragid = rand();
    unsigned short optlen = 40; /* Multiple of 4. */
    unsigned short pinglen = 40;

    packet_size = SIZEOF_ETHER + SIZEOF_IPV4 + optlen + MINIMUM_FRAGMENT_SIZE;

    ethh = (struct ether_header *) malloc_check( BIG_PACKET_SIZE );
    iph = (struct ip *) ( (char *) ethh + SIZEOF_ETHER );
    icmph = (struct icmp *) ( (char *) iph + SIZEOF_IPV4 );
    icmph_optioned = (struct icmp *) ( (char *) icmph + optlen );

    append_ethernet( ethh, srcmac, dstmac, ETHERTYPE_IP );
    append_ipv4_optioned_frag1( iph, srcip, dstip, IPPROTO_ICMP, fragid, optlen );
    append_icmp_ping( icmph_optioned, pinglen );
    calc_checksum( iph, IPPROTO_ICMP, SIZEOF_PING + pinglen );
    calc_checksum( iph, IPPROTO_IP, SIZEOF_IPV4 + optlen );

    synfrag_send( ethh, packet_size );

    packet_size = SIZEOF_ETHER + SIZEOF_IPV4 + SIZEOF_PING + pinglen;

    append_ipv4_frag2( iph, srcip, dstip, IPPROTO_ICMP, fragid, SIZEOF_PING - MINIMUM_FRAGMENT_SIZE + pinglen );
    memmove( icmph, (char *) icmph_optioned + MINIMUM_FRAGMENT_SIZE, SIZEOF_PING + pinglen - MINIMUM_FRAGMENT_SIZE );
    calc_checksum( iph, IPPROTO_IP, SIZEOF_IPV4 );

    synfrag_send( ethh, packet_size );
    free( ethh );
}

/* IPv6 tests. */
void do_ipv6_syn( char *interface, char *srcip, char *dstip, char *srcmac, char *dstmac, unsigned short srcport, unsigned short dstport, uint32_t isn )
{
    struct ip6_hdr *ip6h;
    struct tcphdr *tcph;
    struct ether_header *ethh;
    int packet_size;

    packet_size = SIZEOF_ETHER + SIZEOF_IPV6 + SIZEOF_TCP;

    ethh = (struct ether_header *) malloc_check( BIG_PACKET_SIZE );
    ip6h = (struct ip6_hdr *) ( (char *) ethh + SIZEOF_ETHER );
    tcph = (struct tcphdr *) ( (char *) ip6h + SIZEOF_IPV6 );

    append_ethernet( ethh, srcmac, dstmac, ETHERTYPE_IPV6 );
    append_ipv6( ip6h, srcip, dstip, IPPROTO_TCP, SIZEOF_TCP );
    append_tcp_syn( tcph, srcport, dstport, isn );
    calc_checksum( ip6h, IPPROTO_TCP, SIZEOF_TCP );

    synfrag_send( ethh, packet_size );
    free( ethh );
}

void do_ipv6_frag_tcp( char *interface, char *srcip, char *dstip, char *srcmac, char *dstmac, unsigned short srcport, unsigned short dstport, uint32_t isn )
{
    struct ip6_hdr *ip6h;
    struct tcphdr *tcph;
    struct ether_header *ethh;
    int packet_size;
    unsigned short fragid = rand();
    void *next;

    packet_size = SIZEOF_ETHER + SIZEOF_IPV6 + SIZEOF_FRAG + MINIMUM_FRAGMENT_SIZE;

    ethh = (struct ether_header *) malloc_check( BIG_PACKET_SIZE );
    ip6h = (struct ip6_hdr *) ( (char *) ethh + SIZEOF_ETHER );
    tcph = (struct tcphdr *) ( (char *) ip6h + SIZEOF_IPV6 + SIZEOF_FRAG );

    next = append_ethernet( ethh, srcmac, dstmac, ETHERTYPE_IPV6 );
    next = append_ipv6( next, srcip, dstip, IPPROTO_FRAGMENT, SIZEOF_FRAG + MINIMUM_FRAGMENT_SIZE );
    next = append_frag_first( next, IPPROTO_TCP, fragid );
    append_tcp_syn( next, srcport, dstport, isn );
    calc_checksum( ip6h, IPPROTO_TCP, SIZEOF_TCP );

    synfrag_send( ethh, packet_size );

    packet_size = SIZEOF_ETHER + SIZEOF_IPV6 + SIZEOF_FRAG + SIZEOF_TCP - MINIMUM_FRAGMENT_SIZE;

    next = append_ipv6( ip6h, srcip, dstip, IPPROTO_FRAGMENT, SIZEOF_FRAG + SIZEOF_TCP - MINIMUM_FRAGMENT_SIZE );
    append_frag_last( next, IPPROTO_TCP, MINIMUM_FRAGMENT_SIZE, fragid );
    memmove( tcph, (char *) tcph + MINIMUM_FRAGMENT_SIZE, SIZEOF_TCP - MINIMUM_FRAGMENT_SIZE );

    synfrag_send( ethh, packet_size );
    free( ethh );
}

void do_ipv6_frag_icmp( char *interface, char *srcip, char *dstip, char *srcmac, char *dstmac )
{
    struct ip6_hdr *ip6h;
    struct icmp6_hdr *icmp6h;
    struct ether_header *ethh;
    void *next;
    int packet_size;
    unsigned short fragid = rand();
    unsigned short pinglen = 40;

    packet_size = SIZEOF_ETHER + SIZEOF_IPV6 + SIZEOF_FRAG + MINIMUM_FRAGMENT_SIZE;

    ethh = (struct ether_header *) malloc_check( BIG_PACKET_SIZE );
    ip6h = (struct ip6_hdr *) ( (char *) ethh + SIZEOF_ETHER );
    icmp6h = (struct icmp6_hdr *) ( (char *) ip6h + SIZEOF_IPV6 + SIZEOF_FRAG );

    next = append_ethernet( ethh, srcmac, dstmac, ETHERTYPE_IPV6 );
    next = append_ipv6( next, srcip, dstip, IPPROTO_FRAGMENT, SIZEOF_FRAG + MINIMUM_FRAGMENT_SIZE );
    next = append_frag_first( next, IPPROTO_ICMPV6, fragid );
    append_icmp6_ping( next, pinglen );
    calc_checksum( ip6h, IPPROTO_ICMPV6, SIZEOF_ICMP6 + pinglen );

    synfrag_send( ethh, packet_size );

    packet_size = SIZEOF_ETHER + SIZEOF_IPV6 + SIZEOF_FRAG + SIZEOF_ICMP6 + pinglen - MINIMUM_FRAGMENT_SIZE;

    next = append_ipv6( ip6h, srcip, dstip, IPPROTO_FRAGMENT, SIZEOF_FRAG + SIZEOF_ICMP6 + pinglen - MINIMUM_FRAGMENT_SIZE );
    next = append_frag_last( next, IPPROTO_ICMPV6, MINIMUM_FRAGMENT_SIZE, fragid );
    memmove( icmp6h, (char *) icmp6h + MINIMUM_FRAGMENT_SIZE, SIZEOF_ICMP6 + pinglen - MINIMUM_FRAGMENT_SIZE );

    synfrag_send( ethh, packet_size );
    free( ethh );
}

void do_ipv6_dstopt_frag_icmp( char *interface, char *srcip, char *dstip, char *srcmac, char *dstmac )
{
    struct ip6_hdr *ip6h;
    struct icmp6_hdr *icmp6h, *icmp6h_optioned;
    struct ether_header *ethh;
    void *next;
    int packet_size;
    unsigned short fragid = rand();
    unsigned short optlen = fix_up_destination_options_length(
         MINIMUM_PACKET_SIZE - SIZEOF_IPV6 - SIZEOF_DESTOPT - SIZEOF_FRAG - MINIMUM_FRAGMENT_SIZE
    );
    /*
     * pinglen must be > 6 or our first packet will be <= MINIMUM_PACKET_SIZE bytes and
     * our second packet empty. -- I don't think this applies any more? XXX
     */
    unsigned short pinglen = 40;

    packet_size = SIZEOF_ETHER + SIZEOF_IPV6 + SIZEOF_DESTOPT + optlen + SIZEOF_FRAG + MINIMUM_FRAGMENT_SIZE;

    ethh = (struct ether_header *) malloc_check( BIG_PACKET_SIZE );
    ip6h = (struct ip6_hdr *) ( (char *) ethh + SIZEOF_ETHER );
    icmp6h = (struct icmp6_hdr *) ( (char *) ip6h + SIZEOF_IPV6 + SIZEOF_FRAG );
    icmp6h_optioned = (struct icmp6_hdr *) ( (char *) ip6h + SIZEOF_IPV6 + SIZEOF_DESTOPT + optlen + SIZEOF_FRAG + MINIMUM_FRAGMENT_SIZE );

    next = append_ethernet( ethh, srcmac, dstmac, ETHERTYPE_IPV6 );
    next = append_ipv6( next, srcip, dstip, IPPROTO_DSTOPTS, SIZEOF_DESTOPT + optlen + SIZEOF_FRAG + MINIMUM_FRAGMENT_SIZE );
    next = append_dest( next, IPPROTO_FRAGMENT, optlen );
    next = append_frag_first( next, IPPROTO_ICMPV6, fragid );
    append_icmp6_ping( icmp6h_optioned, pinglen );
    calc_checksum( ip6h, IPPROTO_ICMPV6, SIZEOF_ICMP6 + pinglen );

    synfrag_send( ethh, packet_size );

    packet_size = SIZEOF_ETHER + SIZEOF_IPV6 + SIZEOF_FRAG + SIZEOF_PING + pinglen - MINIMUM_FRAGMENT_SIZE;

    next = append_ipv6( ip6h, srcip, dstip, IPPROTO_FRAGMENT, SIZEOF_FRAG + SIZEOF_ICMP6 + pinglen - MINIMUM_FRAGMENT_SIZE );
    next = append_frag_last( next, IPPROTO_ICMPV6, MINIMUM_FRAGMENT_SIZE, fragid );
    memmove( icmp6h, icmp6h_optioned, SIZEOF_ICMP6 + pinglen - MINIMUM_FRAGMENT_SIZE );

    synfrag_send( ethh, packet_size );
    free( ethh );
}

void do_ipv6_dstopt_frag_tcp( char *interface, char *srcip, char *dstip, char *srcmac, char *dstmac, unsigned short srcport, unsigned short dstport, uint32_t isn )
{
    struct ip6_hdr *ip6h;
    struct tcphdr *tcph, *tcph_optioned;
    struct ether_header *ethh;
    void *next;
    int packet_size;
    unsigned short fragid = rand();
    unsigned short optlen = 6;

    packet_size = SIZEOF_ETHER + SIZEOF_IPV6 + SIZEOF_DESTOPT + optlen + SIZEOF_FRAG + MINIMUM_FRAGMENT_SIZE;

    ethh = (struct ether_header *) malloc_check( BIG_PACKET_SIZE );
    ip6h = (struct ip6_hdr *) ( (char *) ethh + SIZEOF_ETHER );
    tcph = (struct tcphdr *) ( (char *) ip6h + SIZEOF_IPV6 + SIZEOF_FRAG );
    tcph_optioned = (struct tcphdr *) ( (char *) ip6h + SIZEOF_IPV6 + SIZEOF_DESTOPT + optlen + SIZEOF_FRAG + MINIMUM_FRAGMENT_SIZE );

    next = append_ethernet( ethh, srcmac, dstmac, ETHERTYPE_IPV6 );
    next = append_ipv6( next, srcip, dstip, IPPROTO_DSTOPTS, SIZEOF_DESTOPT + optlen + SIZEOF_FRAG + MINIMUM_FRAGMENT_SIZE );
    next = append_dest( next, IPPROTO_FRAGMENT, optlen );
    next = append_frag_first( next, IPPROTO_TCP, fragid );
    append_tcp_syn( next, srcport, dstport, isn );
    calc_checksum( ip6h, IPPROTO_TCP, SIZEOF_TCP );

    synfrag_send( ethh, packet_size );

    packet_size = SIZEOF_ETHER + SIZEOF_IPV6 + SIZEOF_FRAG + SIZEOF_TCP - MINIMUM_FRAGMENT_SIZE;

    next = append_ipv6( ip6h, srcip, dstip, IPPROTO_FRAGMENT, SIZEOF_FRAG + SIZEOF_TCP - MINIMUM_FRAGMENT_SIZE );
    next = append_frag_last( next, IPPROTO_TCP, MINIMUM_FRAGMENT_SIZE, fragid );
    memmove( tcph, tcph_optioned, SIZEOF_TCP - MINIMUM_FRAGMENT_SIZE );

    synfrag_send( ethh, packet_size );
    free( ethh );
}

void do_ipv6_frag_dstopt_tcp( char *interface, char *srcip, char *dstip, char *srcmac, char *dstmac, unsigned short srcport, unsigned short dstport, uint32_t isn )
{
    struct ip6_hdr *ip6h;
    struct tcphdr *tcph, *tcph_optioned;
    struct ether_header *ethh;
    void *next;
    int packet_size;
    unsigned short fragid = rand();
    unsigned short optlen = 6;

    packet_size = SIZEOF_ETHER + SIZEOF_IPV6 + SIZEOF_FRAG + SIZEOF_DESTOPT + optlen;

    ethh = (struct ether_header *) malloc_check( BIG_PACKET_SIZE );
    ip6h = (struct ip6_hdr *) ( (char *) ethh + SIZEOF_ETHER );
    tcph = (struct tcphdr *) ( (char *) ip6h + SIZEOF_IPV6 + SIZEOF_FRAG );

    next = append_ethernet( ethh, srcmac, dstmac, ETHERTYPE_IPV6 );
    next = append_ipv6( next, srcip, dstip, IPPROTO_FRAGMENT, SIZEOF_FRAG + SIZEOF_DESTOPT + optlen );
    next = append_frag_first( next, IPPROTO_DSTOPTS, fragid );
    tcph_optioned = append_dest( next, IPPROTO_TCP, optlen );
    append_tcp_syn( tcph_optioned, srcport, dstport, isn );
    calc_checksum( ip6h, IPPROTO_TCP, SIZEOF_TCP );

    synfrag_send( ethh, packet_size );

    packet_size = SIZEOF_ETHER + SIZEOF_IPV6 + SIZEOF_FRAG + SIZEOF_TCP;

    next = append_ipv6( ip6h, srcip, dstip, IPPROTO_FRAGMENT, SIZEOF_FRAG + SIZEOF_TCP );
    next = append_frag_last( next, IPPROTO_TCP, SIZEOF_DESTOPT + optlen, fragid );
    memmove( tcph, tcph_optioned, SIZEOF_TCP );

    synfrag_send( ethh, packet_size );
    free( ethh );
}

void do_ipv6_frag_dstopt2_tcp( char *interface, char *srcip, char *dstip, char *srcmac, char *dstmac, unsigned short srcport, unsigned short dstport, uint32_t isn )
{
    struct ip6_hdr *ip6h;
    struct tcphdr *tcph;
    struct ether_header *ethh;
    void *next;
    int packet_size;
    unsigned short fragid = rand();
    unsigned short optlen = 6;

    packet_size = SIZEOF_ETHER + SIZEOF_IPV6 + SIZEOF_FRAG + SIZEOF_DESTOPT + optlen;

    ethh = (struct ether_header *) malloc_check( BIG_PACKET_SIZE );
    ip6h = (struct ip6_hdr *) ( (char *) ethh + SIZEOF_ETHER );
    tcph = (struct tcphdr *) ( (char *) ip6h + SIZEOF_IPV6 + SIZEOF_FRAG + SIZEOF_DESTOPT + optlen );

    next = append_ethernet( ethh, srcmac, dstmac, ETHERTYPE_IPV6 );
    next = append_ipv6( next, srcip, dstip, IPPROTO_FRAGMENT, SIZEOF_FRAG + SIZEOF_DESTOPT + optlen );
    next = append_frag_first( next, IPPROTO_DSTOPTS, fragid );
    next = append_dest( next, IPPROTO_DSTOPTS, optlen );

    synfrag_send( ethh, packet_size );

    packet_size = SIZEOF_ETHER + SIZEOF_IPV6 + SIZEOF_FRAG + SIZEOF_DESTOPT + optlen + SIZEOF_TCP;

    next = append_ipv6( ip6h, srcip, dstip, IPPROTO_FRAGMENT, SIZEOF_FRAG + SIZEOF_DESTOPT + optlen + SIZEOF_TCP );
    next = append_frag_last( next, IPPROTO_DSTOPTS, SIZEOF_DESTOPT + optlen, fragid );
    next = append_dest( next, IPPROTO_TCP, optlen );
    append_tcp_syn( next, srcport, dstport, isn );
    calc_checksum( ip6h, IPPROTO_TCP, SIZEOF_TCP );

    synfrag_send( ethh, packet_size );
    free( ethh );
}

void do_ipv6_frag_frag_tcp( char *interface, char *srcip, char *dstip, char *srcmac, char *dstmac, unsigned short srcport, unsigned short dstport, uint32_t isn )
{
    struct ip6_hdr *ip6h;
    struct tcphdr *tcph;
    struct ether_header *ethh;
    int packet_size;
    unsigned short fragid = rand();
    void *next;
    void *tcph_optioned;

    packet_size = SIZEOF_ETHER + SIZEOF_IPV6 + SIZEOF_FRAG + SIZEOF_FRAG + SIZEOF_FRAG;

    ethh = (struct ether_header *) malloc_check( BIG_PACKET_SIZE );
    ip6h = (struct ip6_hdr *) ( (char *) ethh + SIZEOF_ETHER );
    tcph = (struct tcphdr *) ( (char *) ip6h + SIZEOF_IPV6 + SIZEOF_FRAG );
    tcph_optioned = (struct tcphdr *) ( (char *) ip6h + SIZEOF_IPV6 + SIZEOF_FRAG + SIZEOF_FRAG + SIZEOF_FRAG );

    next = append_ethernet( ethh, srcmac, dstmac, ETHERTYPE_IPV6 );
    next = append_ipv6( next, srcip, dstip, IPPROTO_FRAGMENT, SIZEOF_FRAG + SIZEOF_FRAG + SIZEOF_FRAG );
    next = append_frag_first( next, IPPROTO_FRAGMENT, fragid );
    next = append_frag( next, IPPROTO_FRAGMENT, SIZEOF_FRAG, fragid, 1 );
    next = append_frag( next, IPPROTO_FRAGMENT, SIZEOF_FRAG * 2, fragid, 1 );
    append_tcp_syn( next, srcport, dstport, isn );
    calc_checksum( ip6h, IPPROTO_TCP, SIZEOF_TCP );

    synfrag_send( ethh, packet_size );

    packet_size = SIZEOF_ETHER + SIZEOF_IPV6 + SIZEOF_FRAG + SIZEOF_TCP;

    next = append_ipv6( ip6h, srcip, dstip, IPPROTO_FRAGMENT, SIZEOF_FRAG + SIZEOF_TCP );
    append_frag_last( next, IPPROTO_TCP, SIZEOF_FRAG * 3, fragid );
    memmove( tcph, tcph_optioned, SIZEOF_TCP );

    synfrag_send( ethh, packet_size );
    free( ethh );
}

void do_ipv6_fragged_dstopt_tcp( char *interface, char *srcip, char *dstip, char *srcmac, char *dstmac, unsigned short srcport, unsigned short dstport, uint32_t isn )
{
    struct ip6_hdr *ip6h;
    struct tcphdr *tcph, *tcph_optioned;
    struct ether_header *ethh;
    void *next;
    int packet_size;
    unsigned short fragid = rand();
    const int DSTOPT_OVERFLOW = 8;
    const unsigned short optlen = fix_up_destination_options_length( 16 ); /* > DSTOPT_OVERFLOW */

    packet_size = SIZEOF_ETHER + SIZEOF_IPV6 + SIZEOF_FRAG + SIZEOF_DESTOPT + optlen - DSTOPT_OVERFLOW;

    ethh = (struct ether_header *) malloc_check( BIG_PACKET_SIZE );
    ip6h = (struct ip6_hdr *) ( (char *) ethh + SIZEOF_ETHER );
    tcph = (struct tcphdr *) ( (char *) ip6h + SIZEOF_IPV6 + SIZEOF_FRAG + DSTOPT_OVERFLOW );

    next = append_ethernet( ethh, srcmac, dstmac, ETHERTYPE_IPV6 );
    next = append_ipv6( next, srcip, dstip, IPPROTO_FRAGMENT, SIZEOF_FRAG + SIZEOF_DESTOPT + optlen - DSTOPT_OVERFLOW );
    next = append_frag_first( next, IPPROTO_DSTOPTS, fragid );
    tcph_optioned = append_dest( next, IPPROTO_TCP, optlen );
    append_tcp_syn( tcph_optioned, srcport, dstport, isn );
    calc_checksum( ip6h, IPPROTO_TCP, SIZEOF_TCP );

    synfrag_send( ethh, packet_size );

    packet_size = SIZEOF_ETHER + SIZEOF_IPV6 + SIZEOF_FRAG + DSTOPT_OVERFLOW + SIZEOF_TCP;

    next = append_ipv6( ip6h, srcip, dstip, IPPROTO_FRAGMENT, SIZEOF_FRAG + DSTOPT_OVERFLOW + SIZEOF_TCP );
    next = append_frag_last( next, IPPROTO_DSTOPTS, SIZEOF_DESTOPT + optlen - DSTOPT_OVERFLOW, fragid );
    memset( next, 0, DSTOPT_OVERFLOW );
    memmove( tcph, tcph_optioned, SIZEOF_TCP );

    synfrag_send( ethh, packet_size );
    free( ethh );
}

void do_ipv6_frag_nomore_tcp( char *interface, char *srcip, char *dstip, char *srcmac, char *dstmac, unsigned short srcport, unsigned short dstport, uint32_t isn )
{
    struct ip6_hdr *ip6h;
    struct tcphdr *tcph;
    struct ether_header *ethh;
    int packet_size;
    unsigned short fragid = rand();
    void *next;

    packet_size = SIZEOF_ETHER + SIZEOF_IPV6 + SIZEOF_FRAG + SIZEOF_TCP;

    ethh = (struct ether_header *) malloc_check( BIG_PACKET_SIZE );
    ip6h = (struct ip6_hdr *) ( (char *) ethh + SIZEOF_ETHER );
    tcph = (struct tcphdr *) ( (char *) ip6h + SIZEOF_IPV6 + SIZEOF_FRAG );

    next = append_ethernet( ethh, srcmac, dstmac, ETHERTYPE_IPV6 );
    next = append_ipv6( next, srcip, dstip, IPPROTO_FRAGMENT, SIZEOF_FRAG + SIZEOF_TCP );
    next = append_frag_last( next, IPPROTO_TCP, 0, fragid );
    append_tcp_syn( next, srcport, dstport, isn );
    calc_checksum( ip6h, IPPROTO_TCP, SIZEOF_TCP );

    synfrag_send( ethh, packet_size );
    free( ethh );
}

void do_ipv6_many_frag_nomore_tcp( char *interface, char *srcip, char *dstip, char *srcmac, char *dstmac, unsigned short srcport, unsigned short dstport, uint32_t isn )
{
    struct ip6_hdr *ip6h;
    struct tcphdr *tcph;
    struct ether_header *ethh;
    int packet_size;
    void *next;
    const int frag_headers = 14; /* Must be >= 1. FreeBSD seems to stop accepting > 15 headers. */

    packet_size = SIZEOF_ETHER + SIZEOF_IPV6 + ( SIZEOF_FRAG * frag_headers ) + SIZEOF_TCP;

    ethh = (struct ether_header *) malloc_check( BIG_PACKET_SIZE );
    ip6h = (struct ip6_hdr *) ( (char *) ethh + SIZEOF_ETHER );
    tcph = (struct tcphdr *) ( (char *) ip6h + SIZEOF_IPV6 + ( SIZEOF_FRAG * frag_headers ) );

    next = append_ethernet( ethh, srcmac, dstmac, ETHERTYPE_IPV6 );
    next = append_ipv6( next, srcip, dstip, IPPROTO_FRAGMENT, ( SIZEOF_FRAG * frag_headers ) + SIZEOF_TCP );
    for ( int x = 0; x < frag_headers - 1; x++ ) {
        next = append_frag_last( next, IPPROTO_FRAGMENT, 0, rand() );
    }
    next = append_frag_last( next, IPPROTO_TCP, 0, rand() );
    append_tcp_syn( next, srcport, dstport, isn );
    calc_checksum( ip6h, IPPROTO_TCP, SIZEOF_TCP );

    synfrag_send( ethh, packet_size );
    free( ethh );
}

#define do_ipv6_big_dstopt_tcp( a, b, c, d, e, f, g, h ) do_ipv6_many_sized_dstopt_tcp( a, b, c, d, e, f, g, h, 1, 512 )
#define do_ipv6_small_dstopt_tcp( a, b, c, d, e, f, g, h ) do_ipv6_many_sized_dstopt_tcp( a, b, c, d, e, f, g, h, 1, 6 )
#define do_ipv6_many_big_dstopt_tcp( a, b, c, d, e, f, g, h ) do_ipv6_many_sized_dstopt_tcp( a, b, c, d, e, f, g, h, 14, 94 )
#define do_ipv6_many_small_dstopt_tcp( a, b, c, d, e, f, g, h ) do_ipv6_many_sized_dstopt_tcp( a, b, c, d, e, f, g, h, 14, 6 )

void do_ipv6_many_sized_dstopt_tcp( char *interface, char *srcip, char *dstip, char *srcmac, char *dstmac, unsigned short srcport, unsigned short dstport, uint32_t isn, size_t count, size_t dstopt_size )
{
    struct ip6_hdr *ip6h;
    struct tcphdr *tcph;
    struct ether_header *ethh;
    int packet_size;
    void *next;
    const int dstopt_headers = 14; /* Must be >= 1. See above. */
    const int optlen = fix_up_destination_options_length( dstopt_size );
    const int my_dstopt_size = SIZEOF_DESTOPT + optlen;

    packet_size = SIZEOF_ETHER + SIZEOF_IPV6 + ( my_dstopt_size * dstopt_headers ) + SIZEOF_TCP;

    ethh = (struct ether_header *) malloc_check( BIG_PACKET_SIZE );
    ip6h = (struct ip6_hdr *) ( (char *) ethh + SIZEOF_ETHER );
    tcph = (struct tcphdr *) ( (char *) ip6h + SIZEOF_IPV6 + ( my_dstopt_size * dstopt_headers ) );

    next = append_ethernet( ethh, srcmac, dstmac, ETHERTYPE_IPV6 );
    next = append_ipv6( next, srcip, dstip, IPPROTO_DSTOPTS, ( my_dstopt_size * dstopt_headers ) + SIZEOF_TCP );
    for ( int x = 0; x < dstopt_headers - 1; x++ ) {
        next = append_dest( next, IPPROTO_DSTOPTS, optlen );
    }
    next = append_dest( next, IPPROTO_TCP, optlen );
    append_tcp_syn( next, srcport, dstport, isn );
    calc_checksum( ip6h, IPPROTO_TCP, SIZEOF_TCP );

    synfrag_send( ethh, packet_size );
    free( ethh );
}

/* Process functions. */
void fork_pcap_listener( char *dstip, char *srcip, unsigned short dstport, unsigned short srcport, enum TEST_TYPE test_type, long receive_timeout )
{
    char *packet_buf;
    char buf;
    int r;

    if ( pipe(pfd) == -1 ) err( 1, "Failed to creatre pipe." );

    listener_pid = fork();
    if ( listener_pid == -1 ) err( 1, "Failed to fork" );
    if ( listener_pid )  {
        close( pfd[1] );
        read( pfd[0], &buf, 1 );
        return;
    }
    close( pfd[0] );
    /*
     * Due to how pcap works there's still a race between we signal that we are
     * ready and when we actually call select(). Will this even help with our
     * race condition if write() doesn't block? The documentation seems unclear
     * as to the advantages of O_NONBLOCK with a 1 byte write.
     */
    fcntl( pfd[1], F_SETFL, O_NONBLOCK );

    pcap_setdirection( pcap, PCAP_D_IN );

    r = receive_synfrag_reply( dstip, srcip, dstport, srcport, test_type, &packet_buf, receive_timeout );
    if ( r ) {
        write( pfd[1], &r, sizeof( int ) );
        write( pfd[1], packet_buf, r );
    } else {
        r = 0;
        write( pfd[1], &r, sizeof( int ) );
    }
    close( pfd[1] );
    exit( 0 );
}

int harvest_pcap_listener( char **packet_buf ) {
    int packet_buf_size;

    if ( read( pfd[0], &packet_buf_size, sizeof( int ) ) < sizeof( int ) )
        errx( 1, "Error communicating with child process." );
    /* No packet received. */
    if ( packet_buf_size == 0 ) return 0;
    if ( packet_buf_size > PCAP_CAPTURE_LEN || packet_buf_size < 1 )
        errx( 1, "Bad data received from child process." );
    *packet_buf = (char *) malloc_check( packet_buf_size );
    if ( read( pfd[0], *packet_buf, packet_buf_size ) < packet_buf_size )
        errx( 1, "Error communicating with child process (2)." );
    wait( NULL );
    return packet_buf_size;
}

void print_test_types( void )
{
    const char *test;
    int x = 0;

    fprintf( stderr, "Available test types:\n\n" );
    while ( ( test = test_names[x++] ) ) {
        fprintf( stderr, "%s\n", test );
    }
}

void exit_with_usage( void )
{
    fprintf( stderr, "synfrag usage:\n" );
    fprintf( stderr, "--help | -h  This message.\n" );
    fprintf( stderr, "--srcip      Source IP address (this host).\n" );
    fprintf( stderr, "--dstip      Destination IP address (target).\n" );
    fprintf( stderr, "--srcport    Source port for TCP tests (defaults to rand()).\n" );
    fprintf( stderr, "--dstport    Destination port for TCP tests.\n" );
    fprintf( stderr, "--dstmac     Destination MAC address (default gw or target host if on subnet).\n" );
    fprintf( stderr, "--interface  Packet source interface.\n" );
    fprintf( stderr, "--test       Type of test to run.\n" );
    fprintf( stderr, "--timeout    Reply timeout in seconds (defaults to 10).\n" );
    fprintf( stderr, "--replay     Listen for an outgoing TCP SYN packet that matches the specified\n"
                     "             parameters and re-send a duplicate in the test packet format.\n" );
#ifdef DO_TAP
    fprintf( stderr, "--tap        Create a TAP device and transmit the packet on that device, while\n"
                     "             listening on the interface specified by --interface. This is to\n"
                     "             work around an issue on FreeBSD where raw frames can't be sent on\n"
                     "             FreeBSD gif(4) devices. Requires IP/IPv6 routing to be enabled.\n" );
#endif
    fprintf( stderr, "\n" );
    print_test_types();
    fprintf( stderr, "\nAll TCP tests send syn packets, all ICMP/6 test send ping.\n" );
    fprintf( stderr, "All \"frag\" tests send fragments that are below the minimum packet size.\n" );
    fprintf( stderr, "All \"optioned\" tests send fragments that meet the minimum packet size.\n" );
    exit( 2 );
}

void copy_arg_string( char **dst, char *opt )
{
    *dst = malloc_check( strlen( opt ) + 1 );
    memcpy( *dst, opt, strlen( opt) + 1 );
}

void ip_test_arg( char *opt )
{
    struct in6_addr iptest;
    if (
        ( !inet_pton( AF_INET, opt, &iptest ) ) &&
        ( !inet_pton( AF_INET6, opt, &iptest ) )
    ) errx( 1, "Invalid IP address: %s", opt );
}

enum TEST_TYPE parse_args(
    int argc,
    char **argv,
    char **srcip,
    char **dstip,
    int *srcport,
    unsigned short *dstport,
    char **dstmac,
    char **interface,
    const char **test_name,
    long *timeout,
    int *replay,
    int *do_tap
) {
    int x = 0;
    int option_index = 0;
    int c, tmpport;
    long tmptime;
    const char *possible_match;
    enum TEST_TYPE test_type = 0;
    static struct option long_options[] = {
        {"srcip", required_argument, 0, 0},
        {"dstip", required_argument, 0, 0},
        {"srcport", required_argument, 0, 0},
        {"dstport", required_argument, 0, 0},
        {"dstmac", required_argument, 0, 0},
        {"interface", required_argument, 0, 0},
        {"test", required_argument, 0, 0},
        {"help", no_argument, 0, 0},
        {"timeout", required_argument, 0, 0},
        {"replay", no_argument, 0, 0},
        {"tap", no_argument, 0, 0},
        {0, 0, 0, 0}
    };

    if ( argc < 2 ) exit_with_usage();

    *srcip = *dstip = *dstmac = *interface = NULL;
    *srcport = -1;
    *dstport = *replay = *do_tap = 0;

    while ( 1 ) {
        c = getopt_long(argc, argv, "h", long_options, &option_index);
        if ( c != 0 && c != 'h' ) break;

        if ( ( c == 'h' ) || ( strcmp( long_options[option_index].name, "help" ) == 0 ) ) {
            exit_with_usage();

        } else if ( strcmp( long_options[option_index].name, "srcip" ) == 0 ) {
            copy_arg_string( srcip, optarg );

        } else if ( strcmp( long_options[option_index].name, "dstip" ) == 0 ) {
            copy_arg_string( dstip, optarg );

        } else if ( strcmp( long_options[option_index].name, "dstmac" ) == 0 ) {
            copy_arg_string( dstmac, optarg );

        } else if ( strcmp( long_options[option_index].name, "interface" ) == 0 ) {
            copy_arg_string( interface, optarg );

        } else if ( strcmp( long_options[option_index].name, "srcport" ) == 0 ) {
            tmpport = atoi( optarg );
            if ( tmpport > 65535 || tmpport < 1 ) errx( 1, "Invalid value for srcport" );
            *srcport = (unsigned short) tmpport;

        } else if ( strcmp( long_options[option_index].name, "dstport" ) == 0 ) {
            tmpport = atoi( optarg );
            if ( tmpport > 65535 || tmpport < 1 ) errx( 1, "Invalid value for dstport" );
            *dstport = (unsigned short) tmpport;

        } else if ( strcmp( long_options[option_index].name, "timeout" ) == 0 ) {
            tmptime = atol( optarg );
            if ( tmptime < 1 ) errx( 1, "Invalid value for timeout" );
            *timeout = tmptime;

        } else if ( strcmp( long_options[option_index].name, "replay" ) == 0 ) {
            *replay = 1;

        } else if ( strcmp( long_options[option_index].name, "tap" ) == 0 ) {
            *do_tap = 1;

        } else if ( strcmp( long_options[option_index].name, "test" ) == 0 ) {
            while ( ( possible_match = test_names[x] ) ) {
                if ( strcmp( optarg, possible_match ) == 0 ) {
                    test_type = test_indexes[x];
                    *test_name = test_names[x];
                    break;
                }
                x++;
            }
        }
    }

    if ( optind < argc ) exit_with_usage();

    if ( !*srcip ) errx( 1, "Missing srcip" );
    if ( !*dstip ) errx( 1, "Missing dstip" );
    if ( !*do_tap && !*dstmac ) errx( 1, "Missing dstmac" );
    if ( !*interface ) errx( 1, "Missing interface" );
    if ( !test_type ) {
        fprintf( stderr, "Missing or invalid test type\n" );
        print_test_types();
        exit( 1 );
    }

    if ( IS_TEST_TCP( test_type ) ) {
        if ( !*dstport ) errx( 1, "Missing dstport" );
    }

    return test_type;
}

#ifdef DO_TAP
void tap_cleanup( void )
{
    struct ifreq ifr;
    int s = socket( PF_INET, SOCK_DGRAM, 0 );
    if ( s < 0 ) err( 1, "socket failed, unable to destroy tap interface %s", tapname );
    memset( &ifr, 0, sizeof( struct ifreq ) );
    strncpy( ifr.ifr_name, tapname, sizeof( ifr.ifr_name ) );
    ioctl( s, SIOCIFDESTROY, &ifr );
    close( s );
}

void handle_sigint( int dummy ) {
    tap_cleanup();
    exit(1);
}
#endif

int main( int argc, char **argv )
{
    char pcaperr[PCAP_ERRBUF_SIZE];
    int r;
    enum TEST_TYPE test_type;
    char *interface;
    char *srcip;
    char *dstip;
    char *srcmac;
    char *dstmac;
    uint16_t dstport;
    int srcport_param;
    uint16_t srcport;
    uint32_t isn = htonl( rand() );
    char *packet_buf;
    const char *test_name;
    long receive_timeout = DEFAULT_TIMEOUT_SECONDS;
    int replay;
    int do_tap;

    test_type = parse_args( argc, argv, &srcip, &dstip, &srcport_param, &dstport, &dstmac, &interface, &test_name, &receive_timeout, &replay, &do_tap );
    srand( getpid() );

    if ( srcport_param == -1 ) {
        srcport = rand();
        if ( srcport < 1024 ) srcport += 1024;
    } else {
        srcport = srcport_param;
    }

    if ( ( pcap = pcap_open_live( interface, PCAP_CAPTURE_LEN, 0, 1, pcaperr ) ) == NULL )
        errx( 1, "pcap_open_live failed: %s", pcaperr );

    interface_type = pcap_datalink( pcap );
    if ( interface_type != DLT_EN10MB && ( interface_type != DLT_NULL && !do_tap ) ) {
        errx( 1, "unsupported interface type specified (%i).", interface_type );
    }

    if ( do_tap ) {
#ifndef DO_TAP
        err( 1, "TAP mode not supported on this OS." );
#else
        struct ifreq ifr;
        int s;
        tapfd = open( "/dev/tap", O_RDWR );
        if ( tapfd < 0 ) err( 1, "tap open" );
        ioctl( tapfd, TAPGIFNAME, &ifr );
        dstmac = get_interface_mac( ifr.ifr_name );
        srcmac = "00:00:5E:00:53:40"; /* Make up a source. */
        if ( dstmac == NULL ) err( 1, "strdup" );
        tapname = strdup( ifr.ifr_name );

        s = socket( PF_INET, SOCK_DGRAM, 0 );
        if ( s < 0 ) err( 1, "socket open" );
        ioctl( s, SIOCGIFFLAGS, &ifr );
        strncpy( ifr.ifr_name, tapname, sizeof( ifr.ifr_name ) );
        ifr.ifr_flags |= IFF_UP;
        ioctl( s, SIOCSIFFLAGS, &ifr );

        atexit( tap_cleanup );
        close( s );

        signal( SIGINT, handle_sigint );
#endif
    } else {
        if ( ( srcmac = get_interface_mac( interface ) ) == NULL )
            errx( 1, "Failed to get MAC address for %s", interface );
    }

    printf( "Starting test \"%s\". Opening interface \"%s\".", test_name, interface );
    if ( do_tap ) printf( " Allocated TAP interface \"%s\" for transmission.", tapname );
    printf( "\n\n" );

    if ( replay ) {
        if ( !get_isn_for_replay( interface, srcip, dstip, dstport, test_type, &isn, &srcport ) ) {
            errx( 1, "Failed to find outgoing TCP SYN to replay." );
        }
    }

    fork_pcap_listener( dstip, srcip, dstport, srcport, test_type, receive_timeout );

    switch ( test_type ) {
        case TEST_IPV4_TCP:
            do_ipv4_syn( interface, srcip, dstip, srcmac, dstmac, srcport, dstport, isn );
            break;
        case TEST_IPV4_FRAG_TCP:
            do_ipv4_frag_tcp( interface, srcip, dstip, srcmac, dstmac, srcport, dstport, isn );
            break;
        case TEST_IPV4_FRAG_ICMP:
            do_ipv4_frag_icmp( interface, srcip, dstip, srcmac, dstmac );
            break;
        case TEST_IPV4_DSTOPT_FRAG_TCP:
            do_ipv4_options_tcp_frag( interface, srcip, dstip, srcmac, dstmac, srcport, dstport, isn );
            break;
        case TEST_IPV4_DSTOPT_FRAG_ICMP:
            do_ipv4_options_icmp_frag( interface, srcip, dstip, srcmac, dstmac );
            break;

        case TEST_IPV6_TCP:
            do_ipv6_syn( interface, srcip, dstip, srcmac, dstmac, srcport, dstport, isn );
            break;
        case TEST_IPV6_FRAG_TCP:
            do_ipv6_frag_tcp( interface, srcip, dstip, srcmac, dstmac, srcport, dstport, isn );
            break;
        case TEST_IPV6_FRAG_ICMP6:
            do_ipv6_frag_icmp( interface, srcip, dstip, srcmac, dstmac );
            break;
        case TEST_IPV6_DSTOPT_FRAG_TCP:
            do_ipv6_dstopt_frag_tcp( interface, srcip, dstip, srcmac, dstmac, srcport, dstport, isn );
            break;
        case TEST_IPV6_FRAG_DSTOPT_TCP:
            do_ipv6_frag_dstopt_tcp( interface, srcip, dstip, srcmac, dstmac, srcport, dstport, isn );
            break;
        case TEST_IPV6_FRAG_DSTOPT2_TCP:
            do_ipv6_frag_dstopt2_tcp( interface, srcip, dstip, srcmac, dstmac, srcport, dstport, isn );
            break;
        case TEST_IPV6_FRAG_FRAG_TCP:
            do_ipv6_frag_frag_tcp( interface, srcip, dstip, srcmac, dstmac, srcport, dstport, isn );
            break;
        case TEST_IPV6_FRAG_NOMORE_TCP:
            do_ipv6_frag_nomore_tcp( interface, srcip, dstip, srcmac, dstmac, srcport, dstport, isn );
            break;
        case TEST_IPV6_MANY_FRAG_NOMORE_TCP:
            do_ipv6_many_frag_nomore_tcp( interface, srcip, dstip, srcmac, dstmac, srcport, dstport, isn );
            break;
        case TEST_IPV6_MANY_SMALL_DSTOPT_TCP:
            do_ipv6_many_small_dstopt_tcp( interface, srcip, dstip, srcmac, dstmac, srcport, dstport, isn );
            break;
        case TEST_IPV6_MANY_BIG_DSTOPT_TCP:
            do_ipv6_many_big_dstopt_tcp( interface, srcip, dstip, srcmac, dstmac, srcport, dstport, isn );
            break;
        case TEST_IPV6_SMALL_DSTOPT_TCP:
            do_ipv6_small_dstopt_tcp( interface, srcip, dstip, srcmac, dstmac, srcport, dstport, isn );
            break;
        case TEST_IPV6_BIG_DSTOPT_TCP:
            do_ipv6_big_dstopt_tcp( interface, srcip, dstip, srcmac, dstmac, srcport, dstport, isn );
            break;
        case TEST_IPV6_FRAGGED_DSTOPT_TCP:
            do_ipv6_fragged_dstopt_tcp( interface, srcip, dstip, srcmac, dstmac, srcport, dstport, isn );
            break;
        case TEST_IPV6_DSTOPT_FRAG_ICMP6:
            do_ipv6_dstopt_frag_icmp( interface, srcip, dstip, srcmac, dstmac );
            break;

        default:
            errx( 1, "Unsupported test type!" );
    }

    printf( "Packet transmission successful, waiting for reply...\n\n" );

    r = harvest_pcap_listener( &packet_buf );
    if ( !r ) errx( 1, "Test failed, no response before time out (%li seconds).\n", receive_timeout );
    if ( check_received_packet( r, packet_buf, test_type ) ) {
        printf( "\nTest was successful.\n" );
        free( packet_buf );
        return 0;
    }
    printf( "\nTest failed.\n" );
    free( packet_buf );
    return 1;
}

