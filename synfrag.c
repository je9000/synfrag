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
#include <unistd.h>
#include <err.h>
#include <string.h>
#include <netdb.h>

#ifdef __FreeBSD__
#include <netinet/in_systm.h>
#include <ifaddrs.h>
#include <net/if_dl.h>
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
    TEST_IPV6_DSTOPT_FRAG_ICMP6,

    0
};

char *test_names[] = {
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
    "v6-dstopt-frag-icmp6",

    NULL
};

pcap_t *pcap;
pid_t listener_pid;
int pfd[2];

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
#elif __FreeBSD__
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
char *print_a_packet( char *, int, unsigned short );
void synfrag_send( void *packet, int len )
{
    static unsigned int packets_sent = 1;
    printf( "Sending packet %u:\n\n", packets_sent++ );
    print_a_packet( packet, len, 0 );
    putchar( '\n' );
    if ( pcap_inject( pcap, packet, len ) != len ) errx( 1, "pcap_inject" );
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
 Iphl: %i (%i bytes)\n",
        (char *) &srcbuf,
        (char *) &dstbuf,
        iph->ip_p, ip_protocol_to_name( iph->ip_p ),
        ntohs( iph->ip_off ) & 0x1FFF, ( ntohs( iph->ip_off ) & 0x1FFF ) * FRAGMENT_OFFSET_TO_BYTES,
        ntohs( iph->ip_off ) >> IP_FLAGS_OFFSET, flag_names,
        iph->ip_hl, iph->ip_hl * 4
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
 Payload Len: %i\n",
        (char *) &srcbuf,
        (char *) &dstbuf,
        ip6h->ip6_nxt, ip_protocol_to_name( ip6h->ip6_nxt ),
        ntohs( ip6h->ip6_plen )
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
 Flags: %i (%s)\n",
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
 More Frags: %i\n",
        fragh->ip6f_nxt, ip_protocol_to_name( fragh->ip6f_nxt ),
        ntohs( fragh->ip6f_ident ),
        ntohs( fragh->ip6f_offlg ),
        ntohs( fragh->ip6f_offlg ) >> 3, ( ntohs( fragh->ip6f_offlg ) >> 3 ) * 8,
        fragh->ip6f_offlg & IP6F_MORE_FRAG ? 1 : 0
    );
}

void print_dstopth( struct ip6_dest *desth )
{
    printf( "Destination Options Header:\n\
 Next Header: %i (%s)\n\
 Length: %i (%i bytes)\n",
        desth->ip6d_nxt,
        ip_protocol_to_name( desth->ip6d_nxt ),
        desth->ip6d_len,
        desth->ip6d_len * 8
    );
}

/* Returns the layer 4 header if we found one. */
char *print_a_packet( char *packet_data, int len, unsigned short wanted_type )
{
    struct ip *iph;
    struct ip6_hdr *ip6h;
    size_t s;
    struct ether_header *ethh = (struct ether_header *) packet_data;
    int found_type = -1;
    char *found_header = NULL;

    if ( len < SIZEOF_ETHER ) {
        printf( "Ethernet Frame: \nToo short\n" );
        return NULL;
    }
    print_ethh( ethh );

    if ( ntohs( ethh->ether_type ) == ETHERTYPE_IP ) {
        iph = (struct ip *) ( packet_data + SIZEOF_ETHER );
        s = SIZEOF_ETHER + ( iph->ip_hl * 4 );
        if ( s > len ) {
            printf( "IPv4 Header:\n Too short\n" );
            return NULL;
        }
        print_iph( iph );
        if ( ( ntohs( iph->ip_off ) & 0x1FFF ) || ntohs( iph->ip_off ) & ( 1 << IP_FLAGS_OFFSET ) ) {
            printf( "(Fragment)\n" );
            found_type = -1;
            found_header = NULL;
        } else if ( iph->ip_p == IPPROTO_TCP ) {
            if ( s + SIZEOF_TCP > len ) {
                printf( "TCP Header:\n Too short\n" );
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

    } else if ( ntohs( ethh->ether_type ) == ETHERTYPE_IPV6 ) {
        ip6h = (struct ip6_hdr *) ( packet_data + SIZEOF_ETHER );
        s = SIZEOF_ETHER + SIZEOF_IPV6;
        if ( s > len ) {
            printf( "IPv6 Header:\n Too short\n" );
            return NULL;
        }
        print_ip6h( ip6h );
        if ( ip6h->ip6_nxt == IPPROTO_TCP ) {
            if ( s + SIZEOF_TCP > len ) {
                printf( "TCP Header:\n Too short\n" );
                return NULL;
            }
            print_tcph( (struct tcphdr *) ( packet_data + s ) );
            found_type = IPPROTO_TCP;
            found_header = packet_data + s;
        } else if ( ip6h->ip6_nxt == IPPROTO_ICMPV6 ) {
            if ( s + SIZEOF_ICMP6 > len ) {
                printf( "ICMP6 Header:\n Too short\n" );
                return NULL;
            }
            print_icmp6h( (struct icmp6_hdr *) ( packet_data + s ) );
            found_type = IPPROTO_ICMPV6;
            found_header = packet_data + s;
        } else if ( ip6h->ip6_nxt == IPPROTO_FRAGMENT ) {
            if ( s + sizeof( struct ip6_frag ) > len ) {
                printf( "Fragment Header:\n Too short\n" );
                return NULL;
            }
            print_fragh( (struct ip6_frag *) ( packet_data + s ) );
            found_type = IPPROTO_FRAGMENT;
            found_header = packet_data + s;
        } else if ( ip6h->ip6_nxt == IPPROTO_DSTOPTS ) {
            /*
             * Wow, this is ugly! First check if we have enough room in the
             * buffer to read the destopts header, then check we have to check
             * again to see if we have the complete header.
             */
            if ( s + sizeof( struct ip6_dest ) > len ) {
                printf( "Destination Options Header:\n Too short\n" );
                return NULL;
            }
            if ( 
                ( s
                    + sizeof( struct ip6_dest )
                    + ( ( (struct ip6_dest *) packet_data + s )->ip6d_len * 8 )
                )
                > len ) {
                printf( "Destination Options Header:\n Too short (options truncated)\n" );
                return NULL;
            }
            print_dstopth( (struct ip6_dest *) ( packet_data + s ) );
            found_type = IPPROTO_DSTOPTS;
            found_header = packet_data + s + ( ( (struct ip6_dest *) packet_data + s )->ip6d_len * 8 );
        } else {
            printf( "Unsupported IPv6 Header:\n Next header: %i (%s)\n",
                ip6h->ip6_nxt,
                ip_protocol_to_name( ip6h->ip6_nxt )
            );
            return NULL;
        }

    } else {
        printf( "Unsupported Protocol:\n Ethertype: %i (%s)\n",
            ntohs( ethh->ether_type ),
            ether_protocol_to_name( ethh->ether_type )
        );
        return NULL;
    }

    if ( wanted_type == found_type ) return found_header;
    return NULL;
}

int receive_a_packet( char *srcip, char *dstip, unsigned short srcport, unsigned short dstport, enum TEST_TYPE test_type, char **packet_buf, long receive_timeout )
{
    struct pcap_pkthdr *received_packet_pcap;
    struct bpf_program pcap_filter;
    unsigned char *received_packet_data;
/*
 * My back-of-the-napkin for the maximum length for the ipv6 filter string
 * below + 1 byte for the trailing NULL 
 */
#define FILTER_STR_LEN 203 
    char filter_str[FILTER_STR_LEN];
    int r, fd;
    fd_set select_me;
    struct timeval ts;

    /*
     * Something prior to now should have validated srcip and dstip are valid
     * IP addresses, we hope. Napkin math says we shouldn't even be close to
     * overflowing our buffer.
     */
    if ( IS_TEST_IPV4( test_type ) ) {
        r = snprintf(
            (char *) &filter_str,
            FILTER_STR_LEN,
            "src %s and dst %s and (icmp or (tcp and src port %i and dst port %i))",
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
            "src %s and dst %s and ((icmp6 and ip6[40] != 135 and ip6[40] != 136) or (tcp and src port %i and dst port %i))",
            srcip,
            dstip,
            srcport,
            dstport
        );
    }
    if ( r < 0 || r >= FILTER_STR_LEN ) errx( 1, "snprintf for pcap filter failed" );
    if ( pcap_compile( pcap, &pcap_filter, (char *) &filter_str, 1, 0 ) == -1 )
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

    /*
     * Signal we're ready to go. Still a race condition. I don't see how to
     * work around this with pcap. 
     */
    write( pfd[1], ".", 1 );
    r = select( fd + 1, &select_me, NULL, NULL, &ts );
    /* Timed out */
    if ( r == 0 ) return 0;

    r = pcap_next_ex( pcap, &received_packet_pcap, (const unsigned char **) &received_packet_data );

    /* Error or pcap_next_ex timed out (should never happen) */
    if ( r < 1 ) return 0;
    if ( received_packet_pcap->len > received_packet_pcap->caplen ) errx( 1, "pcap didn't capture the whole packet." );

    *packet_buf = (char *) received_packet_data;
    return received_packet_pcap->len;
}

int check_received_packet( int buf_len, char *packet_buf, enum TEST_TYPE test_type ) {
    struct ether_header *received_packet_data = (struct ether_header *) packet_buf;
    struct tcphdr *tcph;
    struct icmp *icmph;
    struct icmp6_hdr *icmp6h;

    printf( "Received packet 1:\n\n" );

    if ( IS_TEST_IPV4( test_type ) && IS_TEST_ICMP( test_type ) ) {
        icmph = (struct icmp *) print_a_packet( (char *) received_packet_data, buf_len, IPPROTO_ICMP );
        if ( !icmph ) return 0;
        if ( icmph->icmp_type == ICMP_ECHOREPLY && icmph->icmp_id == htons( SOURCE_PORT ) ) return 1;
    } else if ( IS_TEST_IPV6( test_type ) && IS_TEST_ICMP( test_type ) ) {
        icmp6h = (struct icmp6_hdr *) print_a_packet( (char *) received_packet_data, buf_len, IPPROTO_ICMPV6 );
        if ( !icmp6h ) return 0;
        if ( icmp6h->icmp6_type == ICMP6_ECHO_REPLY && icmp6h->icmp6_id == htons( SOURCE_PORT ) ) return 1;
    } else { /* Assume pcap picked the right address family for our packet. */
        tcph = (struct tcphdr *) print_a_packet( (char *) received_packet_data, buf_len, IPPROTO_TCP );
        if ( !tcph ) return 0;
        if ( ( tcph->th_flags & ( TH_SYN|TH_ACK ) ) && !( tcph->th_flags & TH_RST ) ) {
            return 1;
        }
    }
    printf( "Received reply but it wasn't what we were hoping for.\n" );
    return 0;
}

/* IPv4 tests. */
void do_ipv4_syn( char *interface, char *srcip, char *dstip, char *srcmac, char *dstmac, unsigned short dstport )
{
    struct ip *iph;
    struct tcphdr *tcph;
    struct ether_header *ethh;
    int packet_size;

    packet_size = SIZEOF_ETHER + SIZEOF_TCP + SIZEOF_IPV4;

    ethh = (struct ether_header *) malloc_check( packet_size );
    iph = (struct ip *) ( (char *) ethh + SIZEOF_ETHER );
    tcph = (struct tcphdr *) ( (char *) iph + SIZEOF_IPV4 );

    build_ethernet( ethh, srcmac, dstmac, ETHERTYPE_IP );
    append_ipv4( iph, srcip, dstip, IPPROTO_TCP );
    append_tcp_syn( iph, tcph, SOURCE_PORT, dstport );
    calc_checksum( iph, IPPROTO_TCP, SIZEOF_TCP );
    calc_checksum( iph, IPPROTO_IP, SIZEOF_IPV4 );

    synfrag_send( ethh, packet_size );
    free( ethh );
}

void do_ipv4_frag_tcp( char *interface, char *srcip, char *dstip, char *srcmac, char *dstmac, unsigned short dstport )
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

    build_ethernet( ethh, srcmac, dstmac, ETHERTYPE_IP );
    append_ipv4_short_frag1( iph, srcip, dstip, IPPROTO_TCP, fragid );
    append_tcp_syn( iph, tcph, SOURCE_PORT, dstport );
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

    build_ethernet( ethh, srcmac, dstmac, ETHERTYPE_IP );
    append_ipv4_short_frag1( iph, srcip, dstip, IPPROTO_ICMP, fragid );
    append_icmp_ping( iph, icmph, pinglen );
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

void do_ipv4_options_tcp_frag( char *interface, char *srcip, char *dstip, char *srcmac, char *dstmac, unsigned short dstport )
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

    build_ethernet( ethh, srcmac, dstmac, ETHERTYPE_IP );
    append_ipv4_optioned_frag1( iph, srcip, dstip, IPPROTO_TCP, fragid, optlen );
    append_tcp_syn( iph, tcph_optioned, SOURCE_PORT, dstport );
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

    build_ethernet( ethh, srcmac, dstmac, ETHERTYPE_IP );
    append_ipv4_optioned_frag1( iph, srcip, dstip, IPPROTO_ICMP, fragid, optlen );
    append_icmp_ping( iph, icmph_optioned, pinglen );
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
void do_ipv6_syn( char *interface, char *srcip, char *dstip, char *srcmac, char *dstmac, unsigned short dstport )
{
    struct ip6_hdr *ip6h;
    struct tcphdr *tcph;
    struct ether_header *ethh;
    int packet_size;

    packet_size = SIZEOF_ETHER + SIZEOF_IPV6 + SIZEOF_TCP;

    ethh = (struct ether_header *) malloc_check( packet_size );
    ip6h = (struct ip6_hdr *) ( (char *) ethh + SIZEOF_ETHER );
    tcph = (struct tcphdr *) ( (char *) ip6h + SIZEOF_IPV6 );

    build_ethernet( ethh, srcmac, dstmac, ETHERTYPE_IPV6 );
    append_ipv6( ip6h, srcip, dstip, IPPROTO_TCP, SIZEOF_TCP );
    append_tcp_syn( ip6h, tcph, SOURCE_PORT, dstport );
    calc_checksum( ip6h, IPPROTO_TCP, SIZEOF_TCP );

    synfrag_send( ethh, packet_size );
    free( ethh );
}

void do_ipv6_frag_tcp( char *interface, char *srcip, char *dstip, char *srcmac, char *dstmac, unsigned short dstport )
{
    struct ip6_hdr *ip6h;
    struct tcphdr *tcph;
    struct ether_header *ethh;
    int packet_size;
    unsigned short fragid = rand();

    packet_size = SIZEOF_ETHER + SIZEOF_IPV6 + sizeof( struct ip6_frag ) + MINIMUM_FRAGMENT_SIZE;

    ethh = (struct ether_header *) malloc_check( BIG_PACKET_SIZE );
    ip6h = (struct ip6_hdr *) ( (char *) ethh + SIZEOF_ETHER );
    tcph = (struct tcphdr *) ( (char *) ip6h + SIZEOF_IPV6 + sizeof( struct ip6_frag ) );

    build_ethernet( ethh, srcmac, dstmac, ETHERTYPE_IPV6 );
    append_ipv6_short_frag1( ip6h, srcip, dstip, IPPROTO_TCP, fragid );
    append_tcp_syn( ip6h, tcph, SOURCE_PORT, dstport );
    calc_checksum( ip6h, IPPROTO_TCP, SIZEOF_TCP );

    synfrag_send( ethh, packet_size );

    packet_size = SIZEOF_ETHER + SIZEOF_IPV6 + sizeof( struct ip6_frag ) + SIZEOF_TCP - MINIMUM_FRAGMENT_SIZE;

    append_ipv6_frag2( ip6h, srcip, dstip, IPPROTO_TCP, fragid, SIZEOF_TCP - MINIMUM_FRAGMENT_SIZE );
    memmove( tcph, (char *) tcph + MINIMUM_FRAGMENT_SIZE, SIZEOF_TCP - MINIMUM_FRAGMENT_SIZE );

    synfrag_send( ethh, packet_size );
    free( ethh );
}

void do_ipv6_frag_icmp( char *interface, char *srcip, char *dstip, char *srcmac, char *dstmac )
{
    struct ip6_hdr *ip6h;
    struct icmp6_hdr *icmp6h;
    struct ether_header *ethh;
    int packet_size;
    unsigned short fragid = rand();
    unsigned short pinglen = 40;

    packet_size = SIZEOF_ETHER + SIZEOF_IPV6 + sizeof( struct ip6_frag ) + MINIMUM_FRAGMENT_SIZE;

    ethh = (struct ether_header *) malloc_check( BIG_PACKET_SIZE );
    ip6h = (struct ip6_hdr *) ( (char *) ethh + SIZEOF_ETHER );
    icmp6h = (struct icmp6_hdr *) ( (char *) ip6h + SIZEOF_IPV6 + sizeof( struct ip6_frag ) );

    build_ethernet( ethh, srcmac, dstmac, ETHERTYPE_IPV6 );
    append_ipv6_short_frag1( ip6h, srcip, dstip, IPPROTO_ICMPV6, fragid );
    append_icmp6_ping( ip6h, icmp6h, pinglen );
    calc_checksum( ip6h, IPPROTO_ICMPV6, SIZEOF_ICMP6 + pinglen );

    synfrag_send( ethh, packet_size );

    packet_size = SIZEOF_ETHER + SIZEOF_IPV6 + sizeof( struct ip6_frag ) + SIZEOF_ICMP6 + pinglen - MINIMUM_FRAGMENT_SIZE;

    append_ipv6_frag2( ip6h, srcip, dstip, IPPROTO_ICMPV6, fragid, SIZEOF_ICMP6 + pinglen - MINIMUM_FRAGMENT_SIZE );
    memmove( icmp6h, (char *) icmp6h + MINIMUM_FRAGMENT_SIZE, SIZEOF_ICMP6 + pinglen - MINIMUM_FRAGMENT_SIZE );

    synfrag_send( ethh, packet_size );
    free( ethh );
}

void do_ipv6_dstopt_frag_icmp( char *interface, char *srcip, char *dstip, char *srcmac, char *dstmac )
{
    struct ip6_hdr *ip6h;
    struct icmp6_hdr *icmp6h, *icmp6h_optioned;
    struct ether_header *ethh;
    int packet_size;
    unsigned short fragid = rand();
    unsigned short optlen = fix_up_destination_options_length(
         MINIMUM_PACKET_SIZE - SIZEOF_IPV6 - sizeof( struct ip6_dest ) - sizeof( struct ip6_frag ) - MINIMUM_FRAGMENT_SIZE
    );
    /*
     * pinglen must be > 6 or our first packet will be <= MINIMUM_PACKET_SIZE bytes and
     * our second packet empty. 
     */
    unsigned short pinglen = 40;

    packet_size = SIZEOF_ETHER + SIZEOF_IPV6 + sizeof( struct ip6_dest ) + optlen + sizeof( struct ip6_frag ) + MINIMUM_FRAGMENT_SIZE;

    ethh = (struct ether_header *) malloc_check( BIG_PACKET_SIZE );
    ip6h = (struct ip6_hdr *) ( (char *) ethh + SIZEOF_ETHER );
    icmp6h = (struct icmp6_hdr *) ( (char *) ip6h + SIZEOF_IPV6 + sizeof( struct ip6_frag ) );
    icmp6h_optioned = (struct icmp6_hdr *) ( (char *) ip6h + SIZEOF_IPV6 + sizeof( struct ip6_dest ) + optlen + sizeof( struct ip6_frag ) );

    build_ethernet( ethh, srcmac, dstmac, ETHERTYPE_IPV6 );
    append_ipv6_optioned_frag1( ip6h, srcip, dstip, IPPROTO_ICMPV6, fragid, optlen );
    append_icmp6_ping( ip6h, icmp6h_optioned, pinglen );
    calc_checksum( ip6h, IPPROTO_ICMPV6, SIZEOF_ICMP6 + pinglen );

    synfrag_send( ethh, packet_size );

    packet_size = SIZEOF_ETHER + SIZEOF_IPV6 + sizeof( struct ip6_frag ) + SIZEOF_PING + pinglen - MINIMUM_FRAGMENT_SIZE;

    append_ipv6_frag2( ip6h, srcip, dstip, IPPROTO_ICMPV6, fragid, SIZEOF_ICMP6 + pinglen - MINIMUM_FRAGMENT_SIZE );
    memmove( icmp6h, (char *) icmp6h_optioned + MINIMUM_FRAGMENT_SIZE, SIZEOF_ICMP6 + pinglen - MINIMUM_FRAGMENT_SIZE );

    synfrag_send( ethh, packet_size );
    free( ethh );
}

void do_ipv6_dstopt_frag_tcp( char *interface, char *srcip, char *dstip, char *srcmac, char *dstmac, unsigned short dstport )
{
    struct ip6_hdr *ip6h;
    struct tcphdr *tcph, *tcph_optioned;
    struct ether_header *ethh;
    int packet_size;
    unsigned short fragid = rand();
    unsigned short optlen = fix_up_destination_options_length(
        MINIMUM_PACKET_SIZE - SIZEOF_IPV6 - sizeof( struct ip6_dest ) - sizeof( struct ip6_frag ) - MINIMUM_FRAGMENT_SIZE
    );

    packet_size = SIZEOF_ETHER + SIZEOF_IPV6 + sizeof( struct ip6_dest ) + optlen + sizeof( struct ip6_frag ) + MINIMUM_FRAGMENT_SIZE;

    ethh = (struct ether_header *) malloc_check( BIG_PACKET_SIZE );
    ip6h = (struct ip6_hdr *) ( (char *) ethh + SIZEOF_ETHER );
    tcph = (struct tcphdr *) ( (char *) ip6h + SIZEOF_IPV6 + sizeof( struct ip6_frag ) );
    tcph_optioned = (struct tcphdr *) ( (char *) ip6h + SIZEOF_IPV6 + sizeof( struct ip6_dest ) + optlen + sizeof( struct ip6_frag ) );

    build_ethernet( ethh, srcmac, dstmac, ETHERTYPE_IPV6 );
    append_ipv6_optioned_frag1( ip6h, srcip, dstip, IPPROTO_TCP, fragid, optlen );
    append_tcp_syn( ip6h, tcph_optioned, SOURCE_PORT, dstport );
    calc_checksum( ip6h, IPPROTO_TCP, SIZEOF_TCP );

    synfrag_send( ethh, packet_size );

    packet_size = SIZEOF_ETHER + SIZEOF_IPV6 + sizeof( struct ip6_frag ) + SIZEOF_TCP - MINIMUM_FRAGMENT_SIZE;

    append_ipv6_frag2( ip6h, srcip, dstip, IPPROTO_TCP, fragid, SIZEOF_TCP - MINIMUM_FRAGMENT_SIZE );
    memmove( tcph, (char *) tcph_optioned + MINIMUM_FRAGMENT_SIZE, SIZEOF_TCP - MINIMUM_FRAGMENT_SIZE );

    synfrag_send( ethh, packet_size );
    free( ethh );
}

void do_ipv6_frag_dstopt_tcp( char *interface, char *srcip, char *dstip, char *srcmac, char *dstmac, unsigned short dstport )
{
    struct ip6_hdr *ip6h;
    struct tcphdr *tcph, *tcph_optioned;
    struct ether_header *ethh;
    int packet_size;
    unsigned short fragid = rand();
    unsigned short optlen = fix_up_destination_options_length(
        MINIMUM_PACKET_SIZE - SIZEOF_IPV6 - sizeof( struct ip6_dest ) - sizeof( struct ip6_frag ) - MINIMUM_FRAGMENT_SIZE
    );

    packet_size = SIZEOF_ETHER + SIZEOF_IPV6 + sizeof( struct ip6_dest ) + optlen + sizeof( struct ip6_frag ) + MINIMUM_FRAGMENT_SIZE;

    ethh = (struct ether_header *) malloc_check( BIG_PACKET_SIZE );
    ip6h = (struct ip6_hdr *) ( (char *) ethh + SIZEOF_ETHER );
    tcph = (struct tcphdr *) ( (char *) ip6h + SIZEOF_IPV6 + sizeof( struct ip6_frag ) );
    tcph_optioned = (struct tcphdr *) ( (char *) ip6h + SIZEOF_IPV6 + sizeof( struct ip6_dest ) + optlen + sizeof( struct ip6_frag ) );

    build_ethernet( ethh, srcmac, dstmac, ETHERTYPE_IPV6 );
    append_ipv6_optioned2_frag1( ip6h, srcip, dstip, IPPROTO_TCP, fragid, optlen );
    append_tcp_syn( ip6h, tcph_optioned, SOURCE_PORT, dstport );
    calc_checksum( ip6h, IPPROTO_TCP, SIZEOF_TCP );

    synfrag_send( ethh, packet_size );

    packet_size = SIZEOF_ETHER + SIZEOF_IPV6 + sizeof( struct ip6_frag ) + SIZEOF_TCP - MINIMUM_FRAGMENT_SIZE;

    append_ipv6_frag2_offset( ip6h, srcip, dstip, IPPROTO_TCP, fragid, SIZEOF_TCP - MINIMUM_FRAGMENT_SIZE, optlen );
    memmove( tcph, (char *) tcph_optioned + MINIMUM_FRAGMENT_SIZE, SIZEOF_TCP - MINIMUM_FRAGMENT_SIZE );

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

    r = receive_a_packet( dstip, srcip, dstport, SOURCE_PORT, test_type, &packet_buf, receive_timeout );
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
    char *test;
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
    fprintf( stderr, "--srcip      Source IP address (this hosts)\n" );
    fprintf( stderr, "--dstip      Destination IP address (target)\n" );
    /* Currently not used.
    fprintf( stderr, "--srcport    Source port for TCP tests\n" ); */
    fprintf( stderr, "--dstport    Destination port for TCP tests\n" );
    fprintf( stderr, "--dstmac     Destination MAC address (default gw or target host if on subnet)\n" );
    fprintf( stderr, "--interface  Packet source interface\n" );
    fprintf( stderr, "--test       Type of test to run\n" );
    fprintf( stderr, "--timeout    Reply timeout in seconds (defaults to 10)\n\n" );
    print_test_types();
    fprintf( stderr, "\nAll TCP tests send syn packets, all ICMP/6 test send ping.\n" );
    fprintf( stderr, "All \"frag\" tests send fragments that are below the minimum packet size.\n" );
    fprintf( stderr, "All \"optioned\" tests send fragments that meet the minimum packet size.\n" );
    exit( 2 );
}

void copy_arg_string( char **dst, char *opt )
{
    *dst = malloc( strlen( opt ) );
    memcpy( *dst, opt, strlen( opt) );
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
    unsigned short *srcport,
    unsigned short *dstport,
    char **dstmac,
    char **interface,
    char **test_name,
    long *timeout
) {
    int x = 0;
    int option_index = 0;
    int c, tmpport;
    long tmptime;
    char *possible_match;
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
        {0, 0, 0, 0}
    };

    if ( argc < 2 ) exit_with_usage();

    *srcip = *dstip = *dstmac = *interface = NULL;
    *srcport = *dstport = 0;

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
    if ( !*dstmac ) errx( 1, "Missing dstmac" );
    if ( !*interface ) errx( 1, "Missing interface" );
    if ( !test_type ) {
        fprintf( stderr, "Missing or invalid test type.\n" );
        print_test_types();
        exit( 1 );
    }

    if ( IS_TEST_TCP( test_type ) ) {
        /* Currently not used.
        if ( !*srcport ) errx( 1, "Missing srcport" ); */
        if ( !*dstport ) errx( 1, "Missing dstport" );
    }

    return test_type;
}

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
    unsigned short dstport;
    unsigned short srcport;
    char *packet_buf;
    char *test_name;
    long receive_timeout = DEFAULT_TIMEOUT_SECONDS;

    test_type = parse_args( argc, argv, &srcip, &dstip, &srcport, &dstport, &dstmac, &interface, &test_name, &receive_timeout );
    srand( getpid() );

    printf( "Starting test \"%s\". Opening interface \"%s\".\n\n", test_name, interface );

    if ( ( pcap = pcap_open_live( interface, PCAP_CAPTURE_LEN, 0, 1, pcaperr ) ) == NULL )
        errx( 1, "pcap_open_live failed: %s", pcaperr );

    if ( pcap_datalink( pcap ) != DLT_EN10MB )
        errx( 1, "non-ethernet interface specified." );

    if ( ( srcmac = get_interface_mac( interface ) ) == NULL )
        err( 1, "Failed to get MAC address for %s", interface );

    fork_pcap_listener( dstip, srcip, dstport, SOURCE_PORT, test_type, receive_timeout );

    switch ( test_type ) {
        case TEST_IPV4_TCP:
            do_ipv4_syn( interface, srcip, dstip, srcmac, dstmac, dstport );
            break;
        case TEST_IPV4_FRAG_TCP:
            do_ipv4_frag_tcp( interface, srcip, dstip, srcmac, dstmac, dstport );
            break;
        case TEST_IPV4_FRAG_ICMP:
            do_ipv4_frag_icmp( interface, srcip, dstip, srcmac, dstmac );
            break;
        case TEST_IPV4_DSTOPT_FRAG_TCP:
            do_ipv4_options_tcp_frag( interface, srcip, dstip, srcmac, dstmac, dstport );
            break;
        case TEST_IPV4_DSTOPT_FRAG_ICMP:
            do_ipv4_options_icmp_frag( interface, srcip, dstip, srcmac, dstmac );
            break;

        case TEST_IPV6_TCP:
            do_ipv6_syn( interface, srcip, dstip, srcmac, dstmac, dstport );
            break;
        case TEST_IPV6_FRAG_TCP:
            do_ipv6_frag_tcp( interface, srcip, dstip, srcmac, dstmac, dstport );
            break;
        case TEST_IPV6_FRAG_ICMP6:
            do_ipv6_frag_icmp( interface, srcip, dstip, srcmac, dstmac );
            break;
        case TEST_IPV6_DSTOPT_FRAG_TCP:
            do_ipv6_dstopt_frag_tcp( interface, srcip, dstip, srcmac, dstmac, dstport );
            break;
        case TEST_IPV6_FRAG_DSTOPT_TCP:
            do_ipv6_frag_dstopt_tcp( interface, srcip, dstip, srcmac, dstmac, dstport );
            break;
        case TEST_IPV6_DSTOPT_FRAG_ICMP6:
            do_ipv6_dstopt_frag_icmp( interface, srcip, dstip, srcmac, dstmac );
            break;

        default:
            errx( 1, "Unsupported test type!" );
    }

    printf( "Packet transmission successful, waiting for reply...\n\n" );

    r = harvest_pcap_listener( &packet_buf );
    if ( !r ) {
        fprintf( stderr, "Test failed, no response before time out (%li seconds).\n", receive_timeout );
        return 1;
    }
    if ( check_received_packet( r, packet_buf, test_type ) ) {
        printf( "\nTest was successful.\n" );
        free( packet_buf );
        return 0;
    }
    printf( "\nTest failed.\n" );
    free( packet_buf );
    return 1;
}

