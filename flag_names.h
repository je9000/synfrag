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

/* Require users to free() the returned pointer. */
char *tcp_flags_to_names( unsigned char );
char *ip_flags_to_names( unsigned char );

/* Returned pointer is to a static buffer, don't call free() */
const char *icmp_type_to_name( unsigned char );
const char *icmp_code_to_name( unsigned char, unsigned char );
const char *icmp6_type_to_name( unsigned char );
const char *icmp6_code_to_name( unsigned char, unsigned char );
const char *ip_protocol_to_name( unsigned char );
const char *ether_protocol_to_name( unsigned short );
