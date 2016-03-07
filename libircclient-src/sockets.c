/* 
 * Copyright (C) 2004-2012 George Yunaev gyunaev@ulduzsoft.com
 *
 * This library is free software; you can redistribute it and/or modify it 
 * under the terms of the GNU Lesser General Public License as published by 
 * the Free Software Foundation; either version 3 of the License, or (at your 
 * option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT 
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or 
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public 
 * License for more details.
 */

/*
 * The sockets interface was moved out to simplify going OpenSSL integration.
 */

#include "../helper.h"


#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>	
#include <netinet/in.h>
#include <fcntl.h>

#define IS_SOCKET_ERROR(a)	((a)<0)
typedef int socket_t;



#ifndef INADDR_NONE
	#define INADDR_NONE 	0xFFFFFFFF
#endif

struct irc_addr_t {
	int family;
	int socktype;
	int protocol;
	socklen_t length;
	struct sockaddr *addr;
};
static int socket_error() {

    return errno;

}

static int socket_create(int domain, int type, socket_t * sock) {
    *sock = socket(domain, type, 0);
    return IS_SOCKET_ERROR(*sock) ? 1 : 0;
}

static int socket_make_nonblocking(socket_t * sock) {

    return fcntl(*sock, F_SETFL, fcntl(*sock, F_GETFL, 0) | O_NONBLOCK) != 0;

}

static int socket_close(socket_t * sock) {
    close(*sock);


    *sock = -1;
    return 0;
}

static int socket_connect(socket_t * sock, const struct sockaddr *saddr, socklen_t len) {
    while (1) {
        if (connect(*sock, saddr, len) < 0) {
            if (socket_error() == EINTR)
                continue;

            if (socket_error() != EINPROGRESS && socket_error() != EWOULDBLOCK)
                return 1;
        }
        DBG_OK("socket_connect succeded!\n");
        return 0;
    }

}

static int socket_recv(socket_t * sock, void * buf, size_t len) {
    int length;

    while ((length = recv(*sock, buf, len, 0)) < 0) {
        int err = socket_error();

        if (err != EINTR && err != EAGAIN)
            break;
    }

    return length;
}

static int socket_send(socket_t * sock, const void *buf, size_t len) {
    int length;

    while ((length = send(*sock, buf, len, 0)) < 0) {
        int err = socket_error();

        if (err != EINTR && err != EAGAIN)
            break;
    }

    return length;
}

static inline void init_irc_addr(struct irc_addr_t *t, struct addrinfo *addr)
{
    t->length = addr->ai_addrlen;
    t->family = addr->ai_family;
    t->protocol = addr->ai_protocol;
    t->socktype = addr->ai_socktype;

    if (addr->ai_family == AF_INET) {
        t->addr = malloc(sizeof (struct sockaddr_in));
    }
    else if (addr->ai_family == AF_INET6) {
        t->addr = malloc(sizeof (struct sockaddr_in6));
    }

    memcpy(t->addr, addr->ai_addr, addr->ai_addrlen);
}

static struct irc_addr_t** resolve_hostname_by_dns(const char *hostname, int *numAddrs, int addressFamily)
{
    struct addrinfo hints;
    struct addrinfo *result;
    int ret;
    int numAddresses = 0;
    *numAddrs = 0;

    memset(&hints, 0, sizeof (struct addrinfo));
    hints.ai_family = addressFamily; /* AF_UNSPEC for Allow IPv4 or IPv6 */
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = 0;
    hints.ai_protocol = IPPROTO_TCP;

    ret = getaddrinfo(hostname, NULL, &hints, &result);

    if (ret != 0) {
        return NULL;
    }

    for (struct addrinfo *rp = result; rp != NULL; rp = rp->ai_next) {
        numAddresses++;
    }

    if (numAddresses == 0) {
        return NULL;
    }

    DBG_OK("got %d addresses!", numAddresses);
    size_t addressSize = sizeof (struct irc_addr_t*);
    struct irc_addr_t **addresses = (struct irc_addr_t**) calloc(numAddresses + 1, addressSize);

    unsigned int currentAddress = 0;

    for (struct addrinfo *addr = result; addr != NULL; addr = addr->ai_next, currentAddress++) {
        addresses[currentAddress] = (struct irc_addr_t*) malloc(sizeof (struct irc_addr_t));
        init_irc_addr(addresses[currentAddress], addr);
    }

    *numAddrs = numAddresses;
    freeaddrinfo(result);

    return addresses;
}

static void free_addresses(struct irc_addr_t **addresses) {
    unsigned int currentAddress = 0;

    for (currentAddress = 0; addresses[currentAddress] != NULL; currentAddress++) {
        struct irc_addr_t *address = addresses[currentAddress];
        free(address->addr);
        free(address);
    }

    free(addresses);
}
