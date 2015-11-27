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

#if !defined (_WIN32)
	#include <sys/socket.h>
	#include <netdb.h>
	#include <arpa/inet.h>	
	#include <netinet/in.h>
	#include <fcntl.h>

	#define IS_SOCKET_ERROR(a)	((a)<0)
	typedef int				socket_t;

#else
	#include <winsock2.h>
	#include <ws2tcpip.h>
	#include <windows.h>

	#define IS_SOCKET_ERROR(a)	((a)==SOCKET_ERROR)

	#define EWOULDBLOCK		WSAEWOULDBLOCK
	#define EINPROGRESS		WSAEINPROGRESS
	#define EINTR			WSAEINTR

	typedef SOCKET			socket_t;

#endif

#ifndef INADDR_NONE
	#define INADDR_NONE 	0xFFFFFFFF
#endif

struct irc_addr_t {
	int length;
	char *value;
};


static int socket_error()
{
#if !defined (_WIN32)
	return errno;
#else
	return WSAGetLastError();
#endif
}


static int socket_create (int domain, int type, socket_t * sock)
{
	*sock = socket (domain, type, 0);
	return IS_SOCKET_ERROR(*sock) ? 1 : 0;
}


static int socket_make_nonblocking (socket_t * sock)
{
#if !defined (_WIN32)
	return fcntl (*sock, F_SETFL, fcntl (*sock, F_GETFL,0 ) | O_NONBLOCK) != 0;
#else
	unsigned long mode = 0;
	return ioctlsocket (*sock, FIONBIO, &mode) == SOCKET_ERROR;
#endif
}


static int socket_close (socket_t * sock)
{
#if !defined (_WIN32)
	close (*sock);
#else
	closesocket (*sock);
#endif

	*sock = -1;
	return 0;
}


static int socket_connect (socket_t * sock, const struct sockaddr *saddr, socklen_t len)
{
	while ( 1 )
	{
	    if ( connect (*sock, saddr, len) < 0 )
	    {
	    	if ( socket_error() == EINTR )
	    		continue;

			if ( socket_error() != EINPROGRESS && socket_error() != EWOULDBLOCK )
				return 1;
		}
		DBG_OK("socket_connect succeded!\n");
		return 0;
	}
	
}

static int socket_recv (socket_t * sock, void * buf, size_t len)
{
	int length;

	while ( (length = recv (*sock, buf, len, 0)) < 0 )
	{
		int err = socket_error();
		
		if ( err != EINTR && err != EAGAIN )
			break;
	}

	return length;
}


static int socket_send (socket_t * sock, const void *buf, size_t len)
{
	int length;

	while ( (length = send (*sock, buf, len, 0)) < 0 )
	{
		int err = socket_error();
		
		if ( err != EINTR && err != EAGAIN )
			break;
	}

	return length;
}

static struct irc_addr_t** resolve_hostname_by_dns (char *hostname, int *numAddrs, int addressFamily) {
	struct hostent *hp;
	int numAddresses = 0;
	*numAddrs = 0;
        
	hp = gethostbyname2(hostname, addressFamily);
	
	if (hp == NULL) {
		return NULL;
	}

	while ( hp -> h_addr_list[numAddresses] != NULL) {
		numAddresses++;
	}
            
	if (numAddresses == 0) {
		return NULL;
	}

	DBG_OK("got %d addresses!", numAddresses);
	size_t addressSize = sizeof(struct irc_addr_t*);
	struct irc_addr_t **addresses = (struct irc_addr_t**) calloc(numAddresses+1, addressSize);

	unsigned int currentAddress = 0;

	for (currentAddress = 0; currentAddress < numAddresses; currentAddress++) {
		char *curAddr = hp->h_addr_list[currentAddress];

		addresses[currentAddress] = (struct irc_addr_t*) malloc(sizeof(struct irc_addr_t));
		addresses[currentAddress]->length = hp->h_length;
		addresses[currentAddress]->value = malloc(sizeof(char) * hp->h_length);
		memcpy(addresses[currentAddress]->value, curAddr, hp->h_length);
	}

	*numAddrs = numAddresses;
	
	return addresses;
} 

static void free_addresses (struct irc_addr_t **addresses) {
	unsigned int currentAddress = 0;
	
	for (currentAddress = 0; addresses[currentAddress] != NULL; currentAddress++) {
		struct irc_addr_t *address = addresses[currentAddress];
		free(address->value);
		free(address);
	}

	free(addresses);
}
