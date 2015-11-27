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


#define IS_DEBUG_ENABLED(s)	((s)->options & LIBIRC_OPTION_DEBUG)


#include "portable.c"
#include "sockets.c"

#include "libircclient.h"
#include "session.h"
#include "../helper.h"

#include "utils.c"
#include "errors.c"
#include "colors.c"
#include "ssl.c"
#include "dcc.c"
#include "commands.c"
#include "irc_parser.c"
#include "irc_line_parser.c" 


#ifdef _MSC_VER
	/*
	 * The debugger of MSVC 2005 does not like strdup.
	 * It complains about heap corruption when free is called.
	 * Use _strdup instead.
	 */
	#undef strdup
	#define strdup _strdup
#endif


irc_session_t * irc_create_session (irc_callbacks_t	* callbacks)
{
	irc_session_t * session = calloc (1, sizeof(irc_session_t));

	if ( !session )
		return 0;

	session->sock = -1;

	if ( libirc_mutex_init (&session->mutex_session)
	|| libirc_mutex_init (&session->mutex_dcc) )
	{
		free (session);
		return 0;
	}

	session->dcc_last_id = 1;
	session->dcc_timeout = 60;

	memcpy (&session->callbacks, callbacks, sizeof(irc_callbacks_t));

	if ( !session->callbacks.event_ctcp_req )
		session->callbacks.event_ctcp_req = libirc_event_ctcp_internal;
        
        session->line_parser = create_line_parser();
        line_parser_set_session(session->line_parser, session);
        
        memset(session->incoming_buf, 0, LIBIRC_BUFFER_SIZE);
        memset(session->outgoing_buf, 0, LIBIRC_BUFFER_SIZE);

	return session;
}

static void free_ircsession_strings (irc_session_t * session)
{
	if ( session->realname )
		free (session->realname);

	if ( session->username )
		free (session->username);

	if ( session->nick )
		free (session->nick);

	if ( session->server )
		free (session->server);

	if ( session->server_password )
		free (session->server_password);

	session->realname = 0;
	session->username = 0;
	session->nick = 0;
	session->server = 0;
	session->server_password = 0;
}

void irc_destroy_session (irc_session_t * session)
{
	free_ircsession_strings( session );
	
	if ( session->sock >= 0 )
		socket_close (&session->sock);

#if defined (ENABLE_THREADS)
	libirc_mutex_destroy (&session->mutex_session);
#endif

	while ( session->dcc_sessions )
		libirc_remove_dcc_session (session, session->dcc_sessions, 0);
        
        free_line_parser(session->line_parser);
        
#ifdef ENABLE_SSL
        if (session->ssl)
            SSL_free(session->ssl);
#endif
                
	free (session);
}


static inline bool isConnectionEstablished(const irc_session_t *session) {
	struct sockaddr_storage saddr, laddr;
	socklen_t slen = sizeof(saddr);
	socklen_t llen = sizeof(laddr);

	// Now we have to determine whether the socket is connected
	// or the connect is failed
	return getsockname(session->sock, (struct sockaddr *) &laddr, &llen) >= 0
			|| getpeername(session->sock, (struct sockaddr *) &saddr, &slen) >= 0;
}

static bool hasConnection(const irc_session_t *session) {
	fd_set out_set;
	struct timeval timeout;
	int maxfd = 0;
	timeout.tv_sec = 5;
	timeout.tv_usec = 0;

	FD_ZERO (&out_set);
	libirc_add_to_set(session->sock, &out_set, &maxfd);
	select(maxfd + 1, NULL, &out_set, NULL, &timeout);

	if (FD_ISSET (session->sock, &out_set)) {
		if (isConnectionEstablished(session)) {
			return true;
		}
	}
	else {
		DBG_WARN("got nothing at fd_isset at connect!");
	}

	return false;
}


int init_socket(irc_session_t *session, int addressFamily) {// create the IRC server socket
	if ( socket_create(addressFamily, SOCK_STREAM, &session->sock)
		 || socket_make_nonblocking (&session->sock) )
	{
		session->lasterror = LIBIRC_ERR_SOCKET;
		return 1;
	}

#if defined (ENABLE_SSL)
	// Init the SSL stuff
	if ( session->flags & SESSIONFL_SSL_CONNECTION )
	{
		int rc = ssl_init( session );

		if ( rc != 0 )
		{
			session->lasterror = rc;
			return 1;
		}
	}
#endif

	return 0;
}


static int try_to_connect_ipv4(irc_session_t *session, struct irc_addr_t *address, unsigned short port) {
	struct sockaddr_in saddr;
	char ip4buf[INET_ADDRSTRLEN];
	int ret;
	
	memset( &saddr, 0, sizeof(saddr) );
	saddr.sin_family = AF_INET;
	saddr.sin_port = htons (port);
	
	memcpy (&saddr.sin_addr, address->value, (size_t) address->length);

	inet_ntop(AF_INET, address->value, ip4buf, INET_ADDRSTRLEN);
	logprintf(LOG_INFO, "connecting to ip %s!", ip4buf);

	ret = init_socket(session, AF_INET);

	if (ret != 0) {
		session->lasterror = LIBIRC_ERR_SOCKET;
		return -1;
	}

	ret = socket_connect (&session->sock, (struct sockaddr *) &saddr, sizeof(saddr));

	if (ret != 0) {
		session->lasterror = LIBIRC_ERR_SOCKET;
		return -1;
	}
	
	return 0;
}

#if defined (ENABLE_IPV6)
static int try_to_connect_ipv6(irc_session_t *session, struct irc_addr_t *address, unsigned short port) {
	struct sockaddr_in6 saddr;
	char ip6buf[INET6_ADDRSTRLEN];
	int ret;
	
	memset( &saddr, 0, sizeof(saddr));
	saddr.sin6_family = AF_INET6;
	saddr.sin6_port = htons (port);
	
	memcpy (&saddr.sin6_addr, address->value, (size_t) address->length);

	inet_ntop(AF_INET6, address->value, ip6buf, INET6_ADDRSTRLEN);
	logprintf(LOG_INFO, "connecting to ip %s!", ip6buf);

	ret = init_socket(session, AF_INET6);

	if (ret != 0) {
		session->lasterror = LIBIRC_ERR_SOCKET;
		return -1;
	}

	ret = socket_connect (&session->sock, (struct sockaddr *) &saddr, sizeof(saddr));

	if (ret != 0) {
		session->lasterror = LIBIRC_ERR_SOCKET;
		return -1;
	}
	
	return 0;
}
#endif

int irc_connect_generic(irc_session_t * session,
			const char * server,
			unsigned short port,
			const char * server_password,
			const char * nick,
			const char * username,
			const char * realname,
			int protocol_family) {
	struct irc_addr_t **addresses;
	int numAddresses = 0;

	if ( !server || !nick )
	{
		session->lasterror = LIBIRC_ERR_INVAL;
		return 1;
	}

	if ( session->state != LIBIRC_STATE_INIT )
	{
		session->lasterror = LIBIRC_ERR_STATE;
		return 1;
	}

	// Free the strings if defined; may be the case when the session is reused after the connection fails
	free_ircsession_strings( session );

	if ( server[0] == SSL_PREFIX )
	{
#if defined (ENABLE_SSL)
		server++;
		session->flags |= SESSIONFL_SSL_CONNECTION;
#else
		session->lasterror = LIBIRC_ERR_SSL_NOT_SUPPORTED;
		return 1;
#endif
	}

	if ( username )
		session->username = strdup (username);

	if ( server_password )
		session->server_password = strdup (server_password);

	if ( realname )
		session->realname = strdup (realname);

	session->nick = strdup (nick);
	session->server = strdup (server);
	
	addresses = resolve_hostname_by_dns(session->server, &numAddresses, protocol_family);

	if (addresses == NULL)
	{
		session->lasterror = LIBIRC_ERR_RESOLV;
		return 1;
	}

	int selectedAddress = rand_range(0, numAddresses-1);

    // and connect to the IRC server
    for (; addresses[selectedAddress] != NULL; selectedAddress++)
    {
		struct irc_addr_t *currentAddress = addresses[selectedAddress];
		int ret = -1;

		if (protocol_family == AF_INET)
			ret = try_to_connect_ipv4(session, currentAddress, port);
#if defined (ENABLE_IPV6)
		else if(protocol_family == AF_INET6)
			ret = try_to_connect_ipv6(session, currentAddress, port);		
#endif

		if (ret == -1) {
			goto err_out;
		}

		if (hasConnection(session)) {
			break;
		}
		else {
			socket_close(&session->sock);
		}
    }

	if (addresses[selectedAddress] == NULL) {
		session->lasterror = LIBIRC_ERR_CONNECT;
		goto err_out;
	}

	logprintf(LOG_INFO, "Connection successful!");

	free_addresses(addresses);

    session->state = LIBIRC_STATE_CONNECTING;
	if(protocol_family == AF_INET6)
		session->flags |= SESSIONFL_USES_IPV6;

	return 0;

err_out:
	free_addresses(addresses);
	return 1;
}

int irc_connect (irc_session_t * session,
			const char * server,
			unsigned short port,
			const char * server_password,
			const char * nick,
			const char * username,
			const char * realname)
{
	return irc_connect_generic(session, server, port, server_password, nick, username, realname, AF_INET);
}

#if defined (ENABLE_IPV6)
int irc_connect6 (irc_session_t * session,
			const char * server, 
			unsigned short port,
			const char * server_password,
			const char * nick,
			const char * username,
			const char * realname)
{
	return irc_connect_generic(session, server, port, server_password, nick, username, realname, AF_INET6);
}
#endif


int irc_is_connected (irc_session_t * session)
{
	return (session->state == LIBIRC_STATE_CONNECTED 
	|| session->state == LIBIRC_STATE_CONNECTING) ? 1 : 0;
}


int irc_run (irc_session_t * session)
{
	if ( session->state != LIBIRC_STATE_CONNECTING )
	{
		session->lasterror = LIBIRC_ERR_STATE;
		return 1;
	}

	while ( irc_is_connected(session) )
	{
		struct timeval tv;
		fd_set in_set, out_set;
		int maxfd = 0;

		tv.tv_usec = 250000;
		tv.tv_sec = 0;

		// Init sets
		FD_ZERO (&in_set);
		FD_ZERO (&out_set);

		irc_add_select_descriptors (session, &in_set, &out_set, &maxfd);

		if ( select (maxfd + 1, &in_set, &out_set, 0, &tv) < 0 )
		{
			if ( socket_error() == EINTR )
				continue;

			session->lasterror = LIBIRC_ERR_TERMINATED;
			return 1;
		}

		if ( irc_process_select_descriptors (session, &in_set, &out_set) )
			return 1;
	}

	return 0;
}


int irc_add_select_descriptors (irc_session_t * session, fd_set *in_set, fd_set *out_set, int * maxfd)
{
	if ( session->sock < 0 
	|| session->state == LIBIRC_STATE_INIT
	|| session->state == LIBIRC_STATE_DISCONNECTED )
	{
		session->lasterror = LIBIRC_ERR_STATE;
		return 1;
	}

	libirc_mutex_lock (&session->mutex_session);

	switch (session->state)
	{
	case LIBIRC_STATE_CONNECTING:
		// While connection, only out_set descriptor should be set
		libirc_add_to_set (session->sock, out_set, maxfd);
		break;

	case LIBIRC_STATE_CONNECTED:
		// Add input descriptor if there is space in input buffer
		if ( session->incoming_offset < (sizeof (session->incoming_buf) - 1) 
		|| (session->flags & SESSIONFL_SSL_WRITE_WANTS_READ) != 0 )
			libirc_add_to_set (session->sock, in_set, maxfd);

		// Add output descriptor if there is something in output buffer
		if ( libirc_findcrlf (session->outgoing_buf, session->outgoing_offset) > 0
		|| (session->flags & SESSIONFL_SSL_READ_WANTS_WRITE) != 0 )
			libirc_add_to_set (session->sock, out_set, maxfd);

		break;
	}

	libirc_mutex_unlock (&session->mutex_session);

	libirc_dcc_add_descriptors (session, in_set, out_set, maxfd);
	return 0;
}

static void libirc_process_incoming_data(irc_session_t * session, size_t process_length) {    
//    logprintf(LOG_INFO, irc_line);

    irc_parser_execute(session->line_parser, session->incoming_buf, process_length);
    free_parser_result(session->line_parser);
}

int irc_process_select_descriptors (irc_session_t * session, fd_set *in_set, fd_set *out_set)
{
	char buf[256], hname[256];

	if ( session->sock < 0 
	|| session->state == LIBIRC_STATE_INIT
	|| session->state == LIBIRC_STATE_DISCONNECTED )
	{
		session->lasterror = LIBIRC_ERR_STATE;
		return 1;
	}

	session->lasterror = 0;
	libirc_dcc_process_descriptors (session, in_set, out_set);

	// Handle "connection succeed" / "connection failed"
	if ( session->state == LIBIRC_STATE_CONNECTING 
	&& FD_ISSET (session->sock, out_set) )
	{
		// Now we have to determine whether the socket is connected 
		// or the connect is failed
		struct sockaddr_storage saddr, laddr;
		socklen_t slen = sizeof(saddr);
		socklen_t llen = sizeof(laddr);

		if ( getsockname (session->sock, (struct sockaddr*)&laddr, &llen) < 0
		|| getpeername (session->sock, (struct sockaddr*)&saddr, &slen) < 0 )
		{
			// connection failed
			DBG_WARN("connection failed");
			session->state = LIBIRC_STATE_DISCONNECTED;
			session->lasterror = LIBIRC_ERR_CONNECT;
			return 1;
		}

		if (saddr.ss_family == AF_INET)
			memcpy (&session->local_addr.v4, &((struct sockaddr_in *)&laddr)->sin_addr, sizeof(struct in_addr));
#if defined (ENABLE_IPV6)
		else
			memcpy (&session->local_addr.v6, &((struct sockaddr_in6 *)&laddr)->sin6_addr, sizeof(struct in6_addr));
#endif

#if defined (ENABLE_DEBUG)
		if ( IS_DEBUG_ENABLED(session) ) {
			if (saddr.ss_family == AF_INET)
				fprintf (stderr, "[DEBUG] Detected local address: %s\n", inet_ntoa(session->local_addr.v4));
#if defined (ENABLE_IPV6)
			else
				fprintf (stderr, "[DEBUG] Detected local address: %s\n", inet_ntoa(session->local_addr.v6));
#endif
		}
#endif

		session->state = LIBIRC_STATE_CONNECTED;

		// Get the hostname
    	if ( gethostname (hname, sizeof(hname)) < 0 )
    		strcpy (hname, "unknown");

		// Prepare the data, which should be sent to the server
		if ( session->server_password )
		{
			snprintf (buf, sizeof(buf), "PASS %s", session->server_password);
			irc_send_raw (session, buf);
		}

		snprintf (buf, sizeof(buf), "NICK %s", session->nick);
		irc_send_raw (session, buf);

		/*
		 * RFC 1459 states that "hostname and servername are normally 
         * ignored by the IRC server when the USER command comes from 
         * a directly connected client (for security reasons)", therefore 
         * we don't need them.
         */
		snprintf (buf, sizeof(buf), "USER %s %s unknown :%s", 
				session->nick, session->nick,
				session->realname ? session->realname : "realname");
		irc_send_raw (session, buf);

		return 0;
	}

	if ( session->state != LIBIRC_STATE_CONNECTED ) {
		DBG_WARN("session->state != LIBIRC_STATE_CONNECTED");
                session->state = LIBIRC_STATE_DISCONNECTED;
		session->lasterror = LIBIRC_ERR_STATE;
		return 1;
	}

	// Hey, we've got something to read!
	if ( FD_ISSET (session->sock, in_set) )
	{
		int offset, length = session_socket_read( session );

		if ( length < 0 )
		{
			if ( session->lasterror == 0 )
				session->lasterror = (length == 0 ? LIBIRC_ERR_CLOSED : LIBIRC_ERR_TERMINATED);
			
			session->state = LIBIRC_STATE_DISCONNECTED;
			DBG_WARN("session->state = LIBIRC_STATE_DISCONNECTED");
			return 1;
		}

		session->incoming_offset += length;

		// process the incoming data
		while ( (offset = libirc_findcrlf (session->incoming_buf, session->incoming_offset)) > 0 )
		{
#if defined (ENABLE_DEBUG)
			if ( IS_DEBUG_ENABLED(session) )
				libirc_dump_data ("RECV", session->incoming_buf, offset);
#endif
			// parse the string
			libirc_process_incoming_data (session, offset);

			if ( session->incoming_offset - offset > 0 )
				memmove (session->incoming_buf, session->incoming_buf + offset, session->incoming_offset - offset);

			session->incoming_offset -= offset;
		}
	}

	// We can write a stored buffer
	if ( FD_ISSET (session->sock, out_set) )
	{
		int length;

		// Because outgoing_buf could be changed asynchronously, we should lock any change
		libirc_mutex_lock (&session->mutex_session);
		length = session_socket_write( session );

		if ( length < 0 )
		{
			if ( session->lasterror == 0 )
				session->lasterror = (length == 0 ? LIBIRC_ERR_CLOSED : LIBIRC_ERR_TERMINATED);

			session->state = LIBIRC_STATE_DISCONNECTED;
			DBG_WARN("session->state = LIBIRC_STATE_DISCONNECTED");
			libirc_mutex_unlock (&session->mutex_session);
			return 1;
		}

#if defined (ENABLE_DEBUG)
		if ( IS_DEBUG_ENABLED(session) )
			libirc_dump_data ("SEND", session->outgoing_buf, length);
#endif

		if ( length > 0 && session->outgoing_offset - length > 0 )
			memmove (session->outgoing_buf, session->outgoing_buf + length, session->outgoing_offset - length);

		session->outgoing_offset -= length;
		libirc_mutex_unlock (&session->mutex_session);
	}

	return 0;
}


int irc_send_raw (irc_session_t * session, const char * format, ...)
{
	char buf[1024];
	va_list va_alist;

	if ( session->state != LIBIRC_STATE_CONNECTED )
	{
		session->lasterror = LIBIRC_ERR_STATE;
		return 1;
	}

	va_start (va_alist, format);
	vsnprintf (buf, sizeof(buf), format, va_alist);
	va_end (va_alist);

	libirc_mutex_lock (&session->mutex_session);

	if ( (strlen(buf) + 2) >= (sizeof(session->outgoing_buf) - session->outgoing_offset) )
	{
		libirc_mutex_unlock (&session->mutex_session);
		session->lasterror = LIBIRC_ERR_NOMEM;
		return 1;
	}

	strcpy (session->outgoing_buf + session->outgoing_offset, buf);
	session->outgoing_offset += strlen (buf);
	session->outgoing_buf[session->outgoing_offset++] = 0x0D;
	session->outgoing_buf[session->outgoing_offset++] = 0x0A;

	libirc_mutex_unlock (&session->mutex_session);
	return 0;
}


int irc_cmd_quit (irc_session_t * session, const char * reason)
{
	return irc_send_raw (session, "QUIT :%s", reason ? reason : "quit");
}


int irc_cmd_join (irc_session_t * session, const char * channel, const char * key)
{
	if ( !channel )
	{
		session->lasterror = LIBIRC_ERR_STATE;
		return 1;
	}

	if ( key )
		return irc_send_raw (session, "JOIN %s :%s", channel, key);
	else
		return irc_send_raw (session, "JOIN %s", channel);
}


int irc_cmd_part (irc_session_t * session, const char * channel)
{
	if ( !channel )
	{
		session->lasterror = LIBIRC_ERR_STATE;
		return 1;
	}

	return irc_send_raw (session, "PART %s", channel);
}


int irc_cmd_topic (irc_session_t * session, const char * channel, const char * topic)
{
	if ( !channel )
	{
		session->lasterror = LIBIRC_ERR_STATE;
		return 1;
	}

	if ( topic )
		return irc_send_raw (session, "TOPIC %s :%s", channel, topic);
	else
		return irc_send_raw (session, "TOPIC %s", channel);
}

int irc_cmd_names (irc_session_t * session, const char * channel)
{
	if ( !channel )
	{
		session->lasterror = LIBIRC_ERR_STATE;
		return 1;
	}

	return irc_send_raw (session, "NAMES %s", channel);
}


int irc_cmd_list (irc_session_t * session, const char * channel)
{
	if ( channel )
		return irc_send_raw (session, "LIST %s", channel);
	else
		return irc_send_raw (session, "LIST");
}


int irc_cmd_invite (irc_session_t * session, const char * nick, const char * channel)
{
	if ( !channel || !nick )
	{
		session->lasterror = LIBIRC_ERR_STATE;
		return 1;
	}

	return irc_send_raw (session, "INVITE %s %s", nick, channel);
}


int irc_cmd_kick (irc_session_t * session, const char * nick, const char * channel, const char * comment)
{
	if ( !channel || !nick )
	{
		session->lasterror = LIBIRC_ERR_STATE;
		return 1;
	}

	if ( comment )
		return irc_send_raw (session, "KICK %s %s :%s", channel, nick, comment);
	else
		return irc_send_raw (session, "KICK %s %s", channel, nick);
}


int irc_cmd_msg (irc_session_t * session, const char * nch, const char * text)
{
	if ( !nch || !text )
	{
		session->lasterror = LIBIRC_ERR_STATE;
		return 1;
	}

	return irc_send_raw (session, "PRIVMSG %s :%s", nch, text);
}


int irc_cmd_notice (irc_session_t * session, const char * nch, const char * text)
{
	if ( !nch || !text )
	{
		session->lasterror = LIBIRC_ERR_STATE;
		return 1;
	}

	return irc_send_raw (session, "NOTICE %s :%s", nch, text);
}

void irc_target_get_nick (const char * target, char *nick, size_t size)
{
	char *p = strstr (target, "!");
	unsigned int len;

	if ( p )
		len = p - target;
	else
		len = strlen (target);

	if ( len > size-1 )
		len = size - 1;

	memcpy (nick, target, len);
	nick[len] = '\0';
}


void irc_target_get_host (const char * target, char *host, size_t size)
{
	unsigned int len;
	const char *p = strstr (target, "!");

	if ( !p )
		p = target;

	len = strlen (p);

	if ( len > size-1 )
		len = size - 1;

	memcpy (host, p, len);
	host[len] = '\0';
}


int irc_cmd_ctcp_request (irc_session_t * session, const char * nick, const char * reply)
{
	if ( !nick || !reply )
	{
		session->lasterror = LIBIRC_ERR_STATE;
		return 1;
	}

	return irc_send_raw (session, "PRIVMSG %s :\x01%s\x01", nick, reply);
}


int irc_cmd_ctcp_reply (irc_session_t * session, const char * nick, const char * reply)
{
	if ( !nick || !reply )
	{
		session->lasterror = LIBIRC_ERR_STATE;
		return 1;
	}

	return irc_send_raw (session, "NOTICE %s :\x01%s\x01", nick, reply);
}


void irc_get_version (unsigned int * high, unsigned int * low)
{
	*high = LIBIRC_VERSION_HIGH;
    *low = LIBIRC_VERSION_LOW;
}


void irc_set_ctx (irc_session_t * session, void * ctx)
{
	session->ctx = ctx;
}


void * irc_get_ctx (irc_session_t * session)
{
	return session->ctx;
}


void irc_disconnect (irc_session_t * session)
{
	if ( session->sock >= 0 )
		socket_close (&session->sock);

	session->sock = -1;
	session->state = LIBIRC_STATE_INIT;
}


int irc_cmd_me (irc_session_t * session, const char * nch, const char * text)
{
	if ( !nch || !text )
	{
		session->lasterror = LIBIRC_ERR_STATE;
		return 1;
	}

	return irc_send_raw (session, "PRIVMSG %s :\x01" "ACTION %s\x01", nch, text);
}

#ifdef ENABLE_SSL
void irc_set_cert_verify_callback(irc_session_t * session, int (*verify_callback)(int, X509_STORE_CTX *)) {
    session->verify_callback = verify_callback;
}

const char* irc_get_ssl_ciphers_used(irc_session_t *session) {
    const char *ciphers_used = "None";
    
    if (session->ssl != NULL) {
        ciphers_used = SSL_get_cipher_name(session->ssl);
    }
    
    return ciphers_used;
}
#endif

void irc_option_set (irc_session_t * session, unsigned int option)
{
	session->options |= option;
}


void irc_option_reset (irc_session_t * session, unsigned int option)
{
	session->options &= ~option;
}


int irc_cmd_channel_mode (irc_session_t * session, const char * channel, const char * mode)
{
	if ( !channel )
	{
		session->lasterror = LIBIRC_ERR_INVAL;
		return 1;
	}

	if ( mode )
		return irc_send_raw (session, "MODE %s %s", channel, mode);
	else
		return irc_send_raw (session, "MODE %s", channel);
}


int irc_cmd_user_mode (irc_session_t * session, const char * mode)
{
	if ( mode )
		return irc_send_raw (session, "MODE %s %s", session->nick, mode);
	else
		return irc_send_raw (session, "MODE %s", session->nick);
}


int irc_cmd_nick (irc_session_t * session, const char * newnick)
{
	if ( !newnick )
	{
		session->lasterror = LIBIRC_ERR_INVAL;
		return 1;
	}

	return irc_send_raw (session, "NICK %s", newnick);
}

int irc_cmd_whois (irc_session_t * session, const char * nick)
{
	if ( !nick )
	{
		session->lasterror = LIBIRC_ERR_INVAL;
		return 1;
	}

	return irc_send_raw (session, "WHOIS %s %s", nick, nick);
}
