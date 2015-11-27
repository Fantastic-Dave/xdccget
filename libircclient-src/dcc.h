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

#ifndef INCLUDE_IRC_DCC_H
#define INCLUDE_IRC_DCC_H


/*
 * This structure keeps the state of a single DCC connection.
 */
struct irc_dcc_session_s
{
	irc_dcc_session_t	*	next;

	irc_dcc_t		id;
	void		*	ctx;
	socket_t		sock;		/*!< DCC socket */

	int				state;
	int 			ssl;
	SSL 			*ssl_ctx;
	time_t			timeout;

	FILE		*	dccsend_file_fp;
	irc_dcc_size_t	received_file_size;
	irc_dcc_size_t	file_confirm_offset;

	struct sockaddr_in	remote_addr;

	char 			incoming_buf[LIBIRC_DCC_BUFFER_SIZE];
	unsigned int	incoming_offset;

	port_mutex_t	mutex_outbuf;

	irc_dcc_callback_t		cb;
};


#endif /* INCLUDE_IRC_DCC_H */
