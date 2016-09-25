#include <strings.h>

#include "commands.h"
#include "params.h"
#include "irc_line_parser.h"
#include "strings_utils.h"

static void irc_ping_command(irc_session_t *session, const char *command, irc_parser_result_t *result);
static void irc_nick_command(irc_session_t *session, const char *command, irc_parser_result_t *result);
static void irc_quit_command(irc_session_t *session, const char *command, irc_parser_result_t *result);
static void irc_join_command(irc_session_t *session, const char *command, irc_parser_result_t *result);
static void irc_part_command(irc_session_t *session, const char *command, irc_parser_result_t *result);
static void irc_mode_command(irc_session_t *session, const char *command, irc_parser_result_t *result);
static void irc_topic_command(irc_session_t *session, const char *command, irc_parser_result_t *result);
static void irc_kick_command(irc_session_t *session, const char *command, irc_parser_result_t *result);
static void irc_privmsg_command(irc_session_t *session, const char *command, irc_parser_result_t *result);
static void irc_notice_command(irc_session_t *session, const char *command, irc_parser_result_t *result);
static void irc_invite_command(irc_session_t *session, const char *command, irc_parser_result_t *result);
static void irc_kill_command(irc_session_t *session, const char *command, irc_parser_result_t *result);
static void irc_unknown_command(irc_session_t *session, const char *command, irc_parser_result_t *result);

static irc_command_t const commands[] = {
    {"PING", irc_ping_command},
    {"NICK", irc_nick_command},
    {"QUIT", irc_quit_command},
    {"JOIN", irc_join_command},
    {"PART", irc_part_command},
    {"MODE", irc_mode_command},
    {"TOPIC", irc_topic_command},
    {"KICK", irc_kick_command},
    {"PRIVMSG", irc_privmsg_command},
    {"NOTICE", irc_notice_command},
    {"INVITE", irc_invite_command},
    {"KILL", irc_kill_command}
};

static irc_command_t const unknownCommand = {"UNKNOWN", irc_unknown_command};

const irc_command_t* get_command(const char *commandString, size_t n) {
    size_t i = 0;
    
    if (n == 0) {
        return &unknownCommand;
    }
    
    size_t commandLength = sizeof(commands) / sizeof(irc_command_t);
    
    for (; i < commandLength; i++) {
        const irc_command_t *irc_command = &commands[i];
        if ( strn_equals(commandString, irc_command->name, n) ) {
            return irc_command;
        }
    }
    
    return &unknownCommand;
}

static void irc_ping_command(irc_session_t *session, const char *command, irc_parser_result_t *result) {
    if (result->params[0] == NULL) {
        return;
    }
    
    irc_send_raw(session, "PONG %s", result->params[0]);
}

static void irc_nick_command (irc_session_t *session, const char *command, irc_parser_result_t *result) {
    
   if ( strn_equals (result->nick, session->nick, strlen(session->nick)) && result->num_params > 0 )
   {
           free (session->nick);
           session->nick = strdup (result->params[0]);
   }

   if ( session->callbacks.event_nick )
           (*session->callbacks.event_nick) (session, command, result);
}

static void irc_quit_command(irc_session_t *session, const char *command, irc_parser_result_t *result) {
    if ( session->callbacks.event_quit )
        (*session->callbacks.event_quit) (session, command, result);
}

static void irc_join_command(irc_session_t *session, const char *command, irc_parser_result_t *result) {
    if ( session->callbacks.event_join )
        (*session->callbacks.event_join) (session, command, result);
}

static void irc_part_command(irc_session_t *session, const char *command, irc_parser_result_t *result) {
    if ( session->callbacks.event_part )
        (*session->callbacks.event_part) (session, command, result);
}

static void irc_mode_command(irc_session_t *session, const char *command, irc_parser_result_t *result) {
    if ( result->num_params > 0 && strn_equals (result->params[0], session->nick, strlen(session->nick)) )
    {
        result->params[0] = result->params[1];
        result->num_params = 1;

        if ( session->callbacks.event_umode )
            (*session->callbacks.event_umode) (session, command, result);
    }
    else
    {
        if ( session->callbacks.event_mode )
            (*session->callbacks.event_mode) (session, command, result);
    }
}

static void irc_topic_command(irc_session_t *session, const char *command, irc_parser_result_t *result) {
    if ( session->callbacks.event_topic )
        (*session->callbacks.event_topic) (session, command, result);
}

static void irc_kick_command(irc_session_t *session, const char *command, irc_parser_result_t *result) {
    if ( session->callbacks.event_kick )
        (*session->callbacks.event_kick) (session, command, result);
}

static inline bool is_dcc_request(const char *string) {
    return strncasecmp(string, "DCC ", 4) == 0;
}

static inline bool is_action_message(const char *string) {
    return strncasecmp(string, "ACTION ", 7) == 0;
}

static void handle_ctcp_request(irc_session_t *session, irc_parser_result_t *result) {
    char ctcp_buf[LIBIRC_BUFFER_SIZE];
    char **params = result->params;
    size_t msglen = strlen(result->params[1]);

    msglen -= 2;
    if (msglen > sizeof (ctcp_buf) - 1)
        msglen = sizeof (ctcp_buf) - 1;

    memcpy(ctcp_buf, params[1] + 1, msglen);
    ctcp_buf[msglen] = '\0';
    DBG_OK("ctcp req recvd! %s", ctcp_buf);

    if (is_dcc_request(ctcp_buf)) {
        libirc_dcc_request(session, result, ctcp_buf);
    }
    else if (is_action_message(ctcp_buf) && session->callbacks.event_ctcp_action) {
        // this removes "ACTION" in front of the message
        char *buf = calloc(strlen(ctcp_buf)+1, sizeof(char));
        memcpy(buf, ctcp_buf+7, strlen(ctcp_buf)-7);
        params[1] = buf; 
        result->num_params = 2;

        (*session->callbacks.event_ctcp_action) (session, "ACTION", result);
    }
    else {
        char *buf = calloc(strlen(ctcp_buf)+1, sizeof(char));
        memcpy(buf, ctcp_buf, strlen(ctcp_buf));
        params[0] = buf;
        result->num_params = 1;

        if (session->callbacks.event_ctcp_req)
            (*session->callbacks.event_ctcp_req) (session, "CTCP", result);
    }
}

static inline bool is_ctcp_request (const char *string) {
    return string[0] == 0x01 && string[strlen(string)-1] == 0x01;
}

static inline bool is_private_message(const char *string, const char *nick) {
    return strncasecmp(string, nick, strlen(nick)) == 0;
}

static void irc_privmsg_command(irc_session_t *session, const char *command, irc_parser_result_t *result) {
    if (result->num_params <= 1) return;

    char **params = result->params;

    if (is_ctcp_request(params[1])) {
        handle_ctcp_request(session, result);
    }
    else if (is_private_message(params[0], session->nick)) {
        if (session->callbacks.event_privmsg)
            (*session->callbacks.event_privmsg) (session, "PRIVMSG", result);
    }
    else {
        if (session->callbacks.event_channel)
            (*session->callbacks.event_channel) (session, "CHANNEL", result);
    }
}

static void irc_notice_command(irc_session_t *session, const char *command, irc_parser_result_t *result) {
    char **params = result->params;
    size_t msglen = strlen (params[1]);
    unsigned int i = 0;

    if ( result->num_params > 1 && is_ctcp_request(params[1]) && session->callbacks.event_ctcp_rep)
    {
        char *ctcp_buf = calloc(LIBIRC_BUFFER_SIZE, sizeof(char));

        msglen -= 2;
        if (msglen > (sizeof(ctcp_buf) - 1))
            msglen = sizeof(ctcp_buf) - 1;

        memcpy (ctcp_buf, params[1] + 1, msglen);
        ctcp_buf[msglen] = '\0';

        for (i = 0; i < result->num_params; i++) {
            FREE(result->params[i]);
        }
        
        params[0] = ctcp_buf;
        result->num_params  = 1;
        
        (*session->callbacks.event_ctcp_rep) (session, "CTCP", result);
    }
    else if (is_private_message(params[0], session->nick))
    {
        if ( session->callbacks.event_notice )
            (*session->callbacks.event_notice) (session, command, result);
    } else {
        if ( session->callbacks.event_channel_notice )
            (*session->callbacks.event_channel_notice) (session, command, result);
    }
}

static void irc_invite_command (irc_session_t *session, const char *command, irc_parser_result_t *result) {
    if ( session->callbacks.event_invite )
        (*session->callbacks.event_invite) (session, command, result);
}
static void irc_kill_command(irc_session_t *session, const char *command, irc_parser_result_t *result) {
    /* ignore this event - not all servers generate this */
}

static void irc_unknown_command(irc_session_t *session, const char *command, irc_parser_result_t *result) {
    /*
    * The "unknown" event is triggered upon receipt of any number of 
    * unclassifiable miscellaneous messages, which aren't handled by 
    * the library.
    */

    if ( session->callbacks.event_unknown )
        (*session->callbacks.event_unknown) (session, command, result);
}
