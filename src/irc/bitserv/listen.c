/*
 listen.c : irc bitserv

    Copyright (C) 1999-2001 Timo Sirainen

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#include "module.h"
#include "signals.h"
#include "net-sendbuffer.h"
#include "servers-redirect.h"
#include "levels.h"
#include "settings.h"

#include "irc.h"
#include "irc-channels.h"

#include "fe-common/core/printtext.h" /* FIXME: evil. need to do fe-bitserv */

GSList *bitserv_listens;
GSList *bitserv_clients;

static GString *next_line;
static int ignore_next;

static void remove_client(CLIENT_REC *rec)
{
	g_return_if_fail(rec != NULL);

	bitserv_clients = g_slist_remove(bitserv_clients, rec);
	rec->listen->clients = g_slist_remove(rec->listen->clients, rec);

	signal_emit("bitserv client disconnected", 1, rec);
	printtext(NULL, NULL, MSGLEVEL_CLIENTNOTICE,
		  "Proxy: Client disconnected from %s", rec->host);

	g_free(rec->bitserv_address);
	net_sendbuffer_destroy(rec->handle, TRUE);
	g_source_remove(rec->recv_tag);
	g_free_not_null(rec->nick);
	g_free_not_null(rec->host);
	g_free(rec);
}

static void bitserv_redirect_event(CLIENT_REC *client, const char *command,
				 int count, const char *arg, int remote)
{
	char *str;

	g_return_if_fail(client != NULL);

	str = g_strdup_printf("bitserv %p", client);
	server_redirect_event(client->server, command, count,
			      arg, remote, NULL, "", str, NULL);
	g_free(str);
}

static void grab_who(CLIENT_REC *client, const char *channel)
{
	GString *arg;
	char **list, **tmp;
	int count;

	/* /WHO a,b,c may respond with either one "a,b,c End of WHO" message
	   or three different "a End of WHO", "b End of WHO", .. messages */
	list = g_strsplit(channel, ",", -1);

	arg = g_string_new(channel);

	for (tmp = list, count = 0; *tmp != NULL; tmp++, count++) {
		if (strcmp(*tmp, "0") == 0) {
			/* /who 0 displays everyone */
			**tmp = '*';
		}

		g_string_append_c(arg, ' ');
		g_string_append(arg, *tmp);
	}

	bitserv_redirect_event(client, "who",
			     client->server->one_endofwho ? 1 : count,
			     arg->str, -1);

	g_strfreev(list);
	g_string_free(arg, TRUE);
}

static void handle_client_connect_cmd(CLIENT_REC *client,
				      const char *cmd, const char *args)
{
	const char *password;

	password = settings_get_str("irssibitserv_password");

	if (password != NULL && strcmp(cmd, "PASS") == 0) {
		if (strcmp(password, args) == 0)
			client->pass_sent = TRUE;
		else {
			/* wrong password! */
			remove_client(client);
            return;
		}
    }

    if (*password != '\0' && !client->pass_sent) {
        /* client didn't send us PASS, kill it */
        remove_client(client);
    } else {
        client->connected = TRUE;
        bitserv_dump_data(client);
    }
}

static void handle_client_cmd(CLIENT_REC *client, char *cmd, char *args,
			      const char *data)
{
	GSList *tmp;
	if (!client->connected) {
		handle_client_connect_cmd(client, cmd, args);
		return;
	}

	if (strcmp(cmd, "QUIT") == 0) {
		remove_client(client);
		return;
	}

	if (strcmp(cmd, "PING") == 0) {
		/* Reply to PING, if the target parameter is either
		   bitserv_adress, our own nick or empty. */
		char *params, *origin, *target;

		params = event_get_params(args, 2, &origin, &target);
		if (*target == '\0' ||
		    g_strcasecmp(target, client->bitserv_address) == 0 ||
		    g_strcasecmp(target, client->nick) == 0) {
			bitserv_outdata(client, ":%s PONG %s :%s\n",
				      client->bitserv_address,
                                      client->bitserv_address, origin);
			g_free(params);
			return;
		}
		g_free(params);
	}

	if (strcmp(cmd, "PROXY") == 0) {
		if (g_ascii_strcasecmp(args, "CTCP ON") == 0) {
                        /* client wants all ctcps */
			client->want_ctcp = 1;
	                for (tmp = bitserv_clients; tmp != NULL; tmp = tmp->next) {
				CLIENT_REC *rec = tmp->data;
				if ((g_strcasecmp(client->listen->ircnet,rec->listen->ircnet) == 0) &&
					/* kludgy way to check if the clients aren't the same */
					(client->recv_tag != rec->recv_tag)) {
						if (rec->want_ctcp == 1)
							bitserv_outdata(rec, ":%s NOTICE %s :Another client is now receiving CTCPs sent to %s\n",
			                                      rec->bitserv_address, rec->nick, rec->listen->ircnet);
						rec->want_ctcp = 0;
		                }
						                                      
			}
			bitserv_outdata(client, ":%s NOTICE %s :You're now receiving CTCPs sent to %s\n",
				      client->bitserv_address, client->nick,client->listen->ircnet);
		} else if (g_ascii_strcasecmp(args, "CTCP OFF") == 0) {
                        /* client wants bitserv to handle all ctcps */
			client->want_ctcp = 0;
			bitserv_outdata(client, ":%s NOTICE %s :Proxy is now handling itself CTCPs sent to %s\n",
				      client->bitserv_address, client->nick, client->listen->ircnet);
		} else {
			signal_emit("bitserv client command", 3, client, args, data);
		}
		return;
	}

	if (client->server == NULL || !client->server->connected) {
		bitserv_outdata(client, ":%s NOTICE %s :Not connected to server\n",
			      client->bitserv_address, client->nick);
                return;
	}

        /* check if the command could be redirected */
	if (strcmp(cmd, "WHO") == 0)
		grab_who(client, args);
	else if (strcmp(cmd, "WHOWAS") == 0)
		bitserv_redirect_event(client, "whowas", 1, args, -1);
	else if (strcmp(cmd, "WHOIS") == 0) {
		char *p;

		/* convert dots to spaces */
		for (p = args; *p != '\0'; p++)
			if (*p == ',') *p = ' ';

		bitserv_redirect_event(client, "whois", 1, args, TRUE);
	} else if (strcmp(cmd, "ISON") == 0)
		bitserv_redirect_event(client, "ison", 1, args, -1);
	else if (strcmp(cmd, "USERHOST") == 0)
		bitserv_redirect_event(client, "userhost", 1, args, -1);
	else if (strcmp(cmd, "MODE") == 0) {
		/* convert dots to spaces */
		char *slist, *str, mode, *p;
		int argc;

		p = strchr(args, ' ');
		if (p != NULL) *p++ = '\0';
		mode = p == NULL ? '\0' : *p;

		slist = g_strdup(args);
		argc = 1;
		for (p = slist; *p != '\0'; p++) {
			if (*p == ',') {
				*p = ' ';
				argc++;
			}
		}

		/* get channel mode / bans / exception / invite list */
		str = g_strdup_printf("%s %s", args, slist);
		switch (mode) {
		case '\0':
			bitserv_redirect_event(client, "mode channel", argc, str, -1);
			break;
		case 'b':
			bitserv_redirect_event(client, "mode b", argc, str, -1);
			break;
		case 'e':
			bitserv_redirect_event(client, "mode e", argc, str, -1);
			break;
		case 'I':
			bitserv_redirect_event(client, "mode I", argc, str, -1);
			break;
		}
		g_free(str);
		g_free(slist);
	} else if (strcmp(cmd, "PRIVMSG") == 0) {
		/* send the message to other clients as well */
		char *params, *target, *msg;

		params = event_get_params(args, 2 | PARAM_FLAG_GETREST,
					  &target, &msg);
		bitserv_outserver_all_except(client, "PRIVMSG %s", args);

		ignore_next = TRUE;
		if (*msg != '\001' || msg[strlen(msg)-1] != '\001') {
	        	signal_emit(ischannel(*target) ?
				    "message own_public" : "message own_private", 4,
				    client->server, msg, target, target);
		} else if (strncmp(msg+1, "ACTION ", 7) == 0) {
			/* action */
                        msg[strlen(msg)-1] = '\0';
			signal_emit("message irc own_action", 3,
				    client->server, msg+8, target);
		} else {
                        /* CTCP */
			char *p;

			msg[strlen(msg)-1] = '\0';
			p = strchr(msg, ' ');
                        if (p != NULL) *p++ = '\0'; else p = "";

			signal_emit("message irc own_ctcp", 4,
				    client->server, msg+1, p, target);
		}
		ignore_next = FALSE;
		g_free(params);
	} else if (strcmp(cmd, "PING") == 0) {
		bitserv_redirect_event(client, "ping", 1, NULL, TRUE);
	} else if (strcmp(cmd, "AWAY") == 0) {
		/* set the away reason */
		if (args != NULL) {
			g_free(client->server->away_reason);
			client->server->away_reason = g_strdup(args);
		}
	}

	irc_send_cmd(client->server, data);
}

static void sig_listen_client(CLIENT_REC *client)
{
	char *str, *cmd, *args;
	int ret;

	g_return_if_fail(client != NULL);

	while (g_slist_find(bitserv_clients, client) != NULL) {
		ret = net_sendbuffer_receive_line(client->handle, &str, 1);
		if (ret == -1) {
			/* connection lost */
			remove_client(client);
			break;
		}

		if (ret == 0)
			break;

		cmd = g_strdup(str);
		args = strchr(cmd, ' ');
		if (args != NULL) *args++ = '\0'; else args = "";
		if (*args == ':') args++;
		ascii_strup(cmd);

		handle_client_cmd(client, cmd, args, str);

		g_free(cmd);
	}
}

static void sig_listen(LISTEN_REC *listen)
{
	CLIENT_REC *rec;
	IPADDR ip;
	NET_SENDBUF_REC *sendbuf;
        GIOChannel *handle;
	char host[MAX_IP_LEN];
	int port;

	g_return_if_fail(listen != NULL);

	/* accept connection */
	handle = net_accept(listen->handle, &ip, &port);
	if (handle == NULL)
		return;
	net_ip2host(&ip, host);
	sendbuf = net_sendbuffer_create(handle, 0);
	rec = g_new0(CLIENT_REC, 1);
	rec->listen = listen;
	rec->handle = sendbuf;
        rec->host = g_strdup(host);
	if (strcmp(listen->ircnet, "*") == 0) {
		rec->bitserv_address = g_strdup("irc.bitserv");
		rec->server = servers == NULL ? NULL : IRC_SERVER(servers->data);
	} else {
		rec->bitserv_address = g_strdup_printf("%s.bitserv", listen->ircnet);
		rec->server = servers == NULL ? NULL :
			IRC_SERVER(server_find_chatnet(listen->ircnet));
	}
	rec->recv_tag = g_input_add(handle, G_INPUT_READ,
			       (GInputFunction) sig_listen_client, rec);

	bitserv_clients = g_slist_prepend(bitserv_clients, rec);
	rec->listen->clients = g_slist_prepend(rec->listen->clients, rec);

        signal_emit("bitserv client connected", 1, rec);
	printtext(NULL, NULL, MSGLEVEL_CLIENTNOTICE,
		  "Proxy: Client connected from %s", rec->host);
}

static LISTEN_REC *find_listen(const char *ircnet, int port)
{
	GSList *tmp;

	for (tmp = bitserv_listens; tmp != NULL; tmp = tmp->next) {
		LISTEN_REC *rec = tmp->data;

		if (rec->port == port &&
		    g_strcasecmp(rec->ircnet, ircnet) == 0)
			return rec;
	}

	return NULL;
}

static void add_listen(const char *ircnet, int port)
{
	LISTEN_REC *rec;
	IPADDR ip4, ip6, *my_ip;

	if (port <= 0 || *ircnet == '\0')
		return;

	/* bind to specific host/ip? */
	my_ip = NULL;
	if (*settings_get_str("irssibitserv_bind") != '\0') {
		if (net_gethostbyname(settings_get_str("irssibitserv_bind"),
				      &ip4, &ip6) != 0) {
			printtext(NULL, NULL, MSGLEVEL_CLIENTERROR,
				  "Proxy: can not resolve '%s' - aborting",
				  settings_get_str("irssibitserv_bind"));
			return;
		}

		my_ip = ip6.family == 0 ? &ip4 : ip4.family == 0 ||
			settings_get_bool("resolve_prefer_ipv6") ? &ip6 : &ip4;
	}

	rec = g_new0(LISTEN_REC, 1);
	rec->ircnet = g_strdup(ircnet);
	rec->port = port;

	rec->handle = net_listen(my_ip, &rec->port);

	if (rec->handle == NULL) {
		printtext(NULL, NULL, MSGLEVEL_CLIENTERROR,
			  "Proxy: Listen in port %d failed: %s",
			  rec->port, g_strerror(errno));
		g_free(rec->ircnet);
                g_free(rec);
		return;
	}

	rec->tag = g_input_add(rec->handle, G_INPUT_READ,
			       (GInputFunction) sig_listen, rec);

        bitserv_listens = g_slist_append(bitserv_listens, rec);
}

static void remove_listen(LISTEN_REC *rec)
{
	bitserv_listens = g_slist_remove(bitserv_listens, rec);

	while (rec->clients != NULL)
		remove_client(rec->clients->data);

	net_disconnect(rec->handle);
	g_source_remove(rec->tag);
	g_free(rec->ircnet);
	g_free(rec);
}

static void read_settings(void)
{
	LISTEN_REC *rec;
	GSList *remove_listens;
	char **ports, **tmp, *ircnet, *port;
	int portnum;

	remove_listens = g_slist_copy(bitserv_listens);

	ports = g_strsplit(settings_get_str("irssibitserv_ports"), " ", -1);
	for (tmp = ports; *tmp != NULL; tmp++) {
		ircnet = *tmp;
		port = strchr(ircnet, '=');
		if (port == NULL)
			continue;

		*port++ = '\0';
		portnum = atoi(port);
		if (portnum <=  0)
			continue;

		rec = find_listen(ircnet, portnum);
		if (rec == NULL)
			add_listen(ircnet, portnum);
		else
			remove_listens = g_slist_remove(remove_listens, rec);
	}
	g_strfreev(ports);

	while (remove_listens != NULL) {
                remove_listen(remove_listens->data);
		remove_listens = g_slist_remove(remove_listens, remove_listens->data);
	}
}

static void sig_print_text(WINDOW_REC *win) {
    GSList *tmp;
    for (tmp = bitserv_clients; tmp != NULL; tmp = tmp->next) {
        CLIENT_REC *rec = tmp->data;
//        bitserv_outdata(rec, "%d %s\n", win->refnum, text);
    }
}

static void sig_dump(CLIENT_REC *client, const char *data)
{
	g_return_if_fail(client != NULL);
	g_return_if_fail(data != NULL);

	bitserv_outdata(client, data);
}

void bitserv_listen_init(void)
{
	next_line = g_string_new(NULL);

	bitserv_clients = NULL;
	bitserv_listens = NULL;
	read_settings();

	signal_add("setup changed", (SIGNAL_FUNC) read_settings);
	
    signal_add("gui print text finished", (SIGNAL_FUNC) sig_print_text);
	signal_add("bitserv client dump", (SIGNAL_FUNC) sig_dump);
}

void bitserv_listen_deinit(void)
{
	while (bitserv_listens != NULL)
		remove_listen(bitserv_listens->data);
	g_string_free(next_line, TRUE);

	signal_remove("setup changed", (SIGNAL_FUNC) read_settings);

    signal_remove("gui print text finished", (SIGNAL_FUNC) sig_print_text);
	signal_remove("bitserv client dump", (SIGNAL_FUNC) sig_dump);
}
