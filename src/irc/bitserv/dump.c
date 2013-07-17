/*
 dump.c : bitserv plugin - output all information about irc session

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
#include "network.h"
#include "net-sendbuffer.h"
#include "settings.h"
#include "irssi-version.h"
#include "recode.h"

#include "irc-servers.h"
#include "irc-channels.h"
#include "irc-nicklist.h"
#include "modes.h"

#include "fe-common/core/printtext.h"
#include "src/fe-text/gui-windows.h"

void bitserv_outdata(CLIENT_REC *client, const char *data, ...)
{
	va_list args;
	char *str;

	g_return_if_fail(client != NULL);
	g_return_if_fail(data != NULL);

	va_start(args, data);

	str = g_strdup_vprintf(data, args);
	net_sendbuffer_send(client->handle, str, strlen(str));
	g_free(str);

	va_end(args);
}

void bitserv_outdata_all(IRC_SERVER_REC *server, const char *data, ...)
{
	va_list args;
	GSList *tmp;
	char *str;
	int len;

	g_return_if_fail(server != NULL);
	g_return_if_fail(data != NULL);

	va_start(args, data);

	str = g_strdup_vprintf(data, args);
	len = strlen(str);
	for (tmp = bitserv_clients; tmp != NULL; tmp = tmp->next) {
		CLIENT_REC *rec = tmp->data;

		if (rec->connected && rec->server == server)
			net_sendbuffer_send(rec->handle, str, len);
	}
	g_free(str);

	va_end(args);
}

void bitserv_outserver(CLIENT_REC *client, const char *data, ...)
{
	va_list args;
	char *str;

	g_return_if_fail(client != NULL);
	g_return_if_fail(data != NULL);

	va_start(args, data);

	str = g_strdup_vprintf(data, args);
	bitserv_outdata(client, ":%s!%s@bitserv %s\n", client->nick,
		      settings_get_str("user_name"), str);
	g_free(str);

	va_end(args);
}

void bitserv_outserver_all(IRC_SERVER_REC *server, const char *data, ...)
{
	va_list args;
	GSList *tmp;
	char *str;

	g_return_if_fail(server != NULL);
	g_return_if_fail(data != NULL);

	va_start(args, data);

	str = g_strdup_vprintf(data, args);
	for (tmp = bitserv_clients; tmp != NULL; tmp = tmp->next) {
		CLIENT_REC *rec = tmp->data;

		if (rec->connected && rec->server == server) {
			bitserv_outdata(rec, ":%s!%s@bitserv %s\n", rec->nick,
				      settings_get_str("user_name"), str);
		}
	}
	g_free(str);

	va_end(args);
}

void bitserv_outserver_all_except(CLIENT_REC *client, const char *data, ...)
{
	va_list args;
	GSList *tmp;
	char *str;

	g_return_if_fail(client != NULL);
	g_return_if_fail(data != NULL);

	va_start(args, data);

	str = g_strdup_vprintf(data, args);
	for (tmp = bitserv_clients; tmp != NULL; tmp = tmp->next) {
		CLIENT_REC *rec = tmp->data;

		if (rec->connected && rec != client &&
		    rec->server == client->server) {
			bitserv_outdata(rec, ":%s!%s@bitserv %s\n", rec->nick,
				      settings_get_str("user_name"), str);
		}
	}
	g_free(str);

	va_end(args);
}

static void create_names_start(GString *str, IRC_CHANNEL_REC *channel,
			       CLIENT_REC *client)
{
	g_string_printf(str, ":%s 353 %s %c %s :",
			 client->bitserv_address, client->nick,
			 channel_mode_is_set(channel, 'p') ? '*' :
			 channel_mode_is_set(channel, 's') ? '@' : '=',
			 channel->name);
}

static void dump_join(IRC_CHANNEL_REC *channel, CLIENT_REC *client)
{
	GSList *tmp, *nicks;
	GString *str;
	int first;
	char *recoded;

	bitserv_outserver(client, "JOIN %s", channel->name);

	str = g_string_new(NULL);
	create_names_start(str, channel, client);

	first = TRUE;
	nicks = nicklist_getnicks(CHANNEL(channel));
	for (tmp = nicks; tmp != NULL; tmp = tmp->next) {
		NICK_REC *nick = tmp->data;

		if (str->len >= 500) {
			g_string_append_c(str, '\n');
			bitserv_outdata(client, "%s", str->str);
			create_names_start(str, channel, client);
			first = TRUE;
		}

		if (first)
			first = FALSE;
		else
			g_string_append_c(str, ' ');

		if (nick->prefixes[0])
                        g_string_append_c(str, nick->prefixes[0]);
		g_string_append(str, nick->nick);
	}
	g_slist_free(nicks);

	g_string_append_c(str, '\n');
	bitserv_outdata(client, "%s", str->str);
	g_string_free(str, TRUE);

	bitserv_outdata(client, ":%s 366 %s %s :End of /NAMES list.\n",
		      client->bitserv_address, client->nick, channel->name);
	if (channel->topic != NULL) {
		/* this is needed because the topic may be encoded into other charsets internaly */
		recoded = recode_out(SERVER(client->server), channel->topic, channel->name);
		bitserv_outdata(client, ":%s 332 %s %s :%s\n",
			      client->bitserv_address, client->nick,
			      channel->name, recoded);
		g_free(recoded);
		if (channel->topic_time > 0)
			bitserv_outdata(client, ":%s 333 %s %s %s %d\n",
			              client->bitserv_address, client->nick,
			              channel->name, channel->topic_by, channel->topic_time);
	}
}

void bitserv_client_reset_nick(CLIENT_REC *client)
{
	if (client->server == NULL ||
	    strcmp(client->nick, client->server->nick) == 0)
		return;

	bitserv_outdata(client, ":%s!bitserv NICK :%s\n",
		      client->nick, client->server->nick);

	g_free(client->nick);
	client->nick = g_strdup(client->server->nick);
}

static void bitserv_dump_data_005(gpointer key, gpointer value, gpointer context)
{
	if (*(char *)value != '\0')
		g_string_append_printf(context, "%s=%s ", (char *)key, (char *)value);
	else
		g_string_append_printf(context, "%s ", (char *)key);
}

void bitserv_dump_data(CLIENT_REC *client)
{
	GString *isupport_out, *paramstr;
	char **paramlist, **tmp;
	int count;

    GString *text = g_string_new(NULL);
    GSList *win_item;
    for (win_item = windows; win_item != NULL; win_item = win_item->next) {
        WINDOW_REC *win_rec = win_item->data;
        TEXT_BUFFER_REC *buf = WINDOW_GUI(win_rec)->view->buffer;
        LINE_REC *line = buf->first_line;
        for (; line != NULL; line = line->next) {
            textbuffer_line2text(line, TRUE, text);
            bitserv_outdata(client, "%d %d %s\n", line->info.time, win_rec->refnum, text->str);
        }
    }
	bitserv_client_reset_nick(client);


	/* welcome info */
	bitserv_outdata(client, ":%s 001 %s :Welcome to the Internet Relay Network %s!%s@bitserv\n", client->bitserv_address, client->nick, client->nick, settings_get_str("user_name"));
	bitserv_outdata(client, ":%s 002 %s :Your host is irssi-bitserv, running version %s\n", client->bitserv_address, client->nick, PACKAGE_VERSION);
	bitserv_outdata(client, ":%s 003 %s :This server was created ...\n", client->bitserv_address, client->nick);
	if (client->server == NULL || !client->server->emode_known)
		bitserv_outdata(client, ":%s 004 %s %s %s oirw abiklmnopqstv\n", client->bitserv_address, client->nick, client->bitserv_address, PACKAGE_VERSION);
	else
		bitserv_outdata(client, ":%s 004 %s %s %s oirw abeIiklmnopqstv\n", client->bitserv_address, client->nick, client->bitserv_address, PACKAGE_VERSION);

	if (client->server != NULL && client->server->isupport_sent) {
		isupport_out = g_string_new(NULL);
		g_hash_table_foreach(client->server->isupport, bitserv_dump_data_005, isupport_out);
		if (isupport_out->len > 0)
			g_string_truncate(isupport_out, isupport_out->len-1);

		bitserv_outdata(client, ":%s 005 %s ", client->bitserv_address, client->nick);

		paramstr = g_string_new(NULL);
		paramlist = g_strsplit(isupport_out->str, " ", -1);
		count = 0;
		tmp = paramlist;

		for (;; tmp++) {
			if (*tmp != NULL) {
				g_string_append_printf(paramstr, "%s ", *tmp);
				if (++count < 15)
					continue;
			}

			count = 0;
			if (paramstr->len > 0)
				g_string_truncate(paramstr, paramstr->len-1);
			g_string_append_printf(paramstr, " :are supported by this server\n");
			bitserv_outdata(client, "%s", paramstr->str);
			g_string_truncate(paramstr, 0);
			g_string_printf(paramstr, ":%s 005 %s ", client->bitserv_address, client->nick);

			if (*tmp == NULL || tmp[1] == NULL)
				break;
		}

		g_string_free(isupport_out, TRUE);
		g_string_free(paramstr, TRUE);
		g_strfreev(paramlist);
	}

	bitserv_outdata(client, ":%s 251 %s :There are 0 users and 0 invisible on 1 servers\n", client->bitserv_address, client->nick);
	bitserv_outdata(client, ":%s 255 %s :I have 0 clients, 0 services and 0 servers\n", client->bitserv_address, client->nick);
	bitserv_outdata(client, ":%s 422 %s :MOTD File is missing\n", client->bitserv_address, client->nick);

	/* user mode / away status */
	if (client->server != NULL) {
		if (client->server->usermode != NULL) {
			bitserv_outserver(client, "MODE %s :+%s",
					client->server->nick,
					client->server->usermode);
		}
		if (client->server->usermode_away) {
			bitserv_outdata(client, ":%s 306 %s :You have been marked as being away\n",
				      client->bitserv_address, client->nick);
		}

		/* Send channel joins */
		g_slist_foreach(client->server->channels, (GFunc) dump_join, client);
	}
}
