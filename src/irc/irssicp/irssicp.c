#include "common.h"

#include <zmq.h>

#define MODULE_NAME "irssicp"

#include "irc.h"
#include "irc-channels.h"
#include "irc-nicklist.h"
#include "irc-servers.h"
#include "irssi-version.h"
#include "levels.h"
#include "modes.h"
#include "net-sendbuffer.h"
#include "network.h"
#include "recode.h"
#include "servers-redirect.h"
#include "settings.h"
#include "signals.h"

#include "fe-text/gui-windows.h"
#include "fe-common/core/printtext.h"

static void *ctx;
static void *pubsock;

static GString *next_line;
static int ignore_next;

static void irssicp_outdata(void *sock, const char *data, ...)
{
    va_list args;
    char *str;

    g_return_if_fail(data != NULL);

    va_start(args, data);

    str = g_strdup_vprintf(data, args);
    zmq_send(sock, str, strlen(str), 0);
    g_free(str);

    va_end(args);
}

static void irssicp_dump_data(void *sock) {
    GString *text = g_string_new(NULL);
    GSList *win_item;
    for (win_item = windows; win_item != NULL; win_item = win_item->next) {
        WINDOW_REC *win_rec = win_item->data;
        TEXT_BUFFER_REC *buf = WINDOW_GUI(win_rec)->view->buffer;
        LINE_REC *line = buf->first_line;
        for (; line != NULL; line = line->next) {
            textbuffer_line2text(line, TRUE, text);
            irssicp_outdata(sock, "%d %d %s\n", line->info.time, win_rec->refnum, text->str);
        }
    }
}

#if 0
static void irssicp_redirect_event(CLIENT_REC *client, const char *command,
				 int count, const char *arg, int remote)
{
	char *str;

	g_return_if_fail(client != NULL);

	str = g_strdup_printf("irssicp %p", client);
	server_redirect_event(client->server, command, count,
			      arg, remote, NULL, "", str, NULL);
	g_free(str);
}

static void handle_client_cmd(CLIENT_REC *client, char *cmd, char *args,
			      const char *data)
{
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
		   irssicp_adress, our own nick or empty. */
		char *params, *origin, *target;

		params = event_get_params(args, 2, &origin, &target);
		if (*target == '\0' ||
		    g_strcasecmp(target, client->irssicp_address) == 0 ||
		    g_strcasecmp(target, client->nick) == 0) {
			irssicp_outdata(client, ":%s PONG %s :%s\n",
				      client->irssicp_address,
                                      client->irssicp_address, origin);
			g_free(params);
			return;
		}
		g_free(params);
	} else if (strcmp(cmd, "PING") == 0) {
		irssicp_redirect_event(client, "ping", 1, NULL, TRUE);
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

	while (g_slist_find(irssicp_clients, client) != NULL) {
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

#endif
static void sig_print_text(WINDOW_REC *win) {
    LINE_REC *l = textbuffer_line_last(WINDOW_GUI(win
                )->view->buffer);
    GString *str = g_string_new(NULL);
    textbuffer_line2text(l, 0, str);
    irssicp_outdata(pubsock, "%d %s", win->refnum, str->str);
    g_string_free(str, 1);
}

static void sig_dump(void *client, const char *data)
{
	g_return_if_fail(client != NULL);
	g_return_if_fail(data != NULL);

	irssicp_outdata(client, data);
}

gboolean zmq_gio_worker(GIOChannel *source, GIOCondition condition, gpointer data)
{
    uint32_t status;
    size_t sizeof_status = sizeof(status);

    if (zmq_getsockopt(data, ZMQ_EVENTS, &status, &sizeof_status)) {
        signal_emit("gui dialog", 2, "warning", "retrieving event status failed; doom");
        return 0;
    }

    signal_emit("gui dialog", 2, "warning", "twerk");

    if ((status & ZMQ_POLLIN) == 0) {
        return 1;
    }

    // do work

    return 1; // keep the callback active
}

static void irssicp_listen_init(void)
{
    next_line = g_string_new(NULL);
    pubsock = zmq_socket(ctx, ZMQ_PUB);
    if (zmq_bind(pubsock, "tcp://*:5556")) {
        signal_emit("gui dialog", 2, "warning", "unbindable");
    }

    int fd;
    size_t sizeof_fd = sizeof(fd);
    if (zmq_getsockopt(pubsock, ZMQ_FD, &fd, &sizeof_fd)) {
        signal_emit("gui dialog", 2, "warning", "fd extraction failed; we're screwed");
    }
    GIOChannel *ichan = g_io_channel_unix_new(fd);
    g_io_add_watch(ichan, G_IO_IN|G_IO_ERR|G_IO_HUP, zmq_gio_worker, pubsock);

    signal_add("gui print text finished", (SIGNAL_FUNC) sig_print_text);
    signal_add("irssicp client dump", (SIGNAL_FUNC) sig_dump);
}

void irc_irssicp_init(void)
{
    ctx = zmq_ctx_new();
    settings_add_str("irssiirssicp", "irssiirssicp_bind", "");
    irssicp_listen_init();
    settings_check();
    module_register("irssicp", "irc");
}

void irc_irssicp_deinit(void)
{
    zmq_term(ctx);
}
