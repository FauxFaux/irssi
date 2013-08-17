#include "common.h"

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

static GSList *irssicp_listens;

static GString *next_line;
static int ignore_next;


typedef struct {
	int port;
	char *ircnet;

	int tag;
	GIOChannel *handle;

	GSList *clients;
} LISTEN_REC;

typedef struct {
	char *nick, *host;
	NET_SENDBUF_REC *handle;
	int recv_tag;
	char *irssicp_address;
	LISTEN_REC *listen;
	IRC_SERVER_REC *server;
	unsigned int pass_sent:1;
	unsigned int user_sent:1;
	unsigned int connected:1;
	unsigned int want_ctcp:1;
} CLIENT_REC;

static CLIENT_REC connected_client = {};

static void irssicp_outdata(CLIENT_REC *client, const char *data, ...)
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

static void irssicp_dump_data(CLIENT_REC *client) {
    GString *text = g_string_new(NULL);
    GSList *win_item;
    for (win_item = windows; win_item != NULL; win_item = win_item->next) {
        WINDOW_REC *win_rec = win_item->data;
        TEXT_BUFFER_REC *buf = WINDOW_GUI(win_rec)->view->buffer;
        LINE_REC *line = buf->first_line;
        for (; line != NULL; line = line->next) {
            textbuffer_line2text(line, TRUE, text);
            irssicp_outdata(client, "%d %d %s\n", line->info.time, win_rec->refnum, text->str);
        }
    }
}

static void remove_client(CLIENT_REC *rec)
{
	g_return_if_fail(rec != NULL);

	irssicp_clients = g_slist_remove(irssicp_clients, rec);
	rec->listen->clients = g_slist_remove(rec->listen->clients, rec);

	signal_emit("irssicp client disconnected", 1, rec);
	printtext(NULL, NULL, MSGLEVEL_CLIENTNOTICE,
		  "Proxy: Client disconnected from %s", rec->host);

	g_free(rec->irssicp_address);
	net_sendbuffer_destroy(rec->handle, TRUE);
	g_source_remove(rec->recv_tag);
	g_free_not_null(rec->nick);
	g_free_not_null(rec->host);
	g_free(rec);
}

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

static void handle_client_connect_cmd(CLIENT_REC *client,
				      const char *cmd, const char *args)
{
	const char *password;

	password = settings_get_str("irssiirssicp_password");

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
        irssicp_dump_data(client);
    }
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
		rec->irssicp_address = g_strdup("irc.irssicp");
		rec->server = servers == NULL ? NULL : IRC_SERVER(servers->data);
	} else {
		rec->irssicp_address = g_strdup_printf("%s.irssicp", listen->ircnet);
		rec->server = servers == NULL ? NULL :
			IRC_SERVER(server_find_chatnet(listen->ircnet));
	}
	rec->recv_tag = g_input_add(handle, G_INPUT_READ,
			       (GInputFunction) sig_listen_client, rec);

	irssicp_clients = g_slist_prepend(irssicp_clients, rec);
	rec->listen->clients = g_slist_prepend(rec->listen->clients, rec);

        signal_emit("irssicp client connected", 1, rec);
	printtext(NULL, NULL, MSGLEVEL_CLIENTNOTICE,
		  "Proxy: Client connected from %s", rec->host);
}

static LISTEN_REC *find_listen(const char *ircnet, int port)
{
	GSList *tmp;

	for (tmp = irssicp_listens; tmp != NULL; tmp = tmp->next) {
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
	if (*settings_get_str("irssiirssicp_bind") != '\0') {
		if (net_gethostbyname(settings_get_str("irssiirssicp_bind"),
				      &ip4, &ip6) != 0) {
			printtext(NULL, NULL, MSGLEVEL_CLIENTERROR,
				  "Proxy: can not resolve '%s' - aborting",
				  settings_get_str("irssiirssicp_bind"));
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

        irssicp_listens = g_slist_append(irssicp_listens, rec);
}

static void remove_listen(LISTEN_REC *rec)
{
	irssicp_listens = g_slist_remove(irssicp_listens, rec);

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

	remove_listens = g_slist_copy(irssicp_listens);

	ports = g_strsplit(settings_get_str("irssiirssicp_ports"), " ", -1);
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
//        irssicp_outdata(current_, "%d %s\n", win->refnum, text);
}

static void sig_dump(CLIENT_REC *client, const char *data)
{
	g_return_if_fail(client != NULL);
	g_return_if_fail(data != NULL);

	irssicp_outdata(client, data);
}

static void irssicp_listen_init(void)
{
	next_line = g_string_new(NULL);

	memset(&connected_client, 0, sizeof(connected_client));
	irssicp_listens = NULL;
	read_settings();

	signal_add("setup changed", (SIGNAL_FUNC) read_settings);
	
    signal_add("gui print text finished", (SIGNAL_FUNC) sig_print_text);
	signal_add("irssicp client dump", (SIGNAL_FUNC) sig_dump);
}

static void irssicp_listen_deinit(void)
{
	while (irssicp_listens != NULL)
		remove_listen(irssicp_listens->data);
	g_string_free(next_line, TRUE);

	signal_remove("setup changed", (SIGNAL_FUNC) read_settings);

    signal_remove("gui print text finished", (SIGNAL_FUNC) sig_print_text);
	signal_remove("irssicp client dump", (SIGNAL_FUNC) sig_dump);
}

void irc_irssicp_init(void)
{
	settings_add_str("irssiirssicp", "irssiirssicp_ports", "");
	settings_add_str("irssiirssicp", "irssiirssicp_password", "");
	settings_add_str("irssiirssicp", "irssiirssicp_bind", "");

	if (*settings_get_str("irssiirssicp_password") == '\0') {
		/* no password - bad idea! */
		signal_emit("gui dialog", 2, "warning",
			    "Warning!! Password not specified, everyone can "
			    "use this irssicp! Use /set irssiirssicp_password "
			    "<password> to set it");
	}
	if (*settings_get_str("irssiirssicp_ports") == '\0') {
		signal_emit("gui dialog", 2, "warning",
			    "No irssicp ports specified. Use /SET "
			    "irssiirssicp_ports <ircnet>=<port> <ircnet2>=<port2> "
			    "... to set them.");
	}

	irssicp_listen_init();
	settings_check();
        module_register("irssicp", "irc");
}

void irc_irssicp_deinit(void)
{
	irssicp_listen_deinit();
}
