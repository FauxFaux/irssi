#include "common.h"

#define MODULE_NAME "bitserv"

#include "network.h"
#include "irc.h"
#include "irc-servers.h"

#include "bitserv.h"

extern GSList *bitserv_listens;
extern GSList *bitserv_clients;

void bitserv_listen_init(void);
void bitserv_listen_deinit(void);

void bitserv_settings_init(void);

void bitserv_dump_data(CLIENT_REC *client);
void bitserv_client_reset_nick(CLIENT_REC *client);

void bitserv_outdata(CLIENT_REC *client, const char *data, ...);
void bitserv_outdata_all(IRC_SERVER_REC *server, const char *data, ...);
void bitserv_outserver(CLIENT_REC *client, const char *data, ...);
void bitserv_outserver_all(IRC_SERVER_REC *server, const char *data, ...);
void bitserv_outserver_all_except(CLIENT_REC *client, const char *data, ...);
