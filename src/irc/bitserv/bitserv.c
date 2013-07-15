/*
 bitserv.c : irc bitserv

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
#include "settings.h"
#include "levels.h"

void irc_bitserv_init(void)
{
	settings_add_str("irssibitserv", "irssibitserv_ports", "");
	settings_add_str("irssibitserv", "irssibitserv_password", "");
	settings_add_str("irssibitserv", "irssibitserv_bind", "");

	if (*settings_get_str("irssibitserv_password") == '\0') {
		/* no password - bad idea! */
		signal_emit("gui dialog", 2, "warning",
			    "Warning!! Password not specified, everyone can "
			    "use this bitserv! Use /set irssibitserv_password "
			    "<password> to set it");
	}
	if (*settings_get_str("irssibitserv_ports") == '\0') {
		signal_emit("gui dialog", 2, "warning",
			    "No bitserv ports specified. Use /SET "
			    "irssibitserv_ports <ircnet>=<port> <ircnet2>=<port2> "
			    "... to set them.");
	}

	bitserv_listen_init();
	settings_check();
        module_register("bitserv", "irc");
}

void irc_bitserv_deinit(void)
{
	bitserv_listen_deinit();
}
