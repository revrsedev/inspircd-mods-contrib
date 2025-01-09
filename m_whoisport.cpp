/*
 * InspIRCd -- Internet Relay Chat Daemon
 *
 *   Copyright (C) 2024 reverse
 *
 * This file contains a third-party module for InspIRCd. You can
 * redistribute it and/or modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation, version 2.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.

 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

/// $ModAuthor: reverse <mike.chevronnet@gmail.com>
/// $ModDesc: Adds the port of the user to the WHOIS response for operators only.
/// $ModDepends: core 4

#include "inspircd.h"
#include "modules/whois.h"

class ModuleWhoisPort final
	: public Module
	, public Whois::EventListener
{
public:
	ModuleWhoisPort()
		: Module(VF_OPTCOMMON, "Adds the port number of the user to the WHOIS response for operators only.")
		, Whois::EventListener(this)
	{
	}

	void OnWhois(Whois::Context& whois) override
	{
		User* source = whois.GetSource();
		User* target = whois.GetTarget();

		// Only show port information if the requesting user (source) is an IRC operator with privs.
		if (!user->HasPrivPermission("users/auspex"))
            {
                user->WriteNotice("You do not have permission to use this command.");
                return CmdResult::FAILURE;
            }
		// Check if the target user is local or remote.
		LocalUser* luser = IS_LOCAL(target);
		if (!luser)
			return;

		// Get the port the user is connected on.
		int port = luser->server_sa.port();

		// Send the port information in the WHOIS response, but only for operators.
		whois.SendLine(RPL_WHOISSPECIAL, "*", "is using port " + ConvToStr(port));
	}
};

MODULE_INIT(ModuleWhoisPort)

