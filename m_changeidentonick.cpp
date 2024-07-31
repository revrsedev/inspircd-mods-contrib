/*
 * InspIRCd -- Internet Relay Chat Daemon
 *
 *   Copyright (C) 2024 Jean Chevronnet <mike.chevronnet@gmail.com>
 *
 * This file contains a third party module for InspIRCd.  You can
 * redistribute it and/or modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation, version 2.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/// $ModAuthor: Jean Chevronnet (reverse) <mike.chevronnet@gmail.com>
/// $ModDesc: Sets the user's ident to match their nickname on connect.
/// $ModDepends: core 4

#include "inspircd.h"

class CommandSetNickIdent : public Command
{
public:
	CommandSetNickIdent(Module* Creator)
		: Command(Creator, "SETNICKIDENT", 1)
	{
		access_needed = CmdAccess::OPERATOR;
		syntax = { "<username>" };
	}

	CmdResult Handle(User* user, const Params& parameters) override
	{
		const size_t max_ident_length = 12;
		std::string ident = parameters[0];

		if (ident.size() > max_ident_length)
		{
			ident.resize(max_ident_length);  // Truncate ident to 12 characters
			user->WriteNotice("*** SETNICKIDENT: Username truncated to 12 characters");
		}

		for (char c : ident)
		{
			if (!isalnum(c) && c != '-' && c != '_')
			{
				user->WriteNotice("*** SETNICKIDENT: Invalid characters in username");
				return CmdResult::FAILURE;
			}
		}

		user->ChangeDisplayedUser(ident);
		ServerInstance->SNO.WriteGlobalSno('a', INSP_FORMAT("{} used SETNICKIDENT to change their username to '{}'", user->nick, ident));

		return CmdResult::SUCCESS;
	}
};

class ModuleSetNickIdent : public Module
{
private:
	CommandSetNickIdent cmd;

public:
	ModuleSetNickIdent()
		: Module(VF_VENDOR, "Sets the user's ident to match their nickname on connect.")
		, cmd(this)
	{
	}

	void OnUserConnect(LocalUser* user) override
	{
		if (IS_LOCAL(user))
		{
			std::string newident = user->nick;
			const size_t max_ident_length = 12;

			if (newident.size() > max_ident_length)
				newident.resize(max_ident_length);  // Truncate to maximum length

			user->ChangeDisplayedUser(newident);
		}
	}

	~ModuleSetNickIdent() override
	{
		// Clean up resources if any (standard practice even if not necessary)
	}
};

MODULE_INIT(ModuleSetNickIdent)
