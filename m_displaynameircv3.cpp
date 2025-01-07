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
/// $ModDesc: Provides IRCv3 draft/display-name
/// $ModDepends: core 4
/// $ModConfig: <module name="m_displaynameircv3">

#include "inspircd.h"
#include "extensible.h"          // For ExtensionType::USER
#include "modules/cap.h"         // For Cap::Capability
#include "message.h"             // For MessageType, MessageDetails, etc.
#include "clientprotocolevent.h" // For ClientProtocol::MessageTagData

class DisplayNameExtItem final
	: public SimpleExtItem<std::string>
{
public:
	DisplayNameExtItem(Module* mod)
		: SimpleExtItem<std::string>(mod, "displayname", ExtensionType::USER, false)
	{
	}
};

class DisplayNameAPI final
{
private:
	DisplayNameExtItem ext;

public:
	DisplayNameAPI(Module* mod)
		: ext(mod)
	{
	}

	void Set(User* user, const std::string& disp) { ext.Set(user, disp); }
	const std::string* Get(const User* user) const { return ext.Get(user); }
	void Clear(User* user) { ext.Unset(user); }
};

class CommandSetDisplayName final
	: public Command
{
private:
	DisplayNameAPI& api;

public:
	CommandSetDisplayName(Module* mod, DisplayNameAPI& dapi)
		: Command(mod, "SETDISPLAYNAME", 1), api(dapi)
	{
		this->syntax.clear();
		this->syntax.push_back("<display-name>");
	}

	CmdResult Handle(User* user, const Params& parameters) override
	{
		const std::string& newname = parameters[0];

		if (newname.size() > 32)
		{
			user->WriteNotice("ERROR: Display name must not exceed 32 characters.");
			return CmdResult::FAILURE;
		}

		if (!ServerInstance->IsNick(newname))
		{
			user->WriteNotice("ERROR: Invalid characters in display name.");
			return CmdResult::FAILURE;
		}

		api.Set(user, newname);
		user->WriteNotice("Your display name is now: " + newname);

		for (const auto& memb : user->chans)
		{
			Channel* chan = memb->chan;
			for (const auto& [chanuser, membership] : chan->GetUsers())
			{
				if (chanuser == user) continue;
				chanuser->WriteNotice("User " + user->nick + " set their display name to: " + newname);
			}
		}
		return CmdResult::SUCCESS;
	}
};

class ModuleDisplayName final
	: public Module
{
private:
	DisplayNameAPI api;
	Cap::Capability displaycap;
	CommandSetDisplayName cmd;

public:
	ModuleDisplayName()
		: Module(VF_VENDOR, "Provides IRCv3 draft/display-name.")
		, api(this)
		, displaycap(this, "draft/display-name")
		, cmd(this, api)
	{
	}

	void OnUserQuit(User* user, const std::string& reason, const std::string& oper_reason) override
	{
		api.Clear(user);
	}

	void OnUserPostMessage(User* user, const MessageTarget& target, const MessageDetails& details) override
	{
		if (details.type != MessageType::PRIVMSG && details.type != MessageType::NOTICE)
			return;

		const std::string* disp = api.Get(user);
		if (!disp)
			return;

		ClientProtocol::TagMap& mutable_tags = const_cast<ClientProtocol::TagMap&>(details.tags_out);
		const std::string tagname("draft/display-name");

		// According to typedef.h, the constructor takes (provider, value, data).
		ClientProtocol::MessageTagData tagData(
			static_cast<ClientProtocol::MessageTagProvider*>(nullptr), // provider
			*disp,                                                    // value
			nullptr                                                   // optional data
		);

		mutable_tags.insert(std::make_pair(tagname, tagData));
	}
};

MODULE_INIT(ModuleDisplayName)
