/*
 * InspIRCd -- Internet Relay Chat Daemon
 *
 *   Copyright (C) 2015-2016 reverse Chevronnet  mike.chevronnet@gmail.com
 *
 * This file is part of InspIRCd.  InspIRCd is free software; you can
 * redistribute it and/or modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; version 2.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */


/// $ModAuthor: reverse mike.chevronnet@gmail.com
/// $ModConfig: <module name="allsend">
/// $ModDepends: core 4
/// $ModDesc: Adds the /ALLSEND command for opers to send messages to specific groups of users.

#include "inspircd.h"

class CommandAllSend : public Command
{
public:
    CommandAllSend(Module* Creator)
        : Command(Creator, "ALLSEND", 4)
    {
        syntax.push_back("<target> <notice|private> <local|global> <message>");
        // Restrict command to operators using IsOper check in the Handle method
    }

    CmdResult Handle(User* user, const Params& parameters) override
    {
        std::string target = parameters[0];
        std::string mode = parameters[1];
        std::string scope = parameters[2];
        std::string message = parameters[3];

        bool isNotice = (mode == "notice");
        bool isLocal = (scope == "local");

        auto sendMessage = [&](User* recipient) {
            if (isNotice)
            {
                recipient->WriteNotice(message);
            }
            else
            {
                CommandBase::Params privmsgParams;
                privmsgParams.push_back(recipient->nick);
                privmsgParams.push_back(message);
                ServerInstance->Parser.CallHandler("PRIVMSG", privmsgParams, user);
            }
        };

        auto sendToUsers = [&](const std::function<bool(User*)>& predicate) {
            const UserManager::LocalList& users = ServerInstance->Users.GetLocalUsers();
            for (auto* recipient : users)
            {
                if (predicate(recipient))
                {
                    sendMessage(recipient);
                }
            }
        };

        if (target == "opers")
        {
            sendToUsers([&](User* recipient) {
                return recipient->IsOper() && (!isLocal || IS_LOCAL(recipient));
            });
            user->WriteNotice("Message sent to all opers.");
        }
        else if (target == "users")
        {
            sendToUsers([&](User* recipient) {
                return !recipient->IsOper() && (!isLocal || IS_LOCAL(recipient));
            });
            user->WriteNotice("Message sent to all users.");
        }
        else if (target == "all")
        {
            sendToUsers([&](User* recipient) {
                return !isLocal || IS_LOCAL(recipient);
            });
            user->WriteNotice("Message sent to everyone.");
        }
        else
        {
            user->WriteNotice("Error: Invalid target. Use 'opers', 'users', or 'all'.");
            return CmdResult::FAILURE;
        }

        return CmdResult::SUCCESS;
    }
};

class ModuleAllSend : public Module
{
private:
    CommandAllSend cmd;

public:
    ModuleAllSend()
        : Module(VF_VENDOR, "Adds the /ALLSEND command for opers to send messages to specific groups."),
          cmd(this)
    {
    }

    void init() override
    {
        // Removed AddService call as services are automatically added since v3
    }
};

MODULE_INIT(ModuleAllSend)
