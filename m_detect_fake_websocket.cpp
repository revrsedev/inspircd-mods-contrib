/*
 * InspIRCd -- Internet Relay Chat Daemon
 *
 *   Copyright (C) 2025 Jean Chevronnet <revrsedev@gmail.com>
 *
 * This file is part of InspIRCd.  InspIRCd is free software: you can
 * redistribute it and/or modify it under the terms of the GNU General
 * Public License as published by the Free Software Foundation, version 2.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/// $ModAuthor: reverse
/// $ModAuthorMail: revrsedev@email.com
/// $ModDepends: core 4
/// $ModDesc: Warns IRC operators and Z-lines botnets trying to use WebSockets.

#include "inspircd.h"
#include "xline.h"
#include "extension.h"

class ModuleDetectFakeWebSocket final : public Module
{
private:
    int websocket_port;
    std::vector<std::string> allowed_origins;
    int zline_duration;
    std::string zline_reason;

    // Reference to the existing WebSocket Origin extension from m_websocket.cpp
    StringExtItem* websocket_origin;

    // Check if the WebSocket origin is allowed
    bool IsAllowedOrigin(const std::string& origin)
    {
        for (const auto& allowed_origin : allowed_origins)
        {
            if (origin.find(allowed_origin) != std::string::npos)
                return true; // Allowed
        }
        return false; // Not allowed
    }

    // Extract the actual WebSocket Origin from m_websocket.cpp
    std::string GetUserWebSocketOrigin(LocalUser* user)
    {
        if (!websocket_origin)
            return "Unknown-Origin"; // ❌ No WebSocket extension found

        const std::string* origin = websocket_origin->Get(user);
        return origin ? *origin : "Unknown-Origin"; // Return WebSocket origin or default
    }

public:
    ModuleDetectFakeWebSocket()
        : Module(VF_VENDOR, "Detects and Z-lines botnets faking WebSocket connections."),
          websocket_origin(nullptr) // Initialize the extension as nullptr
    {
    }

    void ReadConfig(ConfigStatus& status) override
    {
        const auto& tag = ServerInstance->Config->ConfValue("detectfakewebsocket");

        websocket_port = tag->getNum<int>("port", 8083);
        zline_duration = tag->getNum<int>("zline_duration", 3600);
        zline_reason = tag->getString("zline_reason", "Botnet detected using WebSockets!");

        // Read and split multiple allowed origins
        std::string origins = tag->getString("origin", "kiwiirc.com");
        allowed_origins.clear();
        irc::commasepstream originstream(origins);
        std::string origin;
        while (originstream.GetToken(origin))
        {
            allowed_origins.push_back(origin);
        }

        // Get the existing WebSocket origin extension from m_websocket.cpp
        websocket_origin = static_cast<StringExtItem*>(ServerInstance->Extensions.GetItem("websocket-origin"));
        if (!websocket_origin)
        {
            throw ModuleException(this, "Could not find websocket-origin extension. Is m_websocket loaded?");
        }

        ServerInstance->Logs.Normal("m_detect_fake_websocket",
            "Loaded config: WebSockets port = %d, Allowed origins = %s, Z-line = %d seconds",
            websocket_port, origins.c_str(), zline_duration);
    }

    void Prioritize() override
    {
        ServerInstance->Modules.SetPriority(this, I_OnUserRegister, PRIORITY_FIRST);
    }

    ModResult OnUserRegister(LocalUser* user) override
    {
        if (user->server_sa.port() == websocket_port)
        {
            std::string real_origin = GetUserWebSocketOrigin(user); // ✅ Extract real WebSocket Origin

            if (!IsAllowedOrigin(real_origin))
            {
                std::string client_ip = user->GetAddress();

                ServerInstance->Logs.Normal("m_detect_fake_websocket",
                    "Botnet detected! %s is using WebSockets port %d with origin (%s)! Applying Z-line...",
                    client_ip.c_str(), websocket_port, real_origin.c_str());

                for (LocalUser* u : ServerInstance->Users.GetLocalUsers())
                {
                    if (u->IsOper())
                    {
                        u->WriteNotice(INSP_FORMAT(
                            "WARNING: Botnet detected! {} is using WebSockets port {} with origin ({})! Applying Z-line.",
                            client_ip, websocket_port, real_origin));
                    }
                }

                // Apply a Z-line ban
                ZLine* zl = new ZLine(ServerInstance->Time(), zline_duration, "FakeWebSocket", zline_reason, client_ip);
                if (ServerInstance->XLines->AddLine(zl, nullptr))
                {
                    ServerInstance->XLines->ApplyLines();
                }

                //  Disconnect the user immediately
                ServerInstance->Users.QuitUser(user, zline_reason);
            }
        }

        return MOD_RES_PASSTHRU;
    }
};

MODULE_INIT(ModuleDetectFakeWebSocket)
