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

/// $CompilerFlags: find_compiler_flags("sqlite3")
/// $LinkerFlags: find_linker_flags("sqlite3")

/// $ModAuthor: reverse mike.chevronnet@gmail.com
/// $ModConfig: <captchaconfig dbpath="/path/to/your/db.sqlite3" ports="6667,6697" url="http://recaptcha.redlatina.chat/ircaccess/">
/// $ModDepends: core 4
/// $ModDesc: Requires users to solve a CAPTCHA before connecting by checking an SQLite database.

#include "inspircd.h"
#include <sqlite3.h>

class ModuleCaptchaCheck : public Module
{
private:
    std::string dbpath;
    std::string captcha_url;
    sqlite3* db;
    std::set<int> ports;

public:
    ModuleCaptchaCheck()
        : Module(VF_VENDOR, "Requires users to solve a CAPTCHA before connecting by checking an SQLite database.")
        , db(nullptr)
    {
    }

    void ReadConfig(ConfigStatus& status) override
    {
        auto& tag = ServerInstance->Config->ConfValue("captchaconfig");
        
        dbpath = tag->getString("dbpath");
        if (dbpath.empty())
        {
            throw ModuleException(this, "<captchaconfig:dbpath> is a required configuration option.");
        }

        std::string portlist = tag->getString("ports");
        if (portlist.empty())
        {
            throw ModuleException(this, "<captchaconfig:ports> is a required configuration option.");
        }

        captcha_url = tag->getString("url");
        if (captcha_url.empty())
        {
            throw ModuleException(this, "<captchaconfig:url> is a required configuration option.");
        }

        ServerInstance->Logs.Normal(MODNAME, INSP_FORMAT("Configured database path: {}", dbpath));
        ServerInstance->Logs.Normal(MODNAME, INSP_FORMAT("Configured CAPTCHA URL: {}", captcha_url));

        // Parse the ports
        ports.clear();
        irc::sepstream sep(portlist, ',');
        std::string port;
        while (sep.GetToken(port))
        {
            int portnum = ConvToNum<int>(port);
            ports.insert(portnum);
            ServerInstance->Logs.Normal(MODNAME, INSP_FORMAT("Added port {} to CAPTCHA check list", portnum));
        }

        int rc = sqlite3_open(dbpath.c_str(), &db);
        if (rc != SQLITE_OK)
        {
            ServerInstance->Logs.Normal(MODNAME, INSP_FORMAT("Can't open database: {}", sqlite3_errmsg(db)));
            sqlite3_close(db);
            db = nullptr;
        }
        else
        {
            ServerInstance->Logs.Normal(MODNAME, INSP_FORMAT("Database opened successfully: {}", dbpath));
        }
    }

    void OnUnloadModule(Module* mod) override
    {
        if (db)
        {
            sqlite3_close(db);
        }
    }

    bool CheckCaptcha(const std::string& ip)
    {
        sqlite3_stmt* stmt;
        const char* query = "SELECT COUNT(*) FROM ircaccess_alloweduser WHERE ip_address = ?";
        int rc = sqlite3_prepare_v2(db, query, -1, &stmt, 0);
        if (rc != SQLITE_OK)
        {
            ServerInstance->Logs.Normal(MODNAME, INSP_FORMAT("Failed to prepare statement: {}", sqlite3_errmsg(db)));
            return false;
        }

        ServerInstance->Logs.Normal(MODNAME, INSP_FORMAT("Checking CAPTCHA for IP: {}", ip));
        sqlite3_bind_text(stmt, 1, ip.c_str(), -1, SQLITE_STATIC);

        rc = sqlite3_step(stmt);
        int count = 0;
        if (rc == SQLITE_ROW)
        {
            count = sqlite3_column_int(stmt, 0);
        }
        sqlite3_finalize(stmt);

        // Send a notice to all operators
        std::string message = INSP_FORMAT("CAPTCHA check result for IP {}: {}", ip, count);
        ServerInstance->SNO.WriteToSnoMask('a', message);

        return count > 0;
    }

    std::string ExtractIP(const std::string& client_sa_str)
    {
        std::string::size_type pos = client_sa_str.find(':');
        if (pos != std::string::npos)
        {
            return client_sa_str.substr(0, pos);
        }
        return client_sa_str;
    }

    ModResult OnUserRegister(LocalUser* user) override
    {
        int port = user->server_sa.port();
        std::string client_sa_str = user->client_sa.str();
        std::string ip = ExtractIP(client_sa_str);

        ServerInstance->Logs.Normal(MODNAME, INSP_FORMAT("OnUserRegister called for user {} ({}) on port {}", user->nick, client_sa_str, port));

        if (ports.find(port) == ports.end())
        {
            ServerInstance->Logs.Normal(MODNAME, INSP_FORMAT("Port {} is not in the CAPTCHA check list.", port));
            return MOD_RES_PASSTHRU;
        }

        if (!db)
        {
            user->WriteNotice("** Internal error: database not available.");
            ServerInstance->Users.QuitUser(user, "CAPTCHA not solved.");
            return MOD_RES_DENY;
        }

        if (!CheckCaptcha(ip))
        {
            user->WriteNotice("** You must solve a CAPTCHA to connect. Please visit " + captcha_url + " and then reconnect.");
            ServerInstance->Logs.Normal(MODNAME, INSP_FORMAT("User {} denied access due to unsolved CAPTCHA (IP: {})", user->nick, ip));
            ServerInstance->Users.QuitUser(user, "CAPTCHA not solved.");
            return MOD_RES_DENY;
        }

        ServerInstance->Logs.Normal(MODNAME, INSP_FORMAT("User {} allowed access after CAPTCHA verification (IP: {})", user->nick, ip));
        return MOD_RES_PASSTHRU;
    }
};

MODULE_INIT(ModuleCaptchaCheck)
