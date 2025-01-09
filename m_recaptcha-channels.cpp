/*
 * InspIRCd -- Internet Relay Chat Daemon
 *
 *   Copyright (C) 2015-2016 reverse Chevronnet
 *   mike.chevronnet@gmail.com
 *
 * This file is part of InspIRCd.  InspIRCd is free software; you can
 * redistribute it and/or modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; version 2.
 */

/// $CompilerFlags: find_compiler_flags("libpq")
/// $LinkerFlags: find_linker_flags("libpq")

/// $ModAuthor: reverse mike.chevronnet@gmail.com
/// $ModConfig: <captchaconfig conninfo="dbname=example user=postgres password=secret hostaddr=127.0.0.1 port=5432" ports="6667,6697" url="http://meme.com/verify/">
/// $ModDepends: core 4

#include "inspircd.h"
#include "extension.h"
#include <libpq-fe.h>
#include <unordered_map>
#include <unordered_set>
#include <chrono>
#include <sstream>

class ModuleCaptchaCheck : public Module
{
private:
    std::string conninfo;
    std::string captcha_url;
    PGconn* db;
    std::unordered_set<int> ports;
    std::unordered_map<std::string, std::chrono::steady_clock::time_point> ip_cache;

    static constexpr int CACHE_DURATION_MINUTES = 10;
    static constexpr int MAX_ALLOWED_REQUESTS = 5;
    static constexpr size_t IRC_MAX_LENGTH = 512;

    PGconn* GetConnection()
    {
        if (!db || PQstatus(db) != CONNECTION_OK)
        {
            db = PQconnectdb(conninfo.c_str());
            if (PQstatus(db) != CONNECTION_OK)
            {
                ServerInstance->Logs.Normal(MODNAME, INSP_FORMAT("Failed to connect to PostgreSQL database: {}", PQerrorMessage(db)));
                return nullptr;
            }
        }
        return db;
    }

public:
    ModuleCaptchaCheck()
        : Module(VF_VENDOR, "Requires users to solve a Google reCAPTCHA before connecting with PostgreSQL."), db(nullptr)
    {
    }

    void ReadConfig(ConfigStatus& status) override
    {
        auto& tag = ServerInstance->Config->ConfValue("captchaconfig");

        conninfo = tag->getString("conninfo");
        if (conninfo.empty())
        {
            throw ModuleException(this, "<captchaconfig:conninfo> is a required configuration option.");
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

        ServerInstance->Logs.Normal(MODNAME, INSP_FORMAT("Configured PostgreSQL connection info: {}", conninfo));
        ServerInstance->Logs.Normal(MODNAME, INSP_FORMAT("Configured reCAPTCHA URL: {}", captcha_url));

        // Parse the ports
        ports.clear();
        irc::sepstream sep(portlist, ',');
        std::string port;
        while (sep.GetToken(port))
        {
            int portnum = ConvToNum<int>(port);
            ports.insert(portnum);
            ServerInstance->Logs.Normal(MODNAME, INSP_FORMAT("Added port {} to reCAPTCHA check list", portnum));
        }

        db = GetConnection();
    }

    void OnUnloadModule(Module* mod) override
    {
        if (db)
        {
            PQfinish(db);
        }
    }

    bool CheckCaptcha(const std::string& ip)
    {
        auto now = std::chrono::steady_clock::now();

        // Check cache
        if (ip_cache.find(ip) != ip_cache.end() && now < ip_cache[ip])
        {
            return true;
        }

        PGconn* conn = GetConnection();
        if (!conn)
        {
            ServerInstance->Logs.Normal(MODNAME, "Database connection unavailable, skipping reCAPTCHA check.");
            return true; // Allow connections if database is unavailable
        }

        std::string query = INSP_FORMAT("SELECT COUNT(*) FROM ircaccess_alloweduser WHERE ip_address = '{}'", ip);
        PGresult* res = PQexec(conn, query.c_str());

        if (PQresultStatus(res) != PGRES_TUPLES_OK)
        {
            ServerInstance->Logs.Normal(MODNAME, INSP_FORMAT("Failed to execute query: {}", PQerrorMessage(conn)));
            PQclear(res);
            return true; // Allow connections if query fails
        }

        int count = atoi(PQgetvalue(res, 0, 0));
        PQclear(res);

        if (count > 0)
        {
            ip_cache[ip] = now + std::chrono::minutes(CACHE_DURATION_MINUTES); // Cache for defined duration
            return true;
        }

        return false;
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
            ServerInstance->Logs.Normal(MODNAME, INSP_FORMAT("Port {} is not in the Google reCAPTCHA check list.", port));
            return MOD_RES_PASSTHRU;
        }

        if (!CheckCaptcha(ip))
        {
            user->WriteNotice("***** reCAPTCHA: You must solve a Google reCAPTCHA to connect. Please visit " + captcha_url + " to verify yourself.");
        }

        return MOD_RES_PASSTHRU;
    }

    ModResult OnUserPreJoin(LocalUser* user, Channel* chan, const std::string& cname, std::string& privs, const std::string& keygiven, bool override) override;

    class CommandRecaptcha : public Command
    {
    private:
        ModuleCaptchaCheck* parent;

    public:
        CommandRecaptcha(Module* Creator, ModuleCaptchaCheck* Parent)
            : Command(Creator, "RECAPTCHA", 2, 2), parent(Parent)
        {
            this->syntax.clear();
            this->syntax.push_back("add <ip>");
            this->syntax.push_back("search <ip>");
        }

        CmdResult Handle(User* user, const Params& parameters) override
        {
            if (!user->HasPrivPermission("users/auspex"))
            {
                user->WriteNotice("*** reCAPTCHA: You do not have permission to use this command.");
                return CmdResult::FAILURE;
            }

            if (parameters[0] == "add")
            {
                const std::string& ip = parameters[1];
                if (ip.length() > IRC_MAX_LENGTH - 50)
                {
                    user->WriteNotice("*** reCAPTCHA: IP address too long, cannot add.");
                    return CmdResult::FAILURE;
                }

                PGconn* conn = parent->GetConnection();
                if (!conn)
                {
                    user->WriteNotice("*** reCAPTCHA: Database connection error.");
                    return CmdResult::FAILURE;
                }

                std::string query = INSP_FORMAT("INSERT INTO ircaccess_alloweduser (ip_address) VALUES ('{}')", ip);
                PGresult* res = PQexec(conn, query.c_str());

                if (PQresultStatus(res) != PGRES_COMMAND_OK)
                {
                    user->WriteNotice(INSP_FORMAT("*** reCAPTCHA: Failed to add IP: {}", PQerrorMessage(conn)));
                    PQclear(res);
                    return CmdResult::FAILURE;
                }

                PQclear(res);
                user->WriteNotice(INSP_FORMAT("*** reCAPTCHA: Successfully added IP: {}", ip));
                return CmdResult::SUCCESS;
            }
            else if (parameters[0] == "search")
            {
                const std::string& ip = parameters[1];
                if (ip.length() > IRC_MAX_LENGTH - 50)
                {
                    user->WriteNotice("*** reCAPTCHA: IP address too long, cannot search.");
                    return CmdResult::FAILURE;
                }

                PGconn* conn = parent->GetConnection();
                if (!conn)
                {
                    user->WriteNotice("*** reCAPTCHA: Database connection error.");
                    return CmdResult::FAILURE;
                }

                std::string query = INSP_FORMAT("SELECT ip_address FROM ircaccess_alloweduser WHERE ip_address = '{}'", ip);
                PGresult* res = PQexec(conn, query.c_str());

                if (PQresultStatus(res) != PGRES_TUPLES_OK)
                {
                    user->WriteNotice(INSP_FORMAT("*** reCAPTCHA: Failed to search for IP: {}", PQerrorMessage(conn)));
                    PQclear(res);
                    return CmdResult::FAILURE;
                }

                if (PQntuples(res) > 0)
                {
                    user->WriteNotice(INSP_FORMAT("*** reCAPTCHA: IP found: {}", ip));
                }
                else
                {
                    user->WriteNotice(INSP_FORMAT("*** reCAPTCHA: IP not found: {}", ip));
                }

                PQclear(res);
                return CmdResult::SUCCESS;
            }
            else
            {
                user->WriteNotice("*** reCAPTCHA: Unknown subcommand. Use add <ip> or search <ip>. Example: /reCAPTCHA add 127.0.0.1");
                return CmdResult::FAILURE;
            }
        }
    };

    void init() override
    {
        ServerInstance->Modules.AddService(*new CommandRecaptcha(this, this));
    }
};

// OnUserPreJoin implementation
ModResult ModuleCaptchaCheck::OnUserPreJoin(LocalUser* user, Channel* chan, const std::string& cname, std::string& privs, const std::string& keygiven, bool override)
{
    std::string client_sa_str = user->client_sa.str();
    std::string ip = ExtractIP(client_sa_str);

    if (!CheckCaptcha(ip))
    {
        user->WriteNotice("** CAPTCHA verification required: You must verify at " + captcha_url + " before joining channels.");
        return MOD_RES_DENY;
    }

    return MOD_RES_PASSTHRU;
}

MODULE_INIT(ModuleCaptchaCheck)
