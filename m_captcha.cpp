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
/// $ModConfig: <captchaconfig conninfo="dbname=example user=postgres password=secret hostaddr=127.0.0.1 port=5432" ports="6667,6697" url="http://example.com/verify/">
/// $ModDepends: core 4
/// $ModDesc: Requires users to solve a CAPTCHA before connecting by checking a PostgreSQL database.

#include "inspircd.h"
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
        : Module(VF_VENDOR, "Requires users to solve a CAPTCHA before connecting by checking a PostgreSQL database."), db(nullptr)
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
            return false;
        }

        std::string query = INSP_FORMAT("SELECT COUNT(*) FROM ircaccess_alloweduser WHERE ip_address = '{}'", ip);
        PGresult* res = PQexec(conn, query.c_str());

        if (PQresultStatus(res) != PGRES_TUPLES_OK)
        {
            ServerInstance->Logs.Normal(MODNAME, INSP_FORMAT("Failed to execute query: {}", PQerrorMessage(conn)));
            PQclear(res);
            return false;
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
            ServerInstance->Logs.Normal(MODNAME, INSP_FORMAT("Port {} is not in the CAPTCHA check list.", port));
            return MOD_RES_PASSTHRU;
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
