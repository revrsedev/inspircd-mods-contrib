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
/// $ModConfig: <captchaconfig conninfo="dbname=example user=postgres password=secret hostaddr=127.0.0.1 port=5432" url="http://example.com/verify/">
/// $ModDepends: core 4

#include "inspircd.h"
#include "extension.h"
#include <libpq-fe.h>
#include <unordered_map>
#include <chrono>

class ModuleCaptchaCheck : public Module
{
private:
    std::string conninfo;
    std::string captcha_url;
    PGconn* db;
    std::unordered_map<std::string, std::chrono::steady_clock::time_point> ip_cache;
    static constexpr int CACHE_DURATION_MINUTES = 10;

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
            ServerInstance->Logs.Normal(MODNAME, "Database connection unavailable, skipping CAPTCHA check.");
            return true; // Allow actions if database is unavailable
        }

        std::string query = INSP_FORMAT("SELECT COUNT(*) FROM ircaccess_alloweduser WHERE ip_address = '{}'", ip);
        PGresult* res = PQexec(conn, query.c_str());

        if (PQresultStatus(res) != PGRES_TUPLES_OK)
        {
            ServerInstance->Logs.Normal(MODNAME, INSP_FORMAT("Failed to execute query: {}", PQerrorMessage(conn)));
            PQclear(res);
            return true; // Allow actions if query fails
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

    class CommandRecaptcha : public Command
    {
    private:
        ModuleCaptchaCheck* parent;

    public:
        CommandRecaptcha(Module* Creator, ModuleCaptchaCheck* Parent)
            : Command(Creator, "RECAPTCHA", 2, 2), parent(Parent)
        {
            syntax = { "<add|search> <ip>" };
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
                user->WriteNotice("*** reCAPTCHA: Unknown subcommand. Use add <ip> or search <ip>.");
                return CmdResult::FAILURE;
            }
        }
    };

    CommandRecaptcha cmd; // Command is a member variable of the module

public:
    ModuleCaptchaCheck()
        : Module(VF_VENDOR, "Requires users to solve a CAPTCHA before joining channels using PostgreSQL."),
          db(nullptr),
          cmd(this, this) // Initialize the command
    {
    }

    void init() override
    {
        // Command is automatically registered
    }

    void ReadConfig(ConfigStatus& status) override
    {
        auto& tag = ServerInstance->Config->ConfValue("captchaconfig");

        conninfo = tag->getString("conninfo");
        if (conninfo.empty())
        {
            throw ModuleException(this, "<captchaconfig:conninfo> is a required configuration option.");
        }

        captcha_url = tag->getString("url");
        if (captcha_url.empty())
        {
            throw ModuleException(this, "<captchaconfig:url> is a required configuration option.");
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

    ModResult OnUserPreJoin(LocalUser* user, Channel* chan, const std::string& cname, std::string& privs, const std::string& keygiven, bool override) override
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

    ~ModuleCaptchaCheck() override
    {
        if (db)
        {
            PQfinish(db);
        }
    }
};

MODULE_INIT(ModuleCaptchaCheck)
