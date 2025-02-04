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
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http:// www.gnu.org/licenses/>.
 */

/// $ModAuthor: reverse Chevronnet <mike.chevronnet@gmail.com>
/// $ModDesc: Store wiki slug of wikipages of the network.
/// $ModDepends: core 4

#include "inspircd.h"
#include "modules/sql.h"
#include <algorithm>
#include <numeric>
#include <vector>

// Cache to map keywords to slugs.
using WikiMap = std::map<std::string, std::vector<std::string>>;

// Enum to represent query operations.
enum class WikiOp { SHOWALL, SHOWONE, INSERT, DELETE };

// Forward declaration of ModuleWiki.
class ModuleWiki;

// Query to load all entries from the database into the cache. 
class LoadAllQuery final : public SQL::Query {
 private:
    ModuleWiki* mod;

 public:
    explicit LoadAllQuery(ModuleWiki* m);

    void OnResult(SQL::Result& result) override;
    void OnError(const SQL::Error& error) override;
};

// Query to handle operations like SHOW, INSERT, DELETE.
class WikiQuery final : public SQL::Query {
 private:
    ModuleWiki* mod;
    WikiOp operation;
    std::string customData;

 public:
    WikiQuery(ModuleWiki* m, WikiOp op, const std::string& cd = "");

    void OnResult(SQL::Result& result) override;
    void OnError(const SQL::Error& error) override;
};

// Main module class to handle the wiki functionality.
class ModuleWiki final : public Module {
 private:
    dynamic_reference<SQL::Provider> sql;
    WikiMap wikiCache;

    std::string dbid;
    bool autoRespond;
    bool caseSensitive;
    std::string wikiPrefix;
    std::string helpChannel;

 public:
    ModuleWiki()
        : Module(VF_VENDOR, "Store wiki slug of wikipages of the network."),
          sql(this, "SQL"),
          cmd(this),
          cmdSend(this) {} //  Correctly initialize /SEND command

    void ReadConfig(ConfigStatus& status) override;
    void OnUserMessage(User* user, const MessageTarget& target, const MessageDetails& details) override;
    void LoadAllEntries();
    void DoInsert(const std::string& rawKey, const std::string& slug);
    void DoDelete(const std::string& rawKey, const std::string& slug);
    void DoDeleteAll(const std::string& rawKey);
    void OnShow(User* user, const std::string& rawKey);
    void WriteSplitNotice(User* user, const std::string& message, size_t chunkSize = 400);
    std::string EscapeString(const std::string& input);

    //  Public accessor methods for wikiCache and wikiPrefix
    void ClearWikiCache() {
        wikiCache.clear();
    }

    void AddWikiEntry(const std::string& keyword, const std::string& slug) {
        auto& slugs = wikiCache[keyword];
        if (std::find(slugs.begin(), slugs.end(), slug) == slugs.end()) {
            slugs.push_back(slug);
        }
    }

    bool RemoveWikiEntry(const std::string& keyword, const std::string& slug) {
        auto it = wikiCache.find(keyword);
        if (it != wikiCache.end()) {
            auto& slugs = it->second;
            auto slug_it = std::find(slugs.begin(), slugs.end(), slug);
            if (slug_it != slugs.end()) {
                slugs.erase(slug_it);
                if (slugs.empty()) {
                    wikiCache.erase(it);
                }
                return true;
            }
        }
        return false;
    }

    void GetWikiSlugs(const std::string& keyword, std::vector<std::string>& slugs) const {
        auto it = wikiCache.find(keyword);
        if (it != wikiCache.end()) {
            slugs = it->second;
        }
    }

    const std::string& GetWikiPrefix() const {
        return wikiPrefix;
    }

    class CommandWiki final : public Command {
     private:
        ModuleWiki* mod;

     public:
        explicit CommandWiki(ModuleWiki* m)
            : Command(m, "WIKI", 1, 3),
              mod(m) {
            syntax.push_back("{ADD|DEL|SHOW} [<keyword>] [<slug>]");
        }

        CmdResult Handle(User* user, const Params& parameters) override;
    };

    class CommandSend final : public Command {
     private:
        ModuleWiki* mod;

     public:
        explicit CommandSend(ModuleWiki* m)
            : Command(m, "SEND", 2, 2),
              mod(m) {
            // Set the syntax for the command.
            syntax.push_back("<user> <keyword>");
        }

        CmdResult Handle(User* user, const Params& parameters) override;
    };

 private:
    
    CommandWiki cmd;
    CommandSend cmdSend;
};

// Function to send split notices to users. This will change on next release.
void ModuleWiki::WriteSplitNotice(User* user, const std::string& message, size_t chunkSize) {
    size_t offset = 0;
    while (offset < message.size()) {
        size_t len = std::min(chunkSize, message.size() - offset);
        user->WriteNotice(message.substr(offset, len));
        offset += len;
    }
}

// Escape special characters for SQL queries.
std::string ModuleWiki::EscapeString(const std::string& input) {
    std::string escaped;
    for (char c : input) {
        if (c == '\'') //  Escape single quotes
            escaped += "''";
        else
            escaped += c;
    }
    return escaped;
}

LoadAllQuery::LoadAllQuery(ModuleWiki* m)
    : SQL::Query(m), mod(m) {}

void LoadAllQuery::OnResult(SQL::Result& result) {
    mod->ClearWikiCache();
    SQL::Row row;
    while (result.GetRow(row)) {
        std::string keyword = row[0].value_or("");
        std::string slug = row[1].value_or("");
        if (!keyword.empty() && !slug.empty())
            mod->AddWikiEntry(keyword, slug);
    }
    ServerInstance->SNO.WriteGlobalSno('a', "*** [wiki] Wiki database loaded successfully.");
}

void LoadAllQuery::OnError(const SQL::Error& error) {
    ServerInstance->SNO.WriteGlobalSno('a', "*** [wiki] Error loading wiki database: " + std::string(error.ToString()));
}

//  WikiQuery implementation. 
WikiQuery::WikiQuery(ModuleWiki* m, WikiOp op, const std::string& cd)
    : SQL::Query(m), mod(m), operation(op), customData(cd) {}

void WikiQuery::OnResult(SQL::Result& result) {
    if (operation == WikiOp::SHOWONE) {
        size_t pos = customData.find(' ');
        if (pos == std::string::npos)
            return;

        std::string uuid = customData.substr(0, pos);
        std::string rawKey = customData.substr(pos + 1);

        User* user = ServerInstance->Users.FindUUID(uuid);
        if (user) {
            std::vector<std::string> slugs;
            SQL::Row row;
            while (result.GetRow(row)) {
                std::string slug = row[1].value_or("");
                if (!slug.empty())
                    slugs.push_back(slug);
            }

            if (!slugs.empty()) {
                std::string response = "*** [wiki] Wiki Page for '" + rawKey + "':\n";
                for (const auto& slug : slugs) {
                    response += mod->GetWikiPrefix() + slug + "\n";
                }
                mod->WriteSplitNotice(user, response);
            } else {
                user->WriteNotice("*** [wiki] Wiki Page found for '" + rawKey + "'.");
            }
        }
    } else if (operation == WikiOp::SHOWALL) {
        User* user = ServerInstance->Users.FindUUID(customData);
        if (user) {
            std::string message = "*** [wiki] All Wiki's in database:\n";
            SQL::Row row;
            while (result.GetRow(row)) {
                std::string keyword = row[0].value_or("");
                std::string slug = row[1].value_or("");
                if (!keyword.empty() && !slug.empty()) {
                    message += keyword + " -> " + mod->GetWikiPrefix() + slug + "\n";
                }
            }
            mod->WriteSplitNotice(user, message);
        }
    }
}

void WikiQuery::OnError(const SQL::Error& error) {
    ServerInstance->SNO.WriteGlobalSno('a', "*** [wiki] Query error: " + std::string(error.ToString()));
}

//  ModuleWiki implementation. 
void ModuleWiki::ReadConfig(ConfigStatus& status) {
    wikiCache.clear();

    auto& tag = ServerInstance->Config->ConfValue("wiki");
    dbid = tag->getString("dbid", "wikidb");
    sql.SetProvider("SQL/" + dbid);
    autoRespond = tag->getBool("autorespond", true);
    caseSensitive = tag->getBool("casesensitive", false);
    wikiPrefix = tag->getString("wikiprefix", "https:// wiki.t-chat.fr/w/");
    helpChannel = tag->getString("helpchannel", "#aide");

    if (!sql) {
        throw ModuleException(this, "*** [wiki] Could not find SQL provider: " + dbid);
    }

    LoadAllEntries();
}

void ModuleWiki::OnUserMessage(User* user, const MessageTarget& target, const MessageDetails& details) {
    if (!autoRespond || target.type != MessageTarget::TYPE_CHANNEL)
        return;

    Channel* chan = target.Get<Channel>();
    if (!chan || !irc::equals(chan->name, helpChannel))
        return;

    std::string text = details.text;
    if (!caseSensitive) {
        std::transform(text.begin(), text.end(), text.begin(), ::tolower);
    }

    for (const auto& [keyword, slugs] : wikiCache) {
        if (text.find(keyword) != std::string::npos) {
            for (const auto& slug : slugs) {
                std::string link = GetWikiPrefix() + slug;
                chan->WriteRemoteNotice("[wiki] " + user->nick + ": " + link);
            }
            break; //  Remove this break if you want to respond to multiple keywords in one message
        }
    }
}

void ModuleWiki::LoadAllEntries() {
    if (!sql) {
        ServerInstance->SNO.WriteGlobalSno('a', "*** [wiki] No SQL provider available.");
        return;
    }

    sql->Submit(new LoadAllQuery(this), "SELECT keyword, slug FROM wiki_entries");
}

void ModuleWiki::DoInsert(const std::string& rawKey, const std::string& slug) {
    if (!sql) {
        ServerInstance->SNO.WriteGlobalSno('a', "*** [wiki] SQL database is not available.");
        return;
    }

    //  Insert without duplicates due to UNIQUE(keyword, slug)
    std::string query = INSP_FORMAT(
        "INSERT INTO wiki_entries (keyword, slug) VALUES ('{}', '{}')",
        EscapeString(rawKey), EscapeString(slug));

    sql->Submit(new WikiQuery(this, WikiOp::INSERT), query);
}

void ModuleWiki::DoDelete(const std::string& rawKey, const std::string& slug) {
    if (!sql) {
        ServerInstance->SNO.WriteGlobalSno('a', "*** [wiki] SQL database is not available.");
        return;
    }

    std::string query = INSP_FORMAT(
        "DELETE FROM wiki_entries WHERE keyword = '{}' AND slug = '{}'",
        EscapeString(rawKey), EscapeString(slug));

    sql->Submit(new WikiQuery(this, WikiOp::DELETE), query);
}

void ModuleWiki::DoDeleteAll(const std::string& rawKey) {
    if (!sql) {
        ServerInstance->SNO.WriteGlobalSno('a', "*** [wiki] SQL database is not available.");
        return;
    }

    std::string query = INSP_FORMAT(
        "DELETE FROM wiki_entries WHERE keyword = '{}'",
        EscapeString(rawKey));

    sql->Submit(new WikiQuery(this, WikiOp::DELETE), query);
}

void ModuleWiki::OnShow(User* user, const std::string& rawKey) {
    if (!sql) {
        user->WriteNotice("*** [wiki] SQL database is not available.");
        return;
    }

    if (rawKey.empty()) {
        sql->Submit(new WikiQuery(this, WikiOp::SHOWALL, user->uuid), "SELECT keyword, slug FROM wiki_entries");
    } else {
        sql->Submit(new WikiQuery(this, WikiOp::SHOWONE, user->uuid + " " + rawKey),
            INSP_FORMAT("SELECT keyword, slug FROM wiki_entries WHERE keyword = '{}' ORDER BY slug ASC", EscapeString(rawKey)));
    }
}

CmdResult ModuleWiki::CommandWiki::Handle(User* user, const Params& parameters) {
    //  Permission Check for oper status
    if (!user->IsOper()) {
        user->WriteNotice("*** [wiki] You do not have permission to use this command.");
        return CmdResult::FAILURE;
    }

    if (parameters.empty()) {
        user->WriteNotice("*** [wiki] Missing subcommand.");
        return CmdResult::FAILURE;
    }

    std::string subcmd = parameters[0];
    std::transform(subcmd.begin(), subcmd.end(), subcmd.begin(), ::toupper);

    if (subcmd == "ADD") {
        if (parameters.size() < 3) {
            user->WriteNotice("*** [wiki] Usage: WIKI ADD <keyword> <slug>");
            return CmdResult::FAILURE;
        }

        std::string rawKey = parameters[1];
        std::string slug = parameters[2];

        //  Check duplication
        auto it = mod->wikiCache.find(rawKey);
        if (it != mod->wikiCache.end()) {
            if (std::find(it->second.begin(), it->second.end(), slug) != it->second.end()) {
                user->WriteNotice("*** [wiki] Slug already exists for keyword '" + rawKey + "'.");
                return CmdResult::FAILURE;
            }
        }

        mod->DoInsert(rawKey, slug);
        mod->AddWikiEntry(rawKey, slug);
        user->WriteNotice("*** [wiki] Slug added to keyword '" + rawKey + "'.");
        return CmdResult::SUCCESS;
    } else if (subcmd == "DEL") {
        if (parameters.size() < 2) {
            user->WriteNotice("*** [wiki] Usage: WIKI DEL <keyword> [<slug>]");
            return CmdResult::FAILURE;
        }

        std::string rawKey = parameters[1];
        if (parameters.size() == 2) {

            mod->DoDeleteAll(rawKey);
            mod->wikiCache.erase(rawKey);
            user->WriteNotice("*** [wiki] All slugs deleted for keyword '" + rawKey + "'.");
            return CmdResult::SUCCESS;
        } else {
            std::string slug = parameters[2];
            bool removed = mod->RemoveWikiEntry(rawKey, slug);
            if (removed) {
                mod->DoDelete(rawKey, slug);
                user->WriteNotice("*** [wiki] Slug '" + slug + "' deleted from keyword '" + rawKey + "'.");
                return CmdResult::SUCCESS;
            } else {
                user->WriteNotice("*** [wiki] Slug '" + slug + "' not found for keyword '" + rawKey + "'.");
                return CmdResult::FAILURE;
            }
        }
    } else if (subcmd == "SHOW") {
        std::string fullKey = parameters.size() > 1
            ? std::accumulate(parameters.begin() + 1, parameters.end(), std::string(),
                [](const std::string& a, const std::string& b) { return a + (a.empty() ? "" : " ") + b; })
            : "";

        mod->OnShow(user, fullKey);
        return CmdResult::SUCCESS;
    }

    user->WriteNotice("*** [wiki] Invalid subcommand.");
    return CmdResult::FAILURE;
}

CmdResult ModuleWiki::CommandSend::Handle(User* user, const Params& parameters) {
    //  Check oper status
    if (!user->IsOper()) {
        user->WriteNotice("*** [wiki] You do not have permission to use this command.");
        return CmdResult::FAILURE;
    }

    if (parameters.size() < 2) {
        user->WriteNotice("*** [wiki] Usage: SEND <user> <keyword>");
        return CmdResult::FAILURE;
    }

    const std::string& targetNick = parameters[0];
    const std::string& rawKey = parameters[1];

    //  Find the target user
    User* targetUser = ServerInstance->Users.FindNick(targetNick);
    if (!targetUser) {
        user->WriteNotice("*** [wiki] User '" + targetNick + "' not found.");
        return CmdResult::FAILURE;
    }

    //  Search for the keyword in the cache.
    std::vector<std::string> slugs;
    mod->GetWikiSlugs(rawKey, slugs);
    if (slugs.empty()) {
        user->WriteNotice("*** [wiki] Wiki Pages found for keyword '" + rawKey + "'.");
        return CmdResult::FAILURE;
    }

    //  Decide whether to send all slugs or a single one. Here, we'll send all.
    std::string fullUrl;
    for (const auto& slug : slugs) {
        fullUrl += "*** [wiki] Wiki page '" + rawKey + "': " + mod->GetWikiPrefix() + slug + "\n";
    }

    //  Send the notice to the target user.
    mod->WriteSplitNotice(targetUser, fullUrl);

    //  Notify the sender about the successful delivery.
    user->WriteNotice("*** [wiki] Wiki page sent " + std::to_string(slugs.size()) + " url(s) for '" + rawKey + "' to " + targetNick + ".");
    return CmdResult::SUCCESS;
}

MODULE_INIT(ModuleWiki)
