/*
 * InspIRCd -- Internet Relay Chat Daemon
 *
 *   Copyright (C) 2024 Jean reverse Chevronnet
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
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

/// $ModAuthor: Jean reverse Chevronnet
/// $ModDesc: Provides a JSON-RPC 2.0 interface for InspIRCd-4.
/// $ModDepends: core 4


#include "inspircd.h"
#include "modules/httpd.h"
#include "stringutils.h"
#include <nlohmann/json.hpp>

using json = nlohmann::json;

// JSON-RPC Error Codes
enum JSONRPCErrorCode
{
    JSON_RPC_ERROR_PARSE_ERROR              = -32700, /**< JSON parse error (fatal) */
    JSON_RPC_ERROR_INVALID_REQUEST          = -32600, /**< Invalid JSON-RPC Request */
    JSON_RPC_ERROR_METHOD_NOT_FOUND         = -32601, /**< Method not found */
    JSON_RPC_ERROR_INVALID_PARAMS           = -32602, /**< Method parameters invalid */
    JSON_RPC_ERROR_INTERNAL_ERROR           = -32603, /**< Internal server error */

    JSON_RPC_ERROR_API_CALL_DENIED          = -32000, /**< The api user does not have enough permissions to do this call */
    JSON_RPC_ERROR_SERVER_GONE              = -32001, /**< The request was forwarded to a remote server, but this server went gone */
    JSON_RPC_ERROR_TIMEOUT                  = -32002, /**< The request was forwarded to a remote server, but it timed out (15 sec) */
    JSON_RPC_ERROR_REMOTE_SERVER_NO_RPC     = -32003, /**< The request was going to be forwarded but remote server lacks JSON-RPC */

    JSON_RPC_ERROR_NOT_FOUND                =  -1000, /**< Target not found (no such nick / channel / ..) */
    JSON_RPC_ERROR_ALREADY_EXISTS           =  -1001, /**< Resource already exists by that name */
    JSON_RPC_ERROR_INVALID_NAME             =  -1002, /**< Name is not permitted (eg: nick, channel, ..) */
    JSON_RPC_ERROR_USERNOTINCHANNEL         =  -1003, /**< The user is not in the channel */
    JSON_RPC_ERROR_TOO_MANY_ENTRIES         =  -1004, /**< Too many entries (eg: banlist, ..) */
    JSON_RPC_ERROR_DENIED                   =  -1005  /**< Permission denied for user */
};

class ModuleJSONRPC final
    : public Module
    , public HTTPRequestEventListener
{
private:
    std::string apiuser;
    std::string apipassword;
    HTTPdAPI httpAPI;

public:
    ModuleJSONRPC()
        : Module(VF_VENDOR, "Provides a JSON-RPC 2.0 API for InspIRCd.")
        , HTTPRequestEventListener(this)
        , httpAPI(this)
    {
    }

    void ReadConfig(ConfigStatus& status) override
    {
        auto tag = ServerInstance->Config->ConfValue("jsonrpc");
        apiuser = tag->getString("apiuser", "apiuser");
        apipassword = tag->getString("rpc-user-password", "password");
    }

    bool AuthenticateRequest(HTTPRequest& request)
    {
        std::string auth_header = request.headers->GetHeader("Authorization");
        if (auth_header.find("Basic ") == 0)
        {
            std::string encoded = auth_header.substr(6);
            std::string decoded = Base64::Decode(encoded);

            return decoded == apiuser + ":" + apipassword;
        }
        return false;
    }

    void SendJSONErrorResponse(HTTPRequest& request, int id, int error_code, const std::string& message)
    {
        json error_response = {
            {"jsonrpc", "2.0"},
            {"id", id},
            {"error", {{"code", error_code}, {"message", message}}}
        };

        HTTPDocumentResponse http_response(this, request, new std::stringstream(), 400);
        *http_response.document << error_response.dump();
        http_response.headers.SetHeader("Content-Type", "application/json");
        httpAPI->SendResponse(http_response);
    }

    void SendJSONResponse(HTTPRequest& request, int id, const json& result)
    {
        json response = {
            {"jsonrpc", "2.0"},
            {"id", id},
            {"result", result}
        };

        HTTPDocumentResponse http_response(this, request, new std::stringstream(), 200);
        *http_response.document << response.dump();
        http_response.headers.SetHeader("Content-Type", "application/json");
        httpAPI->SendResponse(http_response);
    }

    ModResult OnHTTPRequest(HTTPRequest& request) override
    {
        if (request.GetPath() != "/jsonrpc")  
            return MOD_RES_PASSTHRU;

        if (!AuthenticateRequest(request))
        {
            SendJSONErrorResponse(request, 0, JSON_RPC_ERROR_API_CALL_DENIED, "Unauthorized");
            return MOD_RES_DENY;
        }

        json request_json;
        int id = 0;

        try
        {
            request_json = json::parse(request.GetPostData());
            id = request_json.value("id", 0);
        }
        catch (const std::exception&)
        {
            SendJSONErrorResponse(request, 0, JSON_RPC_ERROR_PARSE_ERROR, "Invalid JSON request");
            return MOD_RES_DENY;
        }

        if (!request_json.contains("method") || !request_json.contains("params"))
        {
            SendJSONErrorResponse(request, id, JSON_RPC_ERROR_INVALID_REQUEST, "Invalid JSON-RPC request format");
            return MOD_RES_DENY;
        }

        std::string method = request_json["method"];
        json params = request_json["params"];

        json result;
        try
        {
            if (method == "channel.list")
            {
                json channels = json::array();
                for (const auto& [name, chan] : ServerInstance->Channels.GetChans())
                    channels.push_back(name);

                result = {{"list", channels}};
            }
            else if (method == "user.list")
            {
                json users = json::array();
                for (const auto& [uuid, user] : ServerInstance->Users.GetUsers())
                    users.push_back(user->nick);

                result = {{"list", users}};
            }
            else if (method == "channel.get")
            {
                if (!params.contains("channel"))
                {
                    SendJSONErrorResponse(request, id, JSON_RPC_ERROR_INVALID_PARAMS, "Missing 'channel' parameter");
                    return MOD_RES_DENY;
                }

                std::string channel_name = params["channel"];
                Channel* chan = ServerInstance->Channels.Find(channel_name);
                if (!chan)
                {
                    SendJSONErrorResponse(request, id, JSON_RPC_ERROR_NOT_FOUND, "Channel not found");
                    return MOD_RES_DENY;
                }

                result = {{"name", chan->name}, {"users", chan->GetUsers().size()}};
            }
            else
            {
                SendJSONErrorResponse(request, id, JSON_RPC_ERROR_METHOD_NOT_FOUND, "Unknown method");
                return MOD_RES_DENY;
            }
        }
        catch (const std::exception&)
        {
            SendJSONErrorResponse(request, id, JSON_RPC_ERROR_INTERNAL_ERROR, "Internal server error");
            return MOD_RES_DENY;
        }

        SendJSONResponse(request, id, result);
        return MOD_RES_DENY;
    }
};

MODULE_INIT(ModuleJSONRPC)
