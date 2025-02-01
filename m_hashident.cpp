/*
 * InspIRCd -- Internet Relay Chat Daemon
 *
 *   Copyright (C) 2024 Jean Chevronnet <mike.chevronnet@gmail.com>
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

/// $ModAuthor: Jean Chevronnet (reverse) <mike.chevronnet@gmail.com>
/// $ModDesc: Sets the user's ident to HMAC-SHA256 hash of their IP address + SECRET_KEY
/// $ModDepends: core 4

#include "inspircd.h"
#include "users.h"
#include "modules/hash.h"
#include <iomanip>
#include <sstream>
#include <arpa/inet.h>

class ModuleHashIdent : public Module
{
private:
	dynamic_reference_nocheck<HashProvider> sha256;
	std::string secret_key;

public:
	ModuleHashIdent()
		: Module(VF_VENDOR, "Sets the user's ident to a 12-character HMAC-SHA256 hash of their IP address. Supports UNIX socket connections."),
		  sha256(this, "hash/sha256")
	{
	}

	/** Read secret key from config **/
	void ReadConfig(ConfigStatus&) override
	{
		std::shared_ptr<ConfigTag> tag = ServerInstance->Config->ConfValue("hashident");
		secret_key = tag->getString("key");

		// If key is missing or empty, throw a config error
		if (secret_key.empty())
		{
			throw ModuleException(this, "Missing required <hashident key=\"...\"> configuration in modules.conf!");
		}
	}

	/** Normalize IP **/
	std::string NormalizeIP(const irc::sockets::sockaddrs& addr)
	{
		char ipstr[INET6_ADDRSTRLEN];

		if (addr.family() == AF_INET) // IPv4
		{
			if (inet_ntop(AF_INET, &addr.in4.sin_addr, ipstr, sizeof(ipstr)) == nullptr)
				return "unknown";
		}
		else if (addr.family() == AF_INET6) // IPv6
		{
			if (inet_ntop(AF_INET6, &addr.in6.sin6_addr, ipstr, sizeof(ipstr)) == nullptr)
				return "unknown";
		}
		else if (addr.family() == AF_UNIX) // UNIX socket
		{
			return "unixsocket";
		}
		else
		{
			return "unknown"; // Unsupported address type
		}

		return std::string(ipstr);
	}

	/** Generate a stable 12-character ident using HMAC-SHA256 **/
	std::string GenerateIdent(const irc::sockets::sockaddrs& addr)
	{
		if (!sha256)
			throw ModuleException(this, "SHA256 module (hash/sha256) is missing!");

		// Normalize IP to ensure it's consistent across reconnects
		std::string normalized_ip = NormalizeIP(addr);

		// Compute HMAC-SHA256 of IP with secret key
		std::string raw_hash = sha256->hmac(secret_key, normalized_ip);
		std::ostringstream hex_stream;
		for (size_t i = 0; i < 6; i++)
		{
			hex_stream << std::hex << std::setw(2) << std::setfill('0') 
			           << (static_cast<unsigned char>(raw_hash[i]) & 0xFF);
		}

		return hex_stream.str();
	}

	void OnUserConnect(LocalUser* user) override
	{
		if (!IS_LOCAL(user))
			return;

		// Detect UNIX socket connection
		bool is_unix_socket = (user->client_sa.family() == AF_UNIX);

		// Retrieve <connect> block for this user
		std::shared_ptr<ConnectClass> connectClass = user->GetClass();
		if (!connectClass)
			return;

		// Check if "hashident" is enabled in <connect>
		if (connectClass->config->getBool("hashident", false))
		{
			std::string newident = is_unix_socket ? "unixsocket" : GenerateIdent(user->client_sa);
			user->ChangeDisplayedUser(newident);
		}
	}
};

MODULE_INIT(ModuleHashIdent)
