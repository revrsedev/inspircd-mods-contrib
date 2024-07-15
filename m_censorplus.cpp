/// $CompilerFlags: find_compiler_flags("icu-uc")
/// $LinkerFlags: find_linker_flags("icu-uc")
/// $CompilerFlags: find_compiler_flags("icu-i18n")
/// $LinkerFlags: find_linker_flags("icu-i18n")
/// $CompilerFlags: -I/usr/local/include
/// $LinkerFlags: -L/usr/local/lib -lhs

#include "inspircd.h"
#include "modules/exemption.h"
#include "numerichelper.h"
#include "utility/string.h"
#include <hs/hs.h> // Hyperscan
#include <unicode/regex.h>
#include <unicode/unistr.h>
#include <codecvt>
#include <locale>

typedef insp::flat_map<std::string, std::string, irc::insensitive_swo> CensorMap;

class ModuleCensor : public Module
{
private:
	CheckExemption::EventProvider exemptionprov;
	CensorMap censors;
	SimpleUserMode cu;
	SimpleChannelMode cc;
	std::unique_ptr<icu::RegexPattern> emoji_pattern;
	std::unique_ptr<icu::RegexPattern> kiwiirc_pattern;
	std::string whitelist_regex_str;

	hs_database_t* whitelist_db = nullptr;
	hs_scratch_t* scratch = nullptr;

	static int onMatch(unsigned int id, unsigned long long from, unsigned long long to, unsigned int flags, void* ctx) {
		bool* matched = (bool*)ctx;
		*matched = true;
		return 0;
	}

	bool CompileRegex(const std::string& pattern, hs_database_t** db) {
		hs_compile_error_t* compile_err;
		if (hs_compile(pattern.c_str(), HS_FLAG_UTF8 | HS_FLAG_UCP, HS_MODE_BLOCK, nullptr, db, &compile_err) != HS_SUCCESS) {
			ServerInstance->Logs.Normal(MODNAME, "Failed to compile regex pattern: %s", compile_err->message);
			hs_free_compile_error(compile_err);
			return false;
		}
		return true;
	}

	bool IsMatch(hs_database_t* db, const std::string& text) {
		bool matched = false;
		if (hs_scan(db, text.c_str(), text.length(), 0, scratch, onMatch, &matched) != HS_SUCCESS) {
			ServerInstance->Logs.Normal(MODNAME, "Hyperscan scan error");
		}
		return matched;
	}

	bool IsMixedUTF8(const std::string& text)
	{
		if (text.empty())
			return false;

		enum ScriptType { SCRIPT_UNKNOWN, SCRIPT_LATIN, SCRIPT_NONLATIN };
		ScriptType detected = SCRIPT_UNKNOWN;

		for (const auto& c : text)
		{
			if (static_cast<unsigned char>(c) < 128)
				continue; // ASCII characters are ignored

			if (std::isalpha(static_cast<unsigned char>(c)))
			{
				ScriptType current = std::islower(static_cast<unsigned char>(c)) || std::isupper(static_cast<unsigned char>(c)) ? SCRIPT_LATIN : SCRIPT_NONLATIN;
				if (detected == SCRIPT_UNKNOWN)
				{
					detected = current;
				}
				else if (detected != current)
				{
					return true; // Mixed scripts detected
				}
			}
		}

		return false;
	}

	bool IsEmojiOnly(const std::string& text)
	{
		UErrorCode status = U_ZERO_ERROR;
		icu::UnicodeString ustr(text.c_str(), "UTF-8");
		std::unique_ptr<icu::RegexMatcher> emoji_matcher(emoji_pattern->matcher(ustr, status));
		if (U_FAILURE(status))
		{
			ServerInstance->Logs.Normal(MODNAME, "Failed to create regex matcher for emojis: %s", u_errorName(status));
			return false;
		}

		// Check if the entire text is matched by the emoji pattern
		return emoji_matcher->matches(status);
	}

	bool IsKiwiIRCOnly(const std::string& text)
	{
		UErrorCode status = U_ZERO_ERROR;
		icu::UnicodeString ustr(text.c_str(), "UTF-8");
		std::unique_ptr<icu::RegexMatcher> kiwiirc_matcher(kiwiirc_pattern->matcher(ustr, status));
		if (U_FAILURE(status))
		{
			ServerInstance->Logs.Normal(MODNAME, "Failed to create regex matcher for KiwiIRC: %s", u_errorName(status));
			return false;
		}

		// Check if the entire text is matched by the KiwiIRC pattern
		return kiwiirc_matcher->matches(status);
	}

	bool IsAllowed(const std::string& text)
	{
		// Allow ASCII characters and common symbols by default
		if (std::all_of(text.begin(), text.end(), [](unsigned char c) { return c >= 32 && c <= 126; }))
		{
			return true;
		}

		// First, try to match the whitelist using Hyperscan
		if (IsMatch(whitelist_db, text))
			return true;

		// Then, try to match the text against emoji and KiwiIRC patterns using ICU
		return IsEmojiOnly(text) || IsKiwiIRCOnly(text);
	}

public:
	ModuleCensor()
		: Module(VF_NONE, "Allows the server administrator to define inappropriate phrases that are not allowed to be used in private or channel messages and blocks messages with mixed UTF-8 scripts, only allowing certain Unicode smileys.")
		, exemptionprov(this)
		, cu(this, "u_censor", 'G')
		, cc(this, "censor", 'G')
	{
	}

	void ReadConfig(ConfigStatus& status) override
	{
		CensorMap newcensors;
		for (const auto& [_, badword_tag] : ServerInstance->Config->ConfTags("badword"))
		{
			const std::string text = badword_tag->getString("text");
			if (text.empty())
				throw ModuleException(this, "<badword:text> is empty! at " + badword_tag->source.str());

			const std::string replace = badword_tag->getString("replace");
			newcensors[text] = replace;
		}
		censors.swap(newcensors);

		const auto& tag = ServerInstance->Config->ConfValue("censorplus");
		std::string emoji_regex_str = tag->getString("emojiregex");
		whitelist_regex_str = tag->getString("whitelistregex");
		std::string kiwiirc_regex_str = tag->getString("kiwiircregex");

		UErrorCode icu_status = U_ZERO_ERROR;
		emoji_pattern = std::unique_ptr<icu::RegexPattern>(icu::RegexPattern::compile(icu::UnicodeString::fromUTF8(emoji_regex_str), 0, icu_status));
		if (U_FAILURE(icu_status))
		{
			throw ModuleException(this, INSP_FORMAT("Failed to compile emoji regex pattern: %s", u_errorName(icu_status)));
		}

		icu_status = U_ZERO_ERROR;
		kiwiirc_pattern = std::unique_ptr<icu::RegexPattern>(icu::RegexPattern::compile(icu::UnicodeString::fromUTF8(kiwiirc_regex_str), 0, icu_status));
		if (U_FAILURE(icu_status))
		{
			throw ModuleException(this, INSP_FORMAT("Failed to compile KiwiIRC regex pattern: %s", u_errorName(icu_status)));
		}

		// Compile Hyperscan databases
		if (!CompileRegex(whitelist_regex_str, &whitelist_db))
		{
			throw ModuleException(this, "Failed to compile whitelist regex pattern for Hyperscan");
		}

		if (hs_alloc_scratch(whitelist_db, &scratch) != HS_SUCCESS) {
			throw ModuleException(this, "Failed to allocate Hyperscan scratch space");
		}
	}

	ModResult OnUserPreMessage(User* user, MessageTarget& target, MessageDetails& details) override
	{
		if (!IS_LOCAL(user))
			return MOD_RES_PASSTHRU;

		// Allow IRC operators to bypass the restrictions
		if (user->IsOper())
			return MOD_RES_PASSTHRU;

		switch (target.type)
		{
		case MessageTarget::TYPE_USER:
		{
			User* targuser = target.Get<User>();
			if (!targuser->IsModeSet(cu))
				return MOD_RES_PASSTHRU;
			break;
		}

		case MessageTarget::TYPE_CHANNEL:
		{
			auto* targchan = target.Get<Channel>();
			if (!targchan->IsModeSet(cc))
				return MOD_RES_PASSTHRU;

			ModResult result = exemptionprov.Check(user, targchan, "censor");
			if (result == MOD_RES_ALLOW)
				return MOD_RES_PASSTHRU;
			break;
		}

		default:
			return MOD_RES_PASSTHRU;
		}

		if (IsMixedUTF8(details.text) || !IsAllowed(details.text))
		{
			const std::string msg = "Your message contained disallowed characters and was blocked. IRC operators have been notified (Spamfilter purpose).";

			// Announce to opers
			std::string oper_announcement;
			if (target.type == MessageTarget::TYPE_CHANNEL)
			{
				auto* targchan = target.Get<Channel>();
				oper_announcement = INSP_FORMAT("MixedCharacterUTF8: User %s in channel %s sent a message containing disallowed characters: '%s', which was blocked.", user->nick, targchan->name, details.text);
				ServerInstance->SNO.WriteGlobalSno('a', oper_announcement);
				user->WriteNumeric(Numerics::CannotSendTo(targchan, msg));
			}
			else
			{
				auto* targuser = target.Get<User>();
				oper_announcement = INSP_FORMAT("MixedCharacterUTF8: User %s sent a private message to %s containing disallowed characters: '%s', which was blocked.", user->nick, targuser->nick, details.text);
				ServerInstance->SNO.WriteGlobalSno('a', oper_announcement);
				user->WriteNumeric(Numerics::CannotSendTo(targuser, msg));
			}
			return MOD_RES_DENY;
		}

		for (const auto& [find, replace] : censors)
		{
			size_t censorpos;
			while ((censorpos = irc::find(details.text, find)) != std::string::npos)
			{
				if (replace.empty())
				{
					const std::string msg = INSP_FORMAT("Your message to this channel contained a banned phrase (%s) and was blocked. IRC operators have been notified (Spamfilter purpose).", find);

					// Announce to opers
					std::string oper_announcement;
					if (target.type == MessageTarget::TYPE_CHANNEL)
					{
						auto* targchan = target.Get<Channel>();
						oper_announcement = INSP_FORMAT("CensorPlus: User %s in channel %s sent a message containing banned phrase (%s): '%s', which was blocked.", user->nick, targchan->name, find, details.text);
					}
					else
					{
						auto* targuser = target.Get<User>();
						oper_announcement = INSP_FORMAT("CensorPlus: User %s sent a private message to %s containing banned phrase (%s): '%s', which was blocked.", user->nick, targuser->nick, find, details.text);
					}
					ServerInstance->SNO.WriteGlobalSno('a', oper_announcement);

					if (target.type == MessageTarget::TYPE_CHANNEL)
						user->WriteNumeric(Numerics::CannotSendTo(target.Get<Channel>(), msg));
					else
						user->WriteNumeric(Numerics::CannotSendTo(target.Get<User>(), msg));
					return MOD_RES_DENY;
				}

				details.text.replace(censorpos, find.size(), replace);
			}
		}
		return MOD_RES_PASSTHRU;
	}
};

MODULE_INIT(ModuleCensor)
