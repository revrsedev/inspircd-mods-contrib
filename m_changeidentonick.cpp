#include "inspircd.h"

class CommandSetNickIdent : public Command
{
public:
	CommandSetNickIdent(Module* Creator)
		: Command(Creator, "SETNICKIDENT", 1)
	{
		access_needed = CmdAccess::OPERATOR;
		syntax = { "<username>" };
	}

	CmdResult Handle(User* user, const Params& parameters) override
	{
		const size_t max_ident_length = 12;  // Typical maximum length for ident in IRC
		const std::string& ident = parameters[0];

		if (ident.size() > max_ident_length)
		{
			user->WriteNotice("*** SETNICKIDENT: Username is too long");
			return CmdResult::FAILURE;
		}

		for (char c : ident)
		{
			if (!isalnum(c) && c != '-' && c != '_')
			{
				user->WriteNotice("*** SETNICKIDENT: Invalid characters in username");
				return CmdResult::FAILURE;
			}
		}

		user->ChangeDisplayedUser(ident);
		ServerInstance->SNO.WriteGlobalSno('a', "{} used SETNICKIDENT to change their username to '{}'", user->nick, ident);

		return CmdResult::SUCCESS;
	}
};

class ModuleSetNickIdent : public Module
{
private:
	CommandSetNickIdent cmd;

public:
	ModuleSetNickIdent()
		: Module(VF_VENDOR, "Sets the user's ident to match their nickname on connect.")
		, cmd(this)
	{
	}

	void OnUserConnect(LocalUser* user) override
	{
		if (IS_LOCAL(user))
		{
			std::string newident = user->nick;
			const size_t max_ident_length = 12;

			if (newident.size() > max_ident_length)
				newident.resize(max_ident_length);

			user->ChangeDisplayedUser(newident);
		}
	}
};

MODULE_INIT(ModuleSetNickIdent)
