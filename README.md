# 1Pwned

CLI tool to check 1Password passwords against Have I Been Pwned.

## Why?

Tools like [1Password](https://1password.com/) are amazing and allow users have a different password for every website.

Tools like [Have I Been Pwned](https://haveibeenpwned.com) are amazing and give users the heads up when their passwords and data turn up in security breaches.

But what do you do when you receive a `You've been pwned` alert email, but you have hundreds of passwords associated with that single email address? How do you find out which website (1Password login) you need to rotate your password for ASAP?

This is a real life problem I faced which led me to building this little tool I call `1Pwned`

## Security

A few things you should do before blindly running this tool.

### Verify the code does what I say it does

You don't have to be a Python expert to do some basic checks in the source code, but please do look over it!

The repo only has a single external dependency in code: `requests` (of course it also depends on 1Password and 1Password's CLI tool `op` being installed on your machine).

If you search the code base for `requests.` to see where we're making network calls, you should be able to satisfy yourself that it's only in `fetch_hibp_suffixes` to call the Have I Been Pwned API (https://api.pwnedpasswords.com//range/{first-5-characters-of-your-hashed-password}).

Nothing is written to disk, and no code should be logging or printing your password EVER.

### Only run this on a machine you are certain is not compromised in any way

The 1Pwned tool will essentially decrypt every single password in your 1Password and these values will at some point be strings stored in memory while it runs. If you are even slightly concerned that your machine may not be secure, has malware etc. DO NOT RUN THIS SCRIPT!

### What this thing does...

1. Attempts to get a list of login items from 1Password via the 1Password `op` CLI tool (you will be prompted by 1Password about this)
2. For each item it builds a login object, any items with no password are ignored (since it defeats the purpose)
3. SHA1 hashes the login object's password
4. Sends only the first 5 characters of the hash (the suffix) to the Have I Been Pwned API
5. Checks the response to see if the suffix (the rest of the hashed password) is shown, if it's found the associated number of Pwns is returned
6. If the login is Pwned it's output (see example below)
7. Once we've checked them all, a summary of total checked, total Pwned is output

...

Then you go and manually change any passwords it flagged ASAP.

## Getting started

### Requirements

* [1Password desktop application](https://1password.com/downloads) (with an account, and if you want this to be useful some logins)
* [1Password CLI](https://1password.com/downloads/command-line)
* [uv](https://docs.astral.sh/uv/getting-started/installation/) the Python package and project manager
* A machine you consider safe to run things on

### 1Password CLI

Please read the [1Password CLI docs](https://developer.1password.com/docs/cli/get-started/ ) on how to enable the CLI integration with your 1Password desktop application.

### Running

1. Create a Python virtual environment using `uv`

```bash
uv venv
```

2. Sync the project dependencies

```bash
uv sync
```

(use the `--dev` flag to pull dev deps too - if you want to contribute to the project)

3. Run `1Pwned`

> [!NOTE]
> When you run the tool, you will get a popup from 1Password desktop application asking you to grant access to the CLI by entering your password!

```bash
uv run check_op_passwords.py
```

Your 1Password logins will now be iterated over and each one checked for pwnage, any matches will be output to the terminal as they are found.

```bash
[PWNED]      3 | 9f12a3 | Bluesky | user@example.com | https://bsky.app/
```

In the example above the columns represent the following:

* Pwnage Count - how many times the password hash was found
* 1Password ID (`9f12a3`) - useful if you want to use the 1Password CLI (`op`)
* 1Password title - the name you gave this entry in 1Password
* Email - the email you login with (this is mostly for visual verification/sanity checking)
* URL - the URL stored in 1Password where you can go to manually update the password

## Good Karma

If this tool is useful to you, please consider [donating to Have I Been Pwned](https://haveibeenpwned.com/Donate)

That's it. Stay safe, be kind.
