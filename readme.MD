# Steam Account Checker

```
  ███████╗████████╗███████╗ █████╗ ███╗   ███╗
  ██╔════╝╚══██╔══╝██╔════╝██╔══██╗████╗ ████║
  ███████╗   ██║   █████╗  ███████║██╔████╔██║
  ╚════██║   ██║   ██╔══╝  ██╔══██║██║╚██╔╝██║
  ███████║   ██║   ███████╗██║  ██║██║ ╚═╝ ██║
  ╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝
                   Steam Checker  v2.0
                      + Game Library
```

A fast, multi-threaded **Steam account checker** written in pure Python that authenticates against the new Steam API (no browser automation required) and displays detailed account info including a full **game library**, Steam level, country, VAC bans, and trade-ban status.

> ⚠️ **Disclaimer**  
> This tool is provided **for educational and personal account-recovery purposes only**.  
> Using it on accounts you do not own is illegal and violates the Steam Subscriber Agreement.  
> The author assumes **no responsibility** for misuse.

---

## ✨ Features

- 🔐 **Native Steam API auth flow** — RSA password encryption, no Selenium / browser needed
- 🛡️ **Steam Guard detection** — detects Mobile / Email 2FA automatically
- 🎮 **Full game library display** — game names, App IDs, playtime, sorted by hours played
- ⭐ **Notable games highlighting** — CS2, Dota 2, Rust, PUBG, Elden Ring, Cyberpunk 2077, and more
- 📊 **Account profiling** — Steam level, country, persona name, VAC bans, trade ban, limited status
- 🚀 **Multi-threaded bulk checking** — configurable worker count & request delay
- 🌐 **Proxy support** — direct, single residential, or rotating proxy list
- 💾 **Auto-saves hits** to `hits.txt` with full game inventories
- 🎨 **Beautiful CLI** powered by [Rich](https://github.com/Textualize/rich)
- 🪶 **Zero external auth dependencies** — pure-Python RSA implementation

---

## 📦 Requirements

- **Python 3.8+**
- [`rich`](https://pypi.org/project/rich/) — for terminal UI

Install dependency:

```bash
pip install rich
```

---

## 🚀 Installation

```bash
git clone https://github.com/realsunil/steam_checker.git
cd steam-account-checker
pip install rich
python steam_checker.py
```

---

## 📁 Project Structure

```
steam-account-checker/
├── steam_checker.py     # Main script
├── combo.txt            # Your username:password list (you create this)
├── hits.txt             # Auto-generated: successful hits + game libraries
├── .steam_cfg.json      # Auto-generated: saved settings
└── LICENSE
```

---

## 🛠️ Usage

### 1. Launch the tool

```bash
python steam_checker.py
```

You'll see the main menu:

```
  1. Check combo file
  2. Check single account
  3. Settings
  0. Exit
```

### 2. Create a combo file

Create `combo.txt` in the same directory, one account per line:

```
username1:password1
username2:password2
username3:password3
```

Lines starting with `#` and empty lines are ignored.

### 3. Choose an option

- **`1`** → Check the entire combo file
- **`2`** → Check a single `username:password`
- **`3`** → Open settings menu

---

## ⚙️ Settings

Access via menu option `3`. All settings persist in `.steam_cfg.json`.

| Setting          | Description                                                   | Default     |
|------------------|---------------------------------------------------------------|-------------|
| **Workers**      | Number of parallel checking threads                           | `5`         |
| **Timeout**      | HTTP request timeout in seconds                               | `20`        |
| **Proxy mode**   | `direct` / `residential` / `list`                             | `direct`    |
| **Proxy URL**    | Single proxy (used when mode = `residential`)                 | *(empty)*   |
| **Proxy list**   | Path to file with one proxy per line (mode = `list`)          | *(empty)*   |
| **Check delay**  | Delay between submitting each check (anti-rate-limit)         | `1.0s`      |
| **Show games**   | Display full game library for hits                            | `yes`       |
| **Max games**    | How many games to show per account in the terminal            | `20`        |

### Proxy formats supported

```
http://user:pass@host:port
host:port:user:pass
host:port
```

### Proxy list file example

```
http://user:pass@proxy1.example.com:8080
http://user:pass@proxy2.example.com:8080
1.2.3.4:8080:myuser:mypass
```

---

## 📤 Output

### Terminal

Hits are color-coded:
- 🟢 **Green HIT** — account has value (games / level)
- 🟡 **Yellow HIT** — account valid but empty / Steam Guard locked
- 🔴 **BAD** — invalid credentials
- 🟡 **ERR** — network / rate-limit / other error

For each hit, you'll see:

```
HIT  user:pass  →  Guard = None | Country = US | Level = 23 | Games = 47 | VACBans = 0 | Tradeban = false | Limited = false
```

Followed by a rich table of all games, sorted by playtime, with notable titles starred ⭐.

### `hits.txt`

Auto-saved to disk, split into two sections:

```
----------- No Value -----------
1. user1:pass1 | Guard = Email | Country = N/A | Level = N/A | ...

----------- Has Value -----------
1. user2:pass2 | Guard = None | Country = US | Level = 23 | Games = 47 | ...
   Games (47 total):
       1. Counter-Strike 2 ⭐  [1,243h]
       2. Dota 2 ⭐  [892h]
       3. Rust ⭐  [340h]
       ...
```

---

## 🔍 How It Works

The script implements Steam's modern web auth API directly:

1. **Seed cookie** → `GET store.steampowered.com/login/`
2. **Fetch RSA key** → `GetPasswordRSAPublicKey`
3. **Encrypt password** → PKCS#1 v1.5 (pure-Python, no `cryptography` lib needed)
4. **Begin session** → `BeginAuthSessionViaCredentials`
   - EResult `5` / `18` → invalid creds → **BAD**
   - Guard type `2`/`3`/`4` → 2FA active → **HIT (locked)**
5. **Poll for token** → `PollAuthSessionStatus` → `access_token`
6. **Fetch profile data**:
   - `IPlayerService/GetOwnedGames` → game count + names + playtime
   - `IPlayerService/GetSteamLevel` → level
   - `ISteamUser/GetPlayerSummaries` → country, persona
   - `ISteamUser/GetPlayerBans` → VAC / trade bans

---

## 🎯 Notable Games Detected

The checker highlights these popular titles when found in a library:

CS2 · Dota 2 · TF2 · PUBG · Rust · Apex Legends · Elden Ring · Cyberpunk 2077 · The Witcher 3 · Call of Duty HQ · Rainbow Six Siege · Dead by Daylight · Black Ops III · PAYDAY 2 · ARK · Stardew Valley · Borderlands 2 · Terraria · Portal · Portal 2

Edit the `_NOTABLE_GAMES` dictionary in `steam_checker.py` to add your own.

---

## 🐛 Troubleshooting

| Issue                                | Fix                                                                   |
|--------------------------------------|-----------------------------------------------------------------------|
| `ModuleNotFoundError: rich`          | Run `pip install rich`                                                |
| Tons of `ERROR rate-limited`         | Increase **Check delay**, lower **Workers**, or use proxies           |
| All accounts return `BAD`            | Steam may be IP-blocking — switch to residential proxies              |
| `Proxy file not found`               | Check the path in Settings → Proxy list                               |
| Games not showing                    | Enable **Show games** in Settings (option 7)                          |

---

## 📜 License

This project is released under the MIT License — see [`LICENSE`](LICENSE) for details.

---

## 🤝 Contributing

Pull requests are welcome! Feel free to:
- Add more notable game IDs
- Improve error handling
- Add export formats (CSV / JSON)
- Implement Steam Guard code submission flow

---

## ⭐ Show Your Support

If this tool helped you, give the repo a star — it really helps!
