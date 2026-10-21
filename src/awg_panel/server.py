"""HTTPS server (stdlib only): routing, sessions, HTML rendering."""
from __future__ import annotations

import concurrent.futures
import base64
import datetime
import hmac
import html
import ipaddress
import re
import ssl
import sys
import threading
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import __version__
from .auth import AuthStore
from .config import PanelConfig, update_user_password
from .manage import (
    cmd_add,
    cmd_awg_restart,
    cmd_check,
    cmd_list,
    cmd_reboot_host,
    cmd_regen,
    cmd_remove,
    cmd_stats,
    run_helper,
)
from .system_info import cpu_pct, disk_usage, fmt_bytes, load_avg, mem_info, net_dev, uptime_str
from .validate import expires_flag, parse_names, valid_client_name

CSS = '<link rel="stylesheet" href="/static/style.css">'

# Cap form bodies to avoid OOM on huge POSTs.
MAX_FORM_BYTES = 1 << 20  # 1 MiB
# Cap batch sizes: 1 MiB of `sel=` is ~50k names -> ARG_MAX/fork-DoS.
MAX_SEL = 100
# Cap number of form fields (a=1&a=1... CPU/RAM-DoS).
MAX_FORM_FIELDS = 2000
# Cap helper payloads kept in memory / sent back (QR/conf/uri).
MAX_HELPER_BYTES = 2 << 20  # 2 MiB
# Bound on waiting for manage/helper futures (their own timeouts are
# 15-120s; without this an authed client holds handler threads forever).
FUT_TIMEOUT = 40


def e(s) -> str:
    return html.escape(str(s), quote=True)


def hmac_eq(a, b) -> bool:
    try:
        return hmac.compare_digest(str(a or "").encode("utf-8"), str(b or "").encode("utf-8"))
    except Exception:
        return False


def fmt_exp(exp) -> str:
    if exp is None:
        return "бессрочно"
    try:
        ts = int(exp)
        dt = datetime.datetime.fromtimestamp(ts).strftime("%d.%m.%Y")
    except (TypeError, ValueError, OverflowError, OSError):
        return "?"
    left = (ts - datetime.datetime.now().timestamp()) / 86400
    if left < 0:
        return f"{dt} (истёк)"
    return f"{dt} (осталось {int(left)} дн.)"


def fmt_hs(hs) -> str:
    try:
        ts = int(hs)
    except (TypeError, ValueError):
        return "никогда"
    if not ts:
        return "никогда"
    try:
        return datetime.datetime.fromtimestamp(ts).strftime("%d.%m.%Y %H:%M")
    except (ValueError, OverflowError, OSError):
        return "?"


# ---------- clients sorting (0.1.18+) ----------
# Sort keys for /clients?sort=<key>&dir=<asc|desc>.
CLIENT_SORT_KEYS = ("name", "ip", "status", "traffic", "expires")

# Status order: active first, errors/unknown last. Unknown codes -> 99.
_STATUS_RANK = {
    "active": 0,
    "recent": 1,
    "no_handshake": 2,
    "inactive": 2,
    "no_data": 3,
    "key_error": 4,
}


def _ip_sort_key(ip) -> tuple:
    s = str(ip or "").strip()
    if not s or s in ("?", "-", "none"):
        return (1, "")
    try:
        return (0, int(ipaddress.ip_address(s)))
    except ValueError:
        return (1, s.lower())


def _status_rank(c: dict) -> int:
    try:
        code = str(c.get("status_code", "") or "").strip()
    except Exception:
        code = ""
    return _STATUS_RANK.get(code, 99 if code else 99)


def _traffic_total(name, stats_map: dict) -> int:
    try:
        s = stats_map.get(name)
        if not isinstance(s, dict):
            return 0
        rx = s.get("rx", 0) or 0
        tx = s.get("tx", 0) or 0
        return int(rx) + int(tx)
    except (TypeError, ValueError):
        return 0


def _expires_key(c: dict):
    exp = c.get("expires_at")
    if exp is None:
        return float("inf")
    try:
        return int(exp)
    except (TypeError, ValueError):
        return float("inf")


def sort_clients(clients: list, stats_map: dict, sort: str = "name",
                 direction: str = "asc") -> list:
    """Sort clients list for /clients table. Invalid sort/dir -> name/asc.

    Tiebreaker is always name asc (stable sort: name first, then primary).
    """
    if sort not in CLIENT_SORT_KEYS:
        sort = "name"
    reverse = direction == "desc"
    items = [c for c in (clients or []) if isinstance(c, dict)]
    # Tiebreaker: name asc first (stable sort keeps it for equal primaries).
    items = sorted(items, key=lambda c: str(c.get("name", "") or "").lower())
    if sort == "name":
        if reverse:
            items.reverse()
        return items
    if sort == "ip":
        return sorted(items, key=lambda c: _ip_sort_key(c.get("ip")), reverse=reverse)
    if sort == "status":
        return sorted(items, key=lambda c: (_status_rank(c),
                                            str(c.get("status", "") or "").lower(),
                                            str(c.get("name", "") or "").lower()),
                      reverse=reverse)
    if sort == "traffic":
        return sorted(items, key=lambda c: _traffic_total(c.get("name"), stats_map or {}),
                      reverse=reverse)
    if sort == "expires":
        return sorted(items, key=lambda c: (_expires_key(c),
                                            str(c.get("name", "") or "").lower()),
                      reverse=reverse)
    return items


def _schedule_reboot(delay_sec: float = 2.0) -> None:
    """Reboot the host after a short delay (lets the HTTP response flush).

    Uses systemctl reboot via manage.cmd_reboot_host in a daemon thread:
    reboot kills this process, so the caller must respond immediately.
    """

    def _do():
        try:
            time.sleep(delay_sec)
            r = cmd_reboot_host()
            if not r.ok:
                sys.stderr.write(f"awg-panel: reboot failed rc={r.rc}: {(r.stderr or '')[-500:]}\n")
        except Exception as ex:
            sys.stderr.write(f"awg-panel: reboot thread failed: {ex}\n")

    threading.Thread(target=_do, daemon=True, name="awg-reboot").start()


class Handler(BaseHTTPRequestHandler):
    server_version = f"awg-panel/{__version__}"
    cfg: PanelConfig = PanelConfig()  # set by main()
    auth: AuthStore = None  # set by main()
    # Per-connection socket timeout: bounds slow-body/slowloris reads
    # (rfile.read with fake Content-Length no longer hangs a thread forever).
    timeout = 10

    # ---------- helpers ----------
    def log_message(self, *a):  # quieter: errors to stderr, successful hits silenced
        try:
            code = int(str(a[1])) if len(a) > 1 else 0
        except (TypeError, ValueError):
            code = 0
        if code >= 400 or code == 0:
            sys.stderr.write(f"awg-panel: {self.client_address[0]} {a[0] if a else ''}\n")

    def _cookie_sid(self) -> str | None:
        c = self.headers.get("Cookie", "")
        try:
            mors = cookies.SimpleCookie(c)
            return mors.get("awgpanel").value if "awgpanel" in mors else None
        except Exception:
            return None

    def _sess(self):
        sid = self._cookie_sid()
        if not sid or not isinstance(sid, str) or len(sid) > 256:
            return None
        return self.auth.get(sid) if sid else None

    def _client_ip(self) -> str:
        # Direct connections only (no trusted reverse proxy): never trust
        # X-Forwarded-For — it is client-controlled and would let anyone
        # bypass the login rate-limit and forge auth.log entries.
        return self.client_address[0]

    def _send(self, code: int, body: str | bytes, ctype="text/html; charset=utf-8", extra=None,
                no_store: bool = True):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy",
                         "default-src 'self'; img-src 'self' data:; "
                         "style-src 'self' 'unsafe-inline'; script-src 'self'")
        self.send_header("Strict-Transport-Security", "max-age=31536000")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        if no_store:
            self.send_header("Cache-Control", "no-store")
            self.send_header("Pragma", "no-cache")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _send_auth(self, code: int, body: str | bytes, ctype="text/html; charset=utf-8",
                   extra=None, no_store: bool = True):
        """Same as _send but refreshes the session cookie (sliding expiry).

        AuthStore.get() extends server-side expiry on every request; without
        re-issuing Max-Age the browser would drop the cookie while the server
        still considers the session valid.
        """
        s = getattr(self, "_authed", None)
        extra = dict(extra or {})
        if s is not None:
            extra["Set-Cookie"] = self._set_session_cookie(s.sid)
        return self._send(code, body, ctype, extra, no_store)

    def _redirect(self, where: str, cookie: str | None = None):
        h = {"Location": where}
        if cookie is not None:
            h["Set-Cookie"] = cookie
        self._send(303, "", extra=h)

    def _set_session_cookie(self, sid: str | None) -> str:
        if sid:
            return f"awgpanel={sid}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age={self.cfg.session_ttl_min*60}"
        return "awgpanel=expired; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0"

    def _require_auth(self):
        s = self._sess()
        if not s:
            self._redirect("/login")
            return None
        self._authed = s
        return s

    def _parse_form(self) -> dict:
        try:
            n = int(self.headers.get("Content-Length", 0) or 0)
        except (TypeError, ValueError):
            n = 0
        if n < 0:
            n = 0
        if n > MAX_FORM_BYTES:
            # Close the connection: leftover bytes would otherwise be parsed
            # as the next HTTP request on keep-alive (desync).
            self.close_connection = True
            raise ValueError("form too large")
        raw = self.rfile.read(n).decode("utf-8", "replace") if n else ""
        pairs = urllib.parse.parse_qsl(raw, keep_blank_values=True)
        if len(pairs) > MAX_FORM_FIELDS:
            self.close_connection = True
            raise ValueError("form too large")
        out = {}
        for k, v in pairs:
            if k in out:
                if isinstance(out[k], list):
                    out[k].append(v)
                else:
                    out[k] = [out[k], v]
            else:
                out[k] = v
        return out

    def _check_csrf(self, form) -> bool:
        s = self._sess()
        tok = form.get("csrf", "")
        if isinstance(tok, list):
            tok = tok[0] if tok else ""
        if not isinstance(tok, str) or not tok:
            return False
        return bool(s and hmac_eq(tok, s.csrf))

    # ---------- pages ----------
    def _layout(self, title: str, active: str, body: str, csrf: str = "", nav: bool = True) -> str:
        nav_links = "".join(
            f'<a href="{href}" class="{"on" if active==k else ""}">{label}</a>'
            for k, href, label in (("system", "/system", "Система"),
                                   ("clients", "/clients", "Клиенты"),
                                   ("help", "/help", "Справка"),
                                   ("support", "/support", "Поддержка"),
                                   ("password", "/password", "Сменить пароль")))
        if active == "logout" or csrf:
            logout = (f"<form method=post action=/logout class=navlogout>"
                      f"<input type=hidden name=csrf value='{e(csrf)}'>"
                      f"<button type=submit class='navlink{' on' if active=='logout' else ''}'>Выход</button></form>")
        else:
            logout = '<a href="/logout">Выход</a>'
        nav = (nav_links + logout) if nav else ""
        return ("<!doctype html><html lang=ru><head><meta charset=utf-8>"
                "<meta name=viewport content='width=device-width,initial-scale=1'>"
                f"<title>{e(title)} — AWG Panel</title>{CSS}</head>"
                f"<body><aside><div class=brand>AWG Panel<small>v{__version__}</small></div>"
                f"<nav>{nav}</nav></aside><main>{body}</main></body></html>")

    def _page_login(self, err=""):
        msg = f'<p class=err>{e(err)}</p>' if err else ""
        return self._layout("Вход", "", f"<div class=card style='max-width:420px'><h1>Вход</h1>{msg}"
                           "<form method=post action=/login>"
                           "<label>Логин<input name=user autofocus></label>"
                           "<label>Пароль<input type=password name=password></label>"
                           "<button>Войти</button></form>"
                           "<p class=muted>Доступ задаётся администратором сервера.</p></div>", nav=False)

    def _page_system(self, msg="") -> str:
        s = self._sess()
        csrf = s.csrf if s else ""
        m = f"<p class=ok>{e(msg)}</p>" if msg else ""
        body = (f"<h1>Система</h1>{m}"
                f"{self._system_block()}{self._interfaces_block()}"
                f"{self._awg_block()}{self._actions_block(csrf)}"
                f"{self._journal_block()}")
        return self._layout("Система", "system", body, csrf)

    def _page_system_confirm(self, kind: str) -> str:
        s = self._sess()
        csrf = s.csrf if s else ""
        if kind == "reboot":
            title = "Перезагрузка сервера"
            text = "Перезагрузка сервера: Вы уверены?"
            action = "/system/reboot"
        else:
            title = "Перезапуск AWG"
            text = "Перезапуск AWG: Вы уверены?"
            action = "/system/awg-restart"
        return self._layout(title, "system",
            "<div class=card style='max-width:520px'>"
            f"<h1>{e(title)}</h1><p>{e(text)}</p>"
            "<div class=row>"
            f"<form method=post action={action}><input type=hidden name=csrf value='{e(csrf)}'>"
            "<button>Подтвердить</button></form> "
            "<a class=btn href=/system>Отмена</a></div>"
            "<p class=muted>Подтверждение защищает от случайного нажатия. "
            "Перезагрузка сервера разорвёт текущую сессию.</p></div>", csrf)

    def _page_logout(self) -> str:
        s = self._sess()
        csrf = s.csrf if s else ""
        return self._layout("Выход", "logout",
            "<div class=card style='max-width:420px'><h1>Выйти?</h1>"
            f"<form method=post action=/logout><input type=hidden name=csrf value='{e(csrf)}'>"
            "<button>Выйти</button></form>"
            "<p><a href=/system>Остаться</a></p></div>", csrf)

    def _page_password(self, err="") -> str:
        s = self._sess()
        csrf = s.csrf if s else ""
        msg = f'<p class=err>{e(err)}</p>' if err else ""
        body = (f"<h1>Сменить пароль</h1>{msg}"
                "<div class=card style='max-width:420px'>"
                "<form method=post action=/password>"
                f"<input type=hidden name=csrf value='{e(csrf)}'>"
                "<label>Старый пароль<input type=password name=old_password required></label>"
                "<label>Новый пароль<input type=password name=new_password required></label>"
                "<label>Новый пароль ещё раз<input type=password name=new_password2 required></label>"
                "<button>Сменить пароль</button>"
                "</form>"
                "<p class=muted>Изменяется пароль вашей учётной записи. "
                "Старый пароль должен совпадать с текущим.</p>"
                "<p><a class=btn href=/system>Отмена</a></p></div>")
        return self._layout("Сменить пароль", "password", body, csrf)

    def _page_password_confirm(self) -> str:
        s = self._sess()
        csrf = s.csrf if s else ""
        return self._layout("Сменить пароль — подтверждение", "password",
            "<div class=card style='max-width:520px'>"
            "<h1>Сменить пароль</h1>"
            "<p>Вы действительно хотите сменить пароль своей учётной записи?</p>"
            "<div class=row>"
            f"<form method=post action=/password/confirm><input type=hidden name=csrf value='{e(csrf)}'>"
            "<button>Подтвердить</button></form> "
            "<a class=btn href=/password>Отмена</a></div>"
            "<p class=muted>Подтверждение защищает от случайной смены пароля.</p></div>", csrf)

    def _page_help(self) -> str:
        s = self._sess()
        csrf = s.csrf if s else ""
        body = ("<h1>Справка</h1>"
                "<div class=card><p class=muted>В коммерческой версии внешние ссылки удалены. "
                "По вопросам работы панели — раздел «Поддержка».</p></div>"
                "<div class=stack>"
                "<div class=card>"
                "<h2>«Подробнее» по теме</h2>"
                "<p class=muted>Выберите раздел справочной системы:</p>"
                "<div class=row>"
                "<a class=btn href='/faq' style='flex:1'>FAQ по панели управления</a> "
                "<a class=btn href='/instructions' style='flex:1'>Инструкции для пользователей</a>"
                "</div></div></div>")
        return self._layout("Справка", "help", body, csrf)

    def _page_support(self) -> str:
        s = self._sess()
        csrf = s.csrf if s else ""
        body = ("<h1>Поддержка</h1>"
                "<div class=card>"
                "<p>Техническая поддержка коммерческой версии AWG Panel:</p>"
                "<p><a href='https://t.me/thrsnknwldgthtsntpwr' target=_blank rel=noopener>"
                "t.me/thrsnknwldgthtsntpwr</a></p>"
                "<p class=muted>Открывается в новой вкладке Telegram.</p></div>")
        return self._layout("Поддержка", "support", body, csrf)

    def _page_faq(self) -> str:
        s = self._sess()
        csrf = s.csrf if s else ""
        ICON_ADD = ('<svg width=16 height=16 viewBox="0 0 24 24" fill="none" stroke="currentColor" '
                    'stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle;margin-right:6px">'
                    '<path d="M16 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"></path>'
                    '<circle cx="8.5" cy="7" r="4"></circle><line x1="20" y1="8" x2="20" y2="14"></line>'
                    '<line x1="16" y1="20" x2="16" y2="20"></line></svg>')
        ICON_KEY = ('<svg width=16 height=16 viewBox="0 0 24 24" fill="none" stroke="currentColor" '
                    'stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle;margin-right:6px">'
                    '<path d="M21 2l-2 2m-7 7 7-7m-7 7l-2.93 2.93a1 1 0 0 1-1.41 0l-1.42-1.42a1 1 0 0 1 0-1.41l2.93-2.93a1 1 0 0 1 1.41 0l1.42 1.42a1 1 0 0 1 0 1.41z"></path>'
                    '<path d="M3 11l2 2m7.77 1.74L13 11.5l-1.42-1.42a1 1 0 0 1 0-1.41l2.93-2.93a1 1 0 0 1 1.41 0l1.42 1.42a1 1 0 0 1 0 1.41z"></path>'
                    '<path d="M12 12l2.93-2.93a1 1 0 0 1 1.41 0l1.42 1.42a1 1 0 0 1 0 1.41z"></path></svg>')
        ICON_POWER = ('<svg width=16 height=16 viewBox="0 0 24 24" fill="none" stroke="currentColor" '
                      'stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle;margin-right:6px">'
                      '<path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path>'
                      '<line x1="12" y1="19" x2="12" y2="23"></line><line x1="12" y1="14" x2="12" y2="18"></line></svg>')
        ICON_REFRESH = ('<svg width=16 height=16 viewBox="0 0 24 24" fill="none" stroke="currentColor" '
                        'stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle;margin-right:6px">'
                        '<path d="M1 4v6h6"></path><path d="M23 20v-6h-6"></path>'
                        '<path d="M20.49 9A9 9 0 0 0 5.64 5.64L1 10m22 4l-4.64 4.36A9 9 0 0 1 3.51 15"></path></svg>')
        ICON_DELETE = ('<svg width=16 height=16 viewBox="0 0 24 24" fill="none" stroke="currentColor" '
                       'stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle;margin-right:6px">'
                       '<polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path></svg>')
        ICON_ROTATE = ('<svg width=16 height=16 viewBox="0 0 24 24" fill="none" stroke="currentColor" '
                       'stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle;margin-right:6px">'
                       '<path d="M12 2a10 10 0 0 0-9 9v4a9 9 0 0 0 9 9h4a9 9 0 0 0 9-9v-4a9 9 0 0 0-9-9z"></path>'
                       '<circle cx="12" cy="12" r="3"></circle></svg>')
        faq_items = (
            ("Как добавить пользователя", ICON_ADD,
             "<p>Перейдите в раздел <b>Клиенты</b> → нажмите <b>Добавить</b> → укажите имена клиентов через пробел или запятую (например <i>ivan petr maria</i>) → при необходимости укажите срок действия в днях (пусто — бессрочно) → нажмите кнопку <b>Добавить</b>.</p>"
             "<p>После добавления клиент появится в таблице. Нажмите на его имя, чтобы скачать .conf, QR-код или получить vpn:// URI для импорта в приложение.</p>"),
            ("Как сменить пароль учётной записи", ICON_KEY,
             "<p>Перейдите в раздел <b>Сменить пароль</b> (последний пункт в боковом меню).</p>"
             "<p>Введите <b>старый пароль</b>, затем <b>новый пароль</b> и повторите его в поле <b>Новый пароль ещё раз</b>. Нажмите кнопку <b>Сменить пароль</b>.</p>"
             "<p>Появится окно подтверждения — нажмите <b>Подтвердить</b>. Пароль будет изменён для вашей текущей учётной записи и сохранён в конфиге сервера.</p>"),
            ("Как перезагрузить сервер", ICON_POWER,
             "<p>Перейдите в раздел <b>Система</b> → в блоке «Действия» нажмите ссылку <b>Перезагрузить сервер</b>.</p>"
             "<p>Появится окно подтверждения. Нажмите <b>Подтвердить</b>. Перезагрузка разорвёт текущую сессию, после чего потребуется войти повторно.</p>"),
            ("Как перезапустить AWG", ICON_REFRESH,
             "<p>Перейдите в раздел <b>Система</b> → в блоке «Действия» нажмите ссылку <b>Перезапустить awg</b>.</p>"
             "<p>Появится окно подтверждения. Нажмите <b>Подтвердить</b>. Выполняется команда systemctl restart awg-quick@awg0.</p>"),
            ("Как удалить клиента", ICON_DELETE,
             "<p>Перейдите в раздел <b>Клиенты</b> → поставьте галочку напротив имени клиента (или нескольких) → нажмите кнопку <b>Удалить выбранные</b>.</p>"
             "<p>Подтвердите удаление в появившемся окне. Конфиг и QR-код клиента будут удалены без возможности восстановления.</p>"),
            ("Как пересоздать ключи клиента (regen)", ICON_ROTATE,
             "<p>Откройте карточку клиента (раздел <b>Клиенты</b> → нажмите на имя) → нажмите кнопку <b>Пересоздать</b>.</p>"
             "<p>Новый ключ и конфиг будут сгенерированы. Старый конфиг клиента перестанет работать — обновите его в приложении.</p>"),
        )
        blocks = ""
        for title, icon, content in faq_items:
            blocks += (
                "<details class=faq style='margin-bottom:12px;border:1px solid #e2e8f0;border-radius:6px;overflow:hidden'>"
                "<summary style='padding:10px 14px;cursor:pointer;background:#f8fafc;font-weight:600'>" + icon + title + "</summary>"
                "<div style='padding:12px 16px'>" + content + "</div>"
                "</details>"
            )
        body = ("<h1>FAQ по панели управления</h1>"
                "<div class=card>" + blocks + "</div>")
        return self._layout("FAQ", "faq", body, csrf)

    def _page_instructions(self) -> str:
        s = self._sess()
        csrf = s.csrf if s else ""
        ICON_VPN = ('<svg width=16 height=16 viewBox="0 0 24 24" fill="none" stroke="currentColor" '
                    'stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle;margin-right:6px">'
                    '<path d="M3 10h18M3 10l1.333-4A1 1 0 0 1 5.333 4H18.667a1 1 0 0 1 1.002 2l-1.333 4A1 1 0 0 1 18.333 18H5.667a1 1 0 0 1-1-2z"></path>'
                    '<path d="M9 10l3 3-1 1m0 0l3 3m-3-3V10"></path></svg>')
        body = ("<h1>Инструкции для клиентов</h1>"
                "<div class=card>"
                "<p>Официальные инструкции по подключению к AWG:</p>"
                "<details class=acc style='margin-bottom:10px;border:1px solid #e2e8f0;border-radius:6px;overflow:hidden'>"
                "<summary style='padding:10px 14px;cursor:pointer;background:#f8fafc;font-weight:600'>" + ICON_VPN + "AmneziaVPN</summary>"
                "<div style='padding:12px 16px'>"
                "<div class=row>"
                "<a class=btn href='https://docs.amnezia.org/ru/documentation/instructions/connect-via-text-key/' target=_blank rel=noopener style='flex:1'>Подключение через ключ в виде текста</a>"
                "</div>"
                "<div class=row style='margin-top:8px'>"
                "<a class=btn href='https://docs.amnezia.org/ru/documentation/instructions/connect-via-config/' target=_blank rel=noopener style='flex:1'>Подключение через файл конфигурации</a>"
                "</div>"
                "<div class=row style='margin-top:8px'>"
                "<a class=btn href='https://docs.amnezia.org/ru/documentation/instructions/connect-via-qr-code/' target=_blank rel=noopener style='flex:1'>Подключение через QR-код</a>"
                "</div>"
                "</div></details>"
                "<details class=acc style='margin-bottom:10px;border:1px solid #e2e8f0;border-radius:6px;overflow:hidden'>"
                "<summary style='padding:10px 14px;cursor:pointer;background:#f8fafc;font-weight:600'>" + ICON_VPN + "AmneziaWG</summary>"
                "<div style='padding:12px 16px'>"
                "<div class=row>"
                "<a class=btn href='https://docs.amnezia.org/ru/documentation/instructions/use-amneziawg-app/' target=_blank rel=noopener style='flex:1'>Как использовать приложение AmneziaWG</a>"
                "</div>"
                "</div></details>"
                "</div>")
        return self._layout("Инструкции для клиентов", "instructions", body, csrf)

    def _system_block(self) -> str:
        try:
            mem = mem_info()
            la = load_avg()
            cpu = cpu_pct()
            disk = disk_usage("/")
        except Exception as ex:
            sys.stderr.write(f"awg-panel: system block failed: {ex}\n")
            return "<div class=card><h2>Система</h2><p class=err>Не удалось прочитать состояние сервера.</p></div>"
        return (f"<div class=card><h2>Система</h2><table>"
                f"<tr><th>Uptime</th><td>{e(uptime_str())}</td></tr>"
                f"<tr><th>Load</th><td>{e(la['l1'])} / {e(la['l5'])} / {e(la['l15'])} (CPU: {e(la['cpus'])})</td></tr>"
                f"<tr><th>CPU</th><td>{'—' if cpu is None else f'{e(cpu)} %'}</td></tr>"
                f"<tr><th>RAM</th><td>{e(fmt_bytes(mem['used_kb']*1024))} / {e(fmt_bytes(mem['total_kb']*1024))} ({e(mem['used_pct'])} %)</td></tr>"
                f"<tr><th>Диск /</th><td>{e(fmt_bytes(disk['used']))} / {e(fmt_bytes(disk['total']))} ({e(disk['pct'])} %)</td></tr>"
                f"</table><p class=muted>Источник: /proc (без выполнения manage).</p></div>")

    def _interfaces_block(self) -> str:
        try:
            nets = net_dev()
        except Exception as ex:
            sys.stderr.write(f"awg-panel: interfaces block failed: {ex}\n")
            return "<div class=card><h2>Интерфейсы</h2><p class=err>Не удалось прочитать интерфейсы.</p></div>"
        net_rows = "".join(
            f"<tr><td>{e(n['if'])}</td><td>{e(fmt_bytes(n['rx']))}</td><td>{e(fmt_bytes(n['tx']))}</td></tr>"
            for n in nets) or "<tr><td colspan=3>нет данных</td></tr>"
        return (f"<div class=card><h2>Интерфейсы</h2>"
                f"<table><tr><th>Iface</th><th>RX</th><th>TX</th></tr>{net_rows}</table>"
                f"<p class=muted>Счётчики с загрузки (/proc/net/dev), не скорость.</p></div>")

    def _actions_block(self, csrf: str) -> str:
        return ("<div class=card><h2>Действия</h2><div class=row>"
                "<a class=btn href='/system/reboot'>Перезагрузить сервер</a> "
                "<a class=btn href='/system/awg-restart'>Перезапустить awg</a></div>"
                "<p class=muted>Оба действия требуют подтверждения. "
                "Перезапуск awg = systemctl restart awg-quick@awg0.</p></div>")

    def _awg_block(self) -> str:
        try:
            r = cmd_check(self.cfg.manage_script)
            rc, init_raw, _ = run_helper(self.cfg.helper, "init-info")
        except ValueError as ex:
            sys.stderr.write(f"awg-panel: awg block failed: {ex}\n")
            return "<div class=card><h2>AWG</h2><p class=err>Внутренняя ошибка.</p></div>"
        except Exception as ex:
            sys.stderr.write(f"awg-panel: awg block failed: {ex}\n")
            return "<div class=card><h2>AWG</h2><p class=err>Не удалось получить статус AWG.</p></div>"
        proto = ver = "?"
        if rc == 0:
            for line in init_raw.decode("utf-8", "replace").splitlines():
                if line.startswith("AWG_PROTOCOL="):
                    proto = line.split("=", 1)[1]
                if line.startswith("SCRIPT_VERSION="):
                    ver = line.split("=", 1)[1]
        if not r.ok or not isinstance(r.data, dict):
            sys.stderr.write(f"awg-panel: manage check failed rc={r.rc}: {(r.stderr or '')[-500:]}\n")
            return (f"<div class=card><h2>AWG</h2><p class=err>Не удалось получить статус AWG (rc={r.rc}). "
                    f"Установщик: v{e(ver)}, поколение: {e(proto)}.</p>"
                    f"<p class=muted>Подробности — в журнале сервиса по SSH.</p></div>")
        d = r.data
        svc = d.get("service", {}) if isinstance(d.get("service", {}), dict) else {}
        iface = d.get("interface", {}) if isinstance(d.get("interface", {}), dict) else {}
        port = d.get("port", {}) if isinstance(d.get("port", {}), dict) else {}
        mod = d.get("module", {}) if isinstance(d.get("module", {}), dict) else {}
        fw = d.get("firewall", {}) if isinstance(d.get("firewall", {}), dict) else {}
        clients = d.get("clients", {}) if isinstance(d.get("clients", {}), dict) else {}
        rows = (
            ("Юнит", f"{svc.get('unit','?')} — {'active' if svc.get('active') else 'DOWN'}"),
            ("Интерфейс", f"awg0 present={iface.get('present')} mtu={iface.get('mtu')} addrs={iface.get('addresses')}"),
            ("Порт", f"{port.get('number')}/{port.get('proto')} listening={port.get('listening')}"),
            ("Модуль", f"loaded={mod.get('loaded')} version={mod.get('version')}"),
            ("Клиентов (peers)", clients.get("total", "?")),
            ("UFW", f"active={fw.get('ufw_active')} port_allowed={fw.get('port_allowed')} (панель не меняет)"),
            ("Поколение", d.get("protocol", proto)),
            ("Установщик", f"v{ver}"),
        )
        tr = "".join(f"<tr><th>{e(k)}</th><td>{e(v)}</td></tr>" for k, v in rows)
        ok = "<p class=ok>OK</p>" if d.get("ok") else "<p class=err>Есть проблемы — смотрите manage check по SSH</p>"
        return f"<div class=card><h2>AWG</h2>{ok}<table>{tr}</table><p class=muted>Источник: manage check --json + маркер AWG_PROTOCOL.</p></div>"

    def _journal_block(self) -> str:
        try:
            with open(self.cfg.auth_log, encoding="utf-8", errors="replace") as f:
                lines = f.read().strip().splitlines()[-10:]
        except OSError:
            return ""
        if not lines:
            return ""
        rows = "".join(f"<tr><td>{e(l)}</td></tr>" for l in reversed(lines))
        return f"<div class=card><h2>Журнал входов (последние)</h2><table>{rows}</table></div>"

    def _clients_table(self, clients: list, stats_map: dict, pubkeys: dict,
                       sort: str = "name", direction: str = "asc") -> str:
        if sort not in CLIENT_SORT_KEYS:
            sort = "name"
        if direction not in ("asc", "desc"):
            direction = "asc"

        def _link(field: str, label: str) -> str:
            if sort == field:
                ndir = "desc" if direction == "asc" else "asc"
                arrow = " ▲" if direction == "asc" else " ▼"
            else:
                ndir = "asc"
                arrow = ""
            return f"<a href='/clients?sort={field}&dir={ndir}'>{label}{arrow}</a>"

        rows = []
        for c in sort_clients(clients, stats_map, sort, direction):
            if not isinstance(c, dict):
                continue
            name = c.get("name", "?")
            ip = c.get("ip", "?")
            st = c.get("status", "?")
            code = c.get("status_code", "")
            cls = "ok" if code == "active" else ("warn" if code == "recent" else "muted")
            s = stats_map.get(name, {})
            traf = ""
            if isinstance(s, dict) and s:
                try:
                    traf = f"{fmt_bytes(s.get('rx',0))} / {fmt_bytes(s.get('tx',0))}"
                except Exception:
                    traf = "?"
            pk = pubkeys.get(name, "…")
            rows.append(
                f"<tr><td><input type=checkbox name=sel value='{e(name)}'></td>"
                f"<td><a href='/client?name={urllib.parse.quote(str(name))}'>{e(name)}</a></td>"
                f"<td>{e(ip)}</td><td class=mono>{e(pk)}</td>"
                f"<td class={cls}>{e(st)}</td><td>{e(traf)}</td>"
                f"<td>{e(fmt_exp(c.get('expires_at')))}</td></tr>")
        body = "".join(rows) or "<tr><td colspan=7>Клиентов нет</td></tr>"
        return (f"<table><tr><th></th><th>{_link('name', 'Имя')}</th><th>{_link('ip', 'IP')}</th>"
                f"<th>Ключ</th><th>{_link('status', 'Статус')}</th>"
                f"<th>{_link('traffic', 'RX / TX')}</th><th>{_link('expires', 'Срок')}</th></tr>{body}</table>")

    def _page_clients(self, msg="", sort="name", direction="asc") -> str:
        if sort not in CLIENT_SORT_KEYS:
            sort = "name"
        if direction not in ("asc", "desc"):
            direction = "asc"
        s = self._sess()
        csrf = s.csrf if s else ""
        # list/stats/helper run in parallel with an overall future timeout
        # so one hung manage call cannot hold handler threads forever.
        try:
            with ThreadPoolExecutor(max_workers=3) as ex:
                fl = ex.submit(cmd_list, self.cfg.manage_script)
                fs = ex.submit(cmd_stats, self.cfg.manage_script)
                fh = ex.submit(run_helper, self.cfg.helper, "server-pubkeys")
                rl = fl.result(timeout=FUT_TIMEOUT)
                rs = fs.result(timeout=FUT_TIMEOUT)
                _rc, pk_raw, _e = fh.result(timeout=FUT_TIMEOUT)
        except concurrent.futures.TimeoutError:
            sys.stderr.write("awg-panel: clients page future timeout\n")
            return self._layout("Клиенты", "clients",
                "<h1>Клиенты</h1><p class=err>Превышено время ожидания manage. Попробуйте позже.</p>", csrf)
        except ValueError as ex:
            sys.stderr.write(f"awg-panel: clients page failed: {ex}\n")
            return self._layout("Клиенты", "clients",
                "<h1>Клиенты</h1><p class=err>Внутренняя ошибка.</p>", csrf)
        clients = rl.data if rl.ok and isinstance(rl.data, list) else []
        stats_map = {}
        if rs.ok and isinstance(rs.data, list):
            stats_map = {x.get("name"): x for x in rs.data if isinstance(x, dict)}
        pubkeys = {}
        cur = ""
        for line in pk_raw.decode("utf-8", "replace").splitlines():
            line = line.strip()
            if line.startswith("#_Name = "):
                cur = line.split("=", 1)[1].strip()
            elif line.startswith("PublicKey = ") and cur:
                pubkeys[cur] = line.split("=", 1)[1].strip()[:10] + "…"
                cur = ""
        m = f"<p class={'ok' if rl.ok else 'err'}>{e(msg)}</p>" if msg else ""
        if not rl.ok:
            sys.stderr.write(f"awg-panel: manage list failed rc={rl.rc}: {(rl.stderr or '')[-500:]}\n")
            m += "<p class=err>Не удалось получить список клиентов. Подробности — в журнале сервиса.</p>"
        tbl = self._clients_table(clients, stats_map, pubkeys, sort, direction)
        return self._layout("Клиенты", "clients",
            f"<h1>Клиенты <span class=muted>({len(clients)})</span></h1>{m}"
            "<div class=card>"
            f"<form method=post action=/clients/add id=addf class=row>"
            f"<input type=hidden name=csrf value='{e(csrf)}'>"
            "<input name=names id=names placeholder='имена через пробел/запятую' required>"
            "<input name=days placeholder='дней (пусто=∞)' size=10 pattern='[0-9]*'>"
            f"<button type=button id=genbtn data-prefix='{e(self.cfg.client_name_prefix)}' "
            f"data-rand-bytes='{self.cfg.client_name_rand_bytes}'>Сгенерировать имя</button></form>"
            "<div class=row><button type=submit form=addf>Добавить</button> "
            "<button type=submit form=delf id=delbtn disabled>Удалить выбранные</button></div>"
            f"<form method=post action=/clients/delete id=delf><input type=hidden name=csrf value='{e(csrf)}'>"
            f"{tbl}</form>"
            "<p class=muted>Таблица = manage list --json (+stats, ключи из awg0.conf). "
            "Удаление множественное чекбоксами. Имя-ссылка → карточка. "
            "Удаление требует подтверждения.</p></div>" + CLIENTS_TAG, csrf)

    def _page_clients_delete_confirm(self, names: list[str]) -> str:
        s = self._sess()
        csrf = s.csrf if s else ""
        items = "".join(f"<tr><td>{e(n)}</td></tr>" for n in names)
        hidden = "".join(f"<input type=hidden name=sel value='{e(n)}'>" for n in names)
        return self._layout("Удаление пользователей", "clients",
            "<div class=card style='max-width:520px'>"
            "<h1>Удаление пользователей</h1>"
            "<p>Удаление пользователей: Вы уверены?</p>"
            f"<table>{items}</table>"
            "<div class=row>"
            f"<form method=post action=/clients/delete/confirm>"
            f"<input type=hidden name=csrf value='{e(csrf)}'>{hidden}"
            "<button>Подтвердить</button></form> "
            "<a class=btn href=/clients>Отмена</a></div>"
            "<p class=muted>Операция опасная: конфиги и QR выбранных клиентов будут удалены.</p></div>", csrf)

    def _page_client(self, name: str) -> str:
        s0 = self._sess()
        csrf0 = s0.csrf if s0 else ""
        if not valid_client_name(name):
            return self._layout("Клиент", "clients", "<p class=err>bad name</p>", csrf0)
        try:
            with ThreadPoolExecutor(max_workers=4) as ex:
                fl = ex.submit(cmd_list, self.cfg.manage_script)
                fs = ex.submit(cmd_stats, self.cfg.manage_script)
                f1 = ex.submit(run_helper, self.cfg.helper, "client-conf", name)
                f2 = ex.submit(run_helper, self.cfg.helper, "client-uri", name)
                rl = fl.result(timeout=FUT_TIMEOUT)
                rs = fs.result(timeout=FUT_TIMEOUT)
                rc1, conf, _e1 = f1.result(timeout=FUT_TIMEOUT)
                rc2, uri, _e2 = f2.result(timeout=FUT_TIMEOUT)
        except concurrent.futures.TimeoutError:
            sys.stderr.write("awg-panel: client page future timeout\n")
            return self._layout(name, "clients", "<p class=err>Превышено время ожидания. Попробуйте позже.</p>", csrf0)
        except ValueError as ex:
            sys.stderr.write(f"awg-panel: client page failed: {ex}\n")
            return self._layout(name, "clients", "<p class=err>Внутренняя ошибка.</p>", csrf0)
        if len(conf) > MAX_HELPER_BYTES or len(uri) > MAX_HELPER_BYTES:
            sys.stderr.write("awg-panel: helper payload too large\n")
            return self._layout(name, "clients", "<p class=err>Файл клиента слишком большой.</p>", csrf0)
        info = {}
        if rl.ok and isinstance(rl.data, list):
            info = next((c for c in rl.data if isinstance(c, dict) and c.get("name") == name), {})
        st = next((c for c in (rs.data if rs.ok and isinstance(rs.data, list) else [])
                   if isinstance(c, dict) and c.get("name") == name), {})
        conf_txt = conf.decode("utf-8", "replace") if rc1 == 0 else "(нет .conf — regen?)"
        uri_txt = uri.decode("utf-8", "replace").strip() if rc2 == 0 else ""
        try:
            traf = f"{fmt_bytes(st.get('rx',0))} / {fmt_bytes(st.get('tx',0))}" if st else "—"
        except Exception:
            traf = "?"
        hs_s = fmt_hs(st.get("last_handshake", 0)) if st else "никогда"
        return self._layout(name, "clients",
            f"<h1><a href=/clients>Клиенты</a> / {e(name)}</h1>"
            "<div class=stack>"
            f"<div class=card><h2>Пир</h2><table>"
            f"<tr><th>IP</th><td>{e(info.get('ip','?'))} {e(info.get('client_ipv6','') or '')}</td></tr>"
            f"<tr><th>Статус</th><td>{e(info.get('status','?'))}</td></tr>"
            f"<tr><th>Срок</th><td>{e(fmt_exp(info.get('expires_at')))}</td></tr>"
            f"<tr><th>Трафик RX/TX</th><td>{e(traf)}</td></tr>"
            f"<tr><th>Handshake</th><td>{e(hs_s)}</td></tr>"
            "</table>"
            "<div class=actions>"
            f"<form method=post action=/clients/regen><input type=hidden name=csrf value='{e(csrf0)}'>"
            f"<input type=hidden name=sel value='{e(name)}'><button>Пересоздать</button></form>"
            f"<a class=btn href='/download?name={urllib.parse.quote(name)}&type=conf'>Скачать .conf</a> "
            f"<a class=btn target=_blank rel=noopener href='/client-qr?name={urllib.parse.quote(name)}'>QR.png</a></div></div>"
            f"<div class=card><h2>Конфиг</h2><pre class=conf id=conf-pre>{e(conf_txt)}</pre>"
            "<div class=actions><button type=button data-src=conf-pre>Скопировать</button></div></div>"
            + (f"<div class=card><h2>vpn://</h2><pre class=wrap id=vpn-pre>{e(uri_txt)}</pre>"
               "<div class=actions><button type=button data-src=vpn-pre>Скопировать</button></div></div>" if uri_txt else "")
            + (f"<div class=card><h2>QR</h2><img src='/client-qr?name={urllib.parse.quote(name)}' alt=QR style='max-width:260px'></div>"
               if rc1 == 0 else "")
            + "</div>" + COPY_TAG, csrf0)

    # ---------- HTTP verbs ----------
    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        q = urllib.parse.parse_qs(u.query)
        if u.path in ("/",):
            return self._redirect("/system")
        if u.path == "/static/style.css":
            return self._send(200, STYLE_CSS, "text/css; charset=utf-8",
                              extra={"Cache-Control": "max-age=3600"}, no_store=False)
        if u.path == "/static/copy.js":
            return self._send(200, COPY_JS, "application/javascript; charset=utf-8",
                              extra={"Cache-Control": "max-age=3600"}, no_store=False)
        if u.path == "/static/clients.js":
            return self._send(200, CLIENTS_JS, "application/javascript; charset=utf-8",
                              extra={"Cache-Control": "max-age=3600"}, no_store=False)
        if u.path == "/login":
            return self._send(200, self._page_login())
        if u.path == "/logout":
            # GET never destroys the session (logout-CSRF): shows confirmation,
            # real logout is POST /logout with CSRF. Unauthed users go to login.
            s = self._sess()
            if not s:
                return self._redirect("/login")
            self._authed = s
            return self._send_auth(200, self._page_logout())
        s = self._require_auth()
        if not s:
            return
        if u.path == "/status":
            # Backward compat: old nav/URL renamed to /system (0.1.18+).
            return self._redirect("/system")
        if u.path == "/system":
            return self._send_auth(200, self._page_system())
        if u.path == "/system/reboot":
            return self._send_auth(200, self._page_system_confirm("reboot"))
        if u.path == "/system/awg-restart":
            return self._send_auth(200, self._page_system_confirm("awg-restart"))
        if u.path == "/help":
            return self._send_auth(200, self._page_help())
        if u.path == "/faq":
            return self._send_auth(200, self._page_faq())
        if u.path == "/instructions":
            return self._send_auth(200, self._page_instructions())
        if u.path == "/support":
            return self._send_auth(200, self._page_support())
        if u.path == "/password":
            return self._send_auth(200, self._page_password())
        if u.path == "/clients":
            sort = (q.get("sort", ["name"])[0] or "name")
            direction = (q.get("dir", ["asc"])[0] or "asc")
            if sort not in CLIENT_SORT_KEYS:
                sort = "name"
            if direction not in ("asc", "desc"):
                direction = "asc"
            return self._send_auth(200, self._page_clients("", sort, direction))
        if u.path == "/client":
            return self._send_auth(200, self._page_client(q.get("name", [""])[0]))
        if u.path == "/client-qr":
            name = q.get("name", [""])[0]
            if not valid_client_name(name):
                return self._send_auth(400, "bad name", "text/plain")
            try:
                rc, data, _err = run_helper(self.cfg.helper, "client-qr", name)
            except ValueError:
                return self._send_auth(400, "bad name", "text/plain")
            if rc != 0:
                return self._send_auth(404, "not found", "text/plain")
            if len(data) > MAX_HELPER_BYTES:
                return self._send_auth(413, "too large", "text/plain")
            return self._send_auth(200, data, "image/png")
        if u.path == "/download":
            name = q.get("name", [""])[0]
            typ = q.get("type", ["conf"])[0]
            if not valid_client_name(name) or typ not in ("conf", "vpnuri"):
                return self._send_auth(400, "bad request", "text/plain")
            act = "client-conf" if typ == "conf" else "client-uri"
            try:
                rc, data, _err = run_helper(self.cfg.helper, act, name)
            except ValueError:
                return self._send_auth(400, "bad request", "text/plain")
            if rc != 0:
                return self._send_auth(404, "not found", "text/plain")
            if len(data) > MAX_HELPER_BYTES:
                return self._send_auth(413, "too large", "text/plain")
            fn = f"{name}.{'conf' if typ=='conf' else 'vpnuri.txt'}"
            return self._send_auth(200, data, "application/octet-stream",
                              {"Content-Disposition": f"attachment; filename=\"{fn}\"; filename*=UTF-8''{urllib.parse.quote(fn)}"})
        return self._send_auth(404, "not found", "text/plain")

    def do_POST(self):
        u = urllib.parse.urlparse(self.path)
        ip = self._client_ip()
        if u.path == "/login":
            if self.auth.blocked(ip):
                self.auth.journal(ip, "-", False, "rate-limited")
                mins = max(1, int(round(self.auth.lock_sec / 60)))
                return self._send(429, self._page_login(f"Слишком много попыток, подождите {mins} мин"))
            try:
                form = self._parse_form()
            except ValueError:
                return self._send(413, self._page_login("Форма слишком большая"))
            pw = form.get("password", "")
            if isinstance(pw, list):
                pw = pw[0] if pw else ""
            if not isinstance(pw, str):
                pw = str(pw)
            user = form.get("user", "")
            if isinstance(user, list):
                user = user[0] if user else ""
            if not isinstance(user, str):
                user = str(user)
            user = user.strip()
            if not user:
                self.auth.note_fail(ip)
                self.auth.journal(ip, "-", False, "empty user")
                return self._send(200, self._page_login("Неверный логин или пароль"))
            if self.auth.verify(user, pw):
                self.auth.note_ok(ip)
                self.auth.journal(ip, user, True)
                s = self.auth.create(ip, user)
                return self._redirect("/system", self._set_session_cookie(s.sid))
            self.auth.note_fail(ip)
            self.auth.journal(ip, user, False, "bad credentials")
            return self._send(200, self._page_login("Неверный логин или пароль"))
        s = self._require_auth()
        if not s:
            return
        try:
            form = self._parse_form()
        except ValueError:
            return self._send_auth(413, "form too large", "text/plain")
        if u.path == "/logout":
            # Real logout: CSRF-protected POST. GET only shows confirmation.
            if not self._check_csrf(form):
                return self._send_auth(403, "bad csrf", "text/plain")
            sid = self._cookie_sid()
            if sid:
                self.auth.destroy(sid)
            return self._redirect("/login", self._set_session_cookie(None))
        if not self._check_csrf(form):
            return self._send_auth(403, "bad csrf", "text/plain")

        if u.path == "/system/reboot":
            try:
                _schedule_reboot()
            except Exception as ex:
                sys.stderr.write(f"awg-panel: schedule reboot failed: {ex}\n")
                return self._send_auth(200, self._page_system("Не удалось запланировать перезагрузку."))
            return self._send_auth(200, self._page_system("Перезагрузка сервера запланирована…"))
        if u.path == "/system/awg-restart":
            try:
                r = cmd_awg_restart()
            except Exception as ex:
                sys.stderr.write(f"awg-panel: awg restart failed: {ex}\n")
                return self._send_auth(200, self._page_system("Не удалось перезапустить AWG."))
            if r.ok:
                return self._send_auth(200, self._page_system("AWG перезапущен."))
            sys.stderr.write(f"awg-panel: awg restart failed rc={r.rc}: {(r.stderr or '')[-500:]}\n")
            return self._send_auth(200, self._page_system(f"Перезапуск AWG не выполнен (rc={r.rc})."))

        def sel_list() -> tuple[list[str], list[str]]:
            v = form.get("sel", [])
            if isinstance(v, str):
                v = [v]
            if not isinstance(v, list):
                v = [v]
            v = [x for x in v if isinstance(x, str)][:MAX_SEL + 1]
            if len(v) > MAX_SEL:
                return [], ["too many selected (max 100)"]
            ok = [x for x in v if valid_client_name(x)]
            bad = [x for x in v if not valid_client_name(x)]
            return ok, bad

        def _fail(msg: str, rc, stderr: str | None):
            sys.stderr.write(f"awg-panel: manage failed {msg} rc={rc}: {(stderr or '')[-500:]}\n")
            return self._send_auth(200, self._page_clients(f"{msg}: операция не выполнена (rc={rc})"))

        if u.path == "/clients/add":
            names_raw = form.get("names", "")
            if isinstance(names_raw, list):
                names_raw = names_raw[0] if names_raw else ""
            if not isinstance(names_raw, str):
                names_raw = str(names_raw)
            days = form.get("days", "")
            if isinstance(days, list):
                days = days[0] if days else ""
            if not isinstance(days, str):
                try:
                    days = str(days)
                except Exception:
                    days = ""
            ok_names, bad = parse_names(names_raw)
            if bad:
                return self._send_auth(200, self._page_clients(f"Плохие имена: {', '.join(bad[:10])}"))
            if not ok_names:
                return self._send_auth(200, self._page_clients("Пусто: укажите имена"))
            if len(ok_names) > MAX_SEL:
                return self._send_auth(200, self._page_clients(f"Слишком много имён (max {MAX_SEL})"))
            try:
                flag = expires_flag(days)
            except ValueError as ex:
                return self._send_auth(200, self._page_clients(str(ex)))
            try:
                r = cmd_add(self.cfg.manage_script, ok_names, flag)
            except ValueError as ex:
                return self._send_auth(200, self._page_clients(str(ex)))
            if r.ok:
                return self._redirect("/clients")
            return _fail("add failed", r.rc, r.stderr)
        if u.path == "/clients/delete":
            names, bad = sel_list()
            if bad:
                return self._send_auth(200, self._page_clients(f"Плохие имена в выборе: {', '.join(bad[:10])}"))
            if not names:
                return self._send_auth(200, self._page_clients("Ничего не выбрано"))
            return self._send_auth(200, self._page_clients_delete_confirm(names))
        if u.path == "/clients/delete/confirm":
            names, bad = sel_list()
            if bad:
                return self._send_auth(200, self._page_clients(f"Плохие имена в выборе: {', '.join(bad[:10])}"))
            if not names:
                return self._send_auth(200, self._page_clients("Ничего не выбрано"))
            try:
                r = cmd_remove(self.cfg.manage_script, names)
            except ValueError as ex:
                return self._send_auth(200, self._page_clients(str(ex)))
            if r.ok:
                return self._redirect("/clients")
            return _fail("remove failed", r.rc, r.stderr)
        if u.path == "/clients/regen":
            names, bad = sel_list()
            if bad:
                return self._send_auth(200, self._page_clients(f"Плохие имена в выборе: {', '.join(bad[:10])}"))
            if not names:
                return self._send_auth(200, self._page_clients("Ничего не выбрано для regen"))
            try:
                r = cmd_regen(self.cfg.manage_script, names)
            except ValueError as ex:
                return self._send_auth(200, self._page_clients(str(ex)))
            if r.ok:
                if len(names) == 1:
                    return self._redirect("/client?name=" + urllib.parse.quote(names[0]))
                return self._redirect("/clients")
            return _fail("regen failed", r.rc, r.stderr)

        if u.path == "/password":
            old = form.get("old_password", "")
            if isinstance(old, list):
                old = old[0] if old else ""
            new1 = form.get("new_password", "")
            if isinstance(new1, list):
                new1 = new1[0] if new1 else ""
            new2 = form.get("new_password2", "")
            if isinstance(new2, list):
                new2 = new2[0] if new2 else ""
            for _v in (old, new1, new2):
                if not isinstance(_v, str):
                    _v = str(_v)
            if not old:
                return self._send_auth(200, self._page_password("Укажите старый пароль"))
            if not self.auth.verify(s.username, old):
                self.auth.journal(ip, s.username, False, "bad old password (change)")
                return self._send_auth(200, self._page_password("Старый пароль неверен"))
            if not new1:
                return self._send_auth(200, self._page_password("Укажите новый пароль"))
            if new1 != new2:
                return self._send_auth(200, self._page_password("Новые пароли не совпадают"))
            if new1 == old:
                return self._send_auth(200, self._page_password("Новый пароль совпадает со старым"))
            s.pending_pw = new1
            return self._send_auth(200, self._page_password_confirm())

        if u.path == "/password/confirm":
            pw = getattr(s, "pending_pw", None)
            if not pw:
                return self._send_auth(200, self._page_password(
                    "Сессия истекла, начните смену пароля заново"))
            # Сначала сохраняем в конфиг, потом в память — при ошибке записи
            # пароль нигде не меняется.
            try:
                update_user_password(self.cfg.config_path, s.username, pw)
            except Exception as ex:
                sys.stderr.write(f"awg-panel: persist password failed: {ex}\n")
                return self._send_auth(200, self._page_password(
                    f"Не удалось сохранить пароль в конфиг: {e(ex)}"))
            self.auth.users[s.username] = pw
            s.pending_pw = None
            self.auth.journal(ip, s.username, True, "password changed")
            return self._send_auth(200, self._page_system("Пароль изменён."))
        return self._send_auth(404, "not found", "text/plain")

    def do_HEAD(self):
        self._send(405, "method not allowed", "text/plain")

    def do_PUT(self):
        self._send(405, "method not allowed", "text/plain")

    def do_DELETE(self):
        self._send(405, "method not allowed", "text/plain")

    def do_PATCH(self):
        self._send(405, "method not allowed", "text/plain")

    def do_OPTIONS(self):
        self._send(405, "method not allowed", "text/plain")


# ---------- HTTP -> HTTPS redirector (port 80 -> https port) ----------
# Plain-HTTP listener that NEVER serves panel content: only 301 to https.
# Needed because a TLS-only socket cannot answer plain-http requests on the
# same port (handshake fails before any HTTP byte can be sent).
_REDIRECT_HOST_RE = re.compile(r"^[A-Za-z0-9.\-]{1,253}$")
_REDIRECT_IPV6_RE = re.compile(r"^[0-9A-Fa-f:.]{2,45}$")


def _extract_redirect_hostname(host_header: str | None) -> str | None:
    """Hostname from Host header without port. None = invalid/missing.

    Strict to avoid open-redirect / response-splitting via crafted Host.
    """
    if not host_header or not isinstance(host_header, str):
        return None
    h = host_header.strip()
    if not h or len(h) > 300:
        return None
    if any(c in h for c in ("\r", "\n", " ", "/", "?", "#", "@", "\\")):
        return None
    if h.startswith("["):
        end = h.find("]")
        if end == -1:
            return None
        inner = h[1:end]
        rest = h[end + 1:]
        if rest and not rest.startswith(":"):
            return None
        if rest.startswith(":") and not rest[1:].isdigit():
            return None
        if not inner or ":" not in inner or not _REDIRECT_IPV6_RE.match(inner):
            return None
        return h[: end + 1]
    if h.count(":") > 1:
        return None  # bare IPv6 without brackets is invalid in Host
    if ":" in h:
        hostname, _, port = h.partition(":")
        if not port.isdigit() or not hostname:
            return None
        h = hostname
    if not _REDIRECT_HOST_RE.match(h):
        return None
    if h.startswith((".", "-")) or h.endswith((".", "-")) or ".." in h:
        return None
    return h


def _sanitize_redirect_path(path: str | None) -> str:
    if not path or not isinstance(path, str) or not path.startswith("/"):
        return "/"
    if "\r" in path or "\n" in path:
        return "/"
    for ch in path:
        if ord(ch) < 32:
            return "/"
    if len(path) > 8192:
        return "/"
    return path


def build_https_redirect_url(host_header: str | None, path: str | None,
                             https_port: int) -> str | None:
    """https://<host>[:port]<path> or None when Host/port invalid."""
    hostname = _extract_redirect_hostname(host_header)
    if not hostname:
        return None
    try:
        port = int(https_port)
    except (TypeError, ValueError):
        return None
    if not 1 <= port <= 65535:
        return None
    safe_path = _sanitize_redirect_path(path)
    if port == 443:
        return f"https://{hostname}{safe_path}"
    return f"https://{hostname}:{port}{safe_path}"


class HttpToHttpsRedirectHandler(BaseHTTPRequestHandler):
    """Minimal 301 redirector. No cookies, no auth, no static, no state."""
    server_version = f"awg-panel/{__version__}"
    https_port: int = 8443
    timeout = 10

    def log_request(self, code="-", size="-"):
        pass  # access log silenced: :80 is scanned constantly, 301 is noise

    def log_error(self, format, *args):
        sys.stderr.write(f"awg-panel-redirect: {self.client_address[0]} {format % args}\n")

    def log_message(self, format, *args):
        # Only send_error() reaches here (format 'code %d, ...').
        try:
            code = int(args[0]) if args else 0
        except (TypeError, ValueError):
            code = 0
        if code >= 400:
            sys.stderr.write(f"awg-panel-redirect: {self.client_address[0]} {format % args}\n")

    def _do_redirect(self):
        # Always close: POST bodies sent in clear to :80 are discarded,
        # leftover bytes must not be parsed as the next request (desync).
        self.close_connection = True
        url = build_https_redirect_url(self.headers.get("Host"), self.path,
                                       self.https_port)
        if url is None:
            self.log_error("code 400, bad Host")
            body = b"bad request\n"
            self.send_response(400)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Pragma", "no-cache")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)
            return
        body = f"Redirecting to {url}\n".encode("utf-8")
        self.send_response(301)
        self.send_header("Location", url)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        # Short cache: permanent enough to skip cleartext next time,
        # short enough to not stick forever after a port change.
        self.send_header("Cache-Control", "public, max-age=3600")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    do_GET = _do_redirect
    do_HEAD = _do_redirect
    do_POST = _do_redirect
    do_PUT = _do_redirect
    do_DELETE = _do_redirect
    do_PATCH = _do_redirect
    do_OPTIONS = _do_redirect
    do_TRACE = _do_redirect


def start_http_redirector(cfg: PanelConfig):
    """Start plain-HTTP :http_redirect_port -> https :port in a daemon thread.

    Never fails the main HTTPS server: port busy / no permission / same port
    as HTTPS just logs to stderr and returns None (panel stays on HTTPS).
    """
    rport = getattr(cfg, "http_redirect_port", 80)
    try:
        rport = int(rport)
    except (TypeError, ValueError):
        rport = 80
    if not rport:
        return None
    if rport == cfg.port:
        sys.stderr.write(
            f"awg-panel-redirect: disabled (http_redirect_port == port == {rport})\n")
        return None
    HttpToHttpsRedirectHandler.https_port = cfg.port
    try:
        srv = ThreadingHTTPServer((cfg.host, rport), HttpToHttpsRedirectHandler)
    except OSError as ex:
        sys.stderr.write(f"awg-panel-redirect: :{rport} disabled ({ex})\n")
        return None
    srv.daemon_threads = True
    t = threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.5},
                         daemon=True, name="http-redirect")
    t.start()
    print(f"awg-panel http://{cfg.host}:{rport} -> https :{cfg.port} (301)")
    return srv


# Copy-to-clipboard helper (0.1.6+). Served as /static/copy.js and included
# via <script src> (COPY_TAG): the CSP header (script-src 'self', 0.1.8+)
# blocks inline scripts, so this MUST NOT be inlined into pages.
COPY_JS = """function awgCopyText(t){if(navigator.clipboard&&navigator.clipboard.writeText){return navigator.clipboard.writeText(t)}return Promise.reject(new Error('no clipboard API'))}
function awgCopyFallback(t){return new Promise(function(res,rej){var ta=document.createElement('textarea');ta.value=t;ta.setAttribute('readonly','');ta.style.position='fixed';ta.style.top='0';ta.style.left='0';ta.style.opacity='0';document.body.appendChild(ta);ta.focus();ta.select();try{var ok=document.execCommand('copy');document.body.removeChild(ta);if(ok){res()}else{rej(new Error('execCommand false'))}}catch(e){try{document.body.removeChild(ta)}catch(_){}rej(e)}})}
function awgCopy(t){var p;try{p=awgCopyText(t)}catch(e){p=Promise.reject(e)}var to=new Promise(function(_,rej){setTimeout(function(){rej(new Error('timeout'))},3000)});return Promise.race([p,to]).catch(function(){return awgCopyFallback(t)})}
function awgBindCopy(){document.querySelectorAll('button[data-src]').forEach(function(b){if(b.getAttribute('data-awg-bound')){return}b.setAttribute('data-awg-bound','1');b.addEventListener('click',function(){var el=document.getElementById(b.getAttribute('data-src'));if(!el){return}awgCopy(el.textContent).then(function(){b.textContent='Скопировано';b.classList.add('copied');setTimeout(function(){b.textContent='Скопировать';b.classList.remove('copied')},1500)},function(){b.textContent='Не скопировалось';setTimeout(function(){b.textContent='Скопировать'},1500)})})})}
if(document.readyState==='loading'){document.addEventListener('DOMContentLoaded',awgBindCopy)}else{awgBindCopy()}
"""
COPY_TAG = '<script src="/static/copy.js" defer></script>'


# Clients page helper (0.1.13+). Served as /static/clients.js and included
# via <script src> (CLIENTS_TAG): the CSP header (script-src 'self', 0.1.8+)
# blocks inline scripts, so this MUST NOT be inlined into pages.
# - Delete button (#delbtn) stays disabled until a checkbox is checked.
# - Generate button (#genbtn) fills #names with prefix + random hex
#   (client-side analogue of `prefix$(openssl rand -hex N)`); prefix and N
#   come from [client_names] via data-attributes rendered by _page_clients.
CLIENTS_JS = """function awgClientsRefreshDel(){var b=document.getElementById('delbtn'),f=document.getElementById('delf');if(!b||!f){return}var boxes=f.querySelectorAll('input[name=sel]'),any=false;for(var i=0;i<boxes.length;i++){if(boxes[i].checked){any=true;break}}b.disabled=!any}
function awgClientsGen(){var g=document.getElementById('genbtn'),n=document.getElementById('names');if(!g||!n){return}var prefix=g.getAttribute('data-prefix')||'user_';var nb=parseInt(g.getAttribute('data-rand-bytes')||'8',10);if(!(nb>=1&&nb<=32)){nb=8}var buf=new Uint8Array(nb),ok=false;try{if(window.crypto&&window.crypto.getRandomValues){window.crypto.getRandomValues(buf);ok=true}}catch(e){ok=false}if(!ok){for(var i=0;i<nb;i++){buf[i]=Math.floor(Math.random()*256)}}var hx='';for(var j=0;j<buf.length;j++){var h=buf[j].toString(16);hx+=h.length<2?'0'+h:h}var gen=prefix+hx;var cur=n.value;if(cur&&cur.trim()!==''){n.value=cur.replace(/\\s+$/,'')+' '+gen}else{n.value=gen}try{n.focus()}catch(e){}}
function awgClientsInit(){var f=document.getElementById('delf');if(f){f.addEventListener('change',function(ev){var t=ev&&ev.target;if(t&&t.getAttribute&&t.getAttribute('name')==='sel'){awgClientsRefreshDel()}})}var g=document.getElementById('genbtn');if(g){g.addEventListener('click',awgClientsGen)}awgClientsRefreshDel()}
if(document.readyState==='loading'){document.addEventListener('DOMContentLoaded',awgClientsInit)}else{awgClientsInit()}
"""
CLIENTS_TAG = '<script src="/static/clients.js" defer></script>'


STYLE_CSS = """*{box-sizing:border-box}body{margin:0;font:14px/1.45 system-ui,Segoe UI,Roboto,Arial,sans-serif;background:#eef1f5;color:#1f2937;display:flex;min-height:100vh;overflow-x:hidden}
aside{width:220px;background:#1f2937;color:#cbd5e1;display:flex;flex-direction:column;padding:18px 0;flex-shrink:0;position:sticky;top:0;height:100vh;overflow-y:auto}
.brand{color:#fff;font-weight:700;font-size:18px;padding:0 20px 16px}.brand small{display:block;color:#94a3b8;font-weight:400;font-size:11px}.brand small a{color:#94a3b8}
nav a{display:block;color:#cbd5e1;text-decoration:none;padding:10px 20px}nav a.on,nav a:hover{background:#374151;color:#fff}
nav{display:flex;flex-direction:column;flex:1}
nav form.navlogout{margin:auto 0 0;padding:12px 0 0}nav form.navlogout:before{content:"";display:block;border-top:1px solid #374151;margin-bottom:12px}nav button.navlink{display:block;width:100%;text-align:left;background:none;border:0;color:#cbd5e1;padding:10px 20px;font:inherit;cursor:pointer;border-radius:0}nav button.navlink.on,nav button.navlink:hover{background:#374151;color:#fff}
main{flex:1;padding:24px;max-width:1200px;min-width:0;overflow-x:hidden}h1{margin:0 0 16px;font-size:22px}.card{background:#fff;border:1px solid #e2e8f0;border-radius:8px;padding:16px;margin-bottom:16px;min-width:0;max-width:100%}
table{width:100%;border-collapse:collapse;background:#fff}th,td{border:1px solid #e2e8f0;padding:8px;text-align:left;font-size:13px}th{background:#f1f5f9}th a{color:inherit;text-decoration:none}th a:hover{text-decoration:underline}
.stack{display:flex;flex-direction:column;gap:16px}.stack>.card{margin-bottom:0}.row{display:flex;gap:8px;margin-bottom:12px;flex-wrap:wrap}.actions{display:flex;gap:8px;margin-top:12px;flex-wrap:wrap;align-items:center}.actions form{margin:0}
input{padding:8px;border:1px solid #cbd5e1;border-radius:6px}button,.btn{font:inherit;background:#e2e8f0;border:1px solid #cbd5e1;border-radius:6px;padding:8px 14px;cursor:pointer;text-decoration:none;color:#111;display:inline-block;vertical-align:middle}
button:hover,.btn:hover{background:#cbd5e1}button:disabled{color:#9ca3af;cursor:not-allowed;background:#e2e8f0}button:disabled:hover{background:#e2e8f0}button.copied{color:#9ca3af}
.err{color:#b91c1c}.ok{color:#15803d}.warn{color:#b45309}.muted{color:#64748b;font-size:12px}.mono{font-family:ui-monospace,Consolas,monospace;font-size:12px}
pre{background:#0f172a;color:#e2e8f0;padding:12px;border-radius:6px;overflow:auto;max-width:100%;font-size:12px}pre.wrap{white-space:pre-wrap;word-break:break-all}
img{max-width:100%}
label{display:block;margin:8px 0}input[name=user],input[name=password],input[name=names],input[name=old_password],input[name=new_password],input[name=new_password2]{width:100%}
@media(max-width:800px){aside{width:150px}}
"""


def run(cfg: PanelConfig):
    import os as _os
    from .config import MAX_USERS
    if not isinstance(cfg.users, dict) or not cfg.users:
        raise SystemExit("bad [users] config: нет пользователей (проверьте /etc/awg-panel/config.ini)")
    if len(cfg.users) > MAX_USERS:
        raise SystemExit(f"bad [users] config: больше {MAX_USERS} пользователей")
    auth = AuthStore(cfg.users, cfg.auth_log, cfg.session_ttl_min * 60,
                     cfg.auth_max_attempts, cfg.auth_lock_minutes * 60)
    Handler.cfg = cfg
    Handler.auth = auth
    if not (_os.path.isfile(cfg.cert) and _os.path.isfile(cfg.key)):
        raise SystemExit(
            f"TLS cert/key not found: cert={cfg.cert} key={cfg.key} "
            "(postinst normally creates them; check /etc/awg-panel/config.ini)")
    srv = ThreadingHTTPServer((cfg.host, cfg.port), Handler)
    srv.daemon_threads = True
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    try:
        ctx.load_cert_chain(cfg.cert, cfg.key)
    except (OSError, ssl.SSLError) as ex:
        raise SystemExit(f"TLS load failed ({cfg.cert}, {cfg.key}): {ex}")
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    start_http_redirector(cfg)
    print(f"awg-panel https://{cfg.host}:{cfg.port} (manage={cfg.manage_script})")
    srv.serve_forever()
