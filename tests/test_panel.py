import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from awg_panel.auth import AuthStore
from awg_panel.validate import expires_flag, parse_names, valid_client_name


class TestValidate(unittest.TestCase):
    def test_names(self):
        self.assertTrue(valid_client_name("my_phone-1"))
        self.assertFalse(valid_client_name("bad name"))
        self.assertFalse(valid_client_name("../x"))
        self.assertFalse(valid_client_name("a" * 64))

    def test_parse(self):
        ok, bad = parse_names("a, b;c\nd, a, bad name!")
        self.assertEqual(ok, ["a", "b", "c", "d", "bad"])
        self.assertEqual(bad, ["name!"])

    def test_expires_days_only(self):
        self.assertIsNone(expires_flag(""))
        self.assertIsNone(expires_flag(None))
        self.assertIsNone(expires_flag("0"))
        self.assertEqual(expires_flag("7"), "--expires=7d")
        with self.assertRaises(ValueError):
            expires_flag("7h")
        with self.assertRaises(ValueError):
            expires_flag("abc")
        with self.assertRaises(ValueError):
            expires_flag("99999")


class TestAuth(unittest.TestCase):
    def test_verify_config_credentials(self):
        st = AuthStore({"admin": "s3cret-password"}, "/tmp/nonexistent-auth.log", 60)
        self.assertTrue(st.verify("admin", "s3cret-password"))
        self.assertFalse(st.verify("admin", "wrong"))
        self.assertFalse(st.verify("other", "s3cret-password"))
        self.assertFalse(st.verify("", ""))

    def test_verify_multi_no_cross_password(self):
        st = AuthStore({"user1": "password1", "user2": "password2"},
                       "/tmp/nonexistent-auth.log", 60)
        self.assertTrue(st.verify("user1", "password1"))
        self.assertTrue(st.verify("user2", "password2"))
        # пароль от одного не подходит другому
        self.assertFalse(st.verify("user1", "password2"))
        self.assertFalse(st.verify("user2", "password1"))
        self.assertFalse(st.verify("nosuch", "password1"))

    def test_sessions(self):
        st = AuthStore({"admin": "pw"}, "/tmp/nonexistent-auth.log", 60)
        s = st.create("1.2.3.4", "admin")
        self.assertIsNotNone(st.get(s.sid))
        st.destroy(s.sid)
        self.assertIsNone(st.get(s.sid))

    def test_session_stores_username(self):
        st = AuthStore({"user1": "password1"}, "/tmp/nonexistent-auth.log", 60)
        s = st.create("1.2.3.4", "user1")
        got = st.get(s.sid)
        self.assertIsNotNone(got)
        self.assertEqual(got.username, "user1")

    def test_rate_limit(self):
        st = AuthStore({"admin": "pw"}, "/tmp/nonexistent-auth.log", 60)
        for _ in range(5):
            st.note_fail("9.9.9.9")
        self.assertTrue(st.blocked("9.9.9.9"))

    def test_rate_limit_custom(self):
        import time
        st = AuthStore({"admin": "pw"}, "/tmp/nonexistent-auth.log", 60, 3, 120)
        st.note_fail("9.9.9.9")
        st.note_fail("9.9.9.9")
        self.assertFalse(st.blocked("9.9.9.9"))
        st.note_fail("9.9.9.9")
        self.assertTrue(st.blocked("9.9.9.9"))
        _c, until, _l = st.fails["9.9.9.9"]
        self.assertGreater(until, time.time() + 100)

    def test_rate_limit_gc(self):
        import time
        st = AuthStore({"admin": "pw"}, "/tmp/nonexistent-auth.log", 60)
        st.fails["1.1.1.1"] = (2, 0.0, time.time() - 700)
        st._gc_fails()
        self.assertNotIn("1.1.1.1", st.fails)


class TestConfig(unittest.TestCase):
    def test_clamp(self):
        import tempfile
        from awg_panel.config import load_config
        users = "[users]\nuser.1 = admin\npassword.1 = admin\n"
        with tempfile.NamedTemporaryFile("w+", suffix=".ini", delete=False) as f:
            f.write("[server]\nhost = \nport = 99999\nsession_ttl_min = 0\n" + users)
            path = f.name
        cfg = load_config(path)
        self.assertEqual(cfg.host, "0.0.0.0")
        self.assertEqual(cfg.port, 8443)
        self.assertEqual(cfg.session_ttl_min, 1)
        with tempfile.NamedTemporaryFile("w+", suffix=".ini", delete=False) as f:
            f.write("[server]\nsession_ttl_min = 9999\n" + users)
            path2 = f.name
        self.assertEqual(load_config(path2).session_ttl_min, 1440)

    def test_users_numbered(self):
        import tempfile
        from awg_panel.config import load_config
        with tempfile.NamedTemporaryFile("w+", suffix=".ini", delete=False) as f:
            f.write("[server]\nport = 8443\n"
                    "[users]\nuser.1 = user1\npassword.1 = password1\n"
                    "user.2 = user2\npassword.2 = password2\n")
            path = f.name
        cfg = load_config(path)
        self.assertEqual(cfg.users, {"user1": "password1", "user2": "password2"})

    def test_users_required_fail_closed(self):
        import tempfile
        from awg_panel.config import load_config
        # нет секции [users] -> отказ старта (обратной совместимости нет)
        with tempfile.NamedTemporaryFile("w+", suffix=".ini", delete=False) as f:
            f.write("[server]\nport = 8443\n")
            path = f.name
        with self.assertRaises(ValueError):
            load_config(path)
        # старые ключи webusername/webpassword игнорируются и не спасают
        with tempfile.NamedTemporaryFile("w+", suffix=".ini", delete=False) as f:
            f.write("[server]\nwebusername = solo\nwebpassword = s3cret\n")
            path2 = f.name
        with self.assertRaises(ValueError):
            load_config(path2)
        # нет файла -> отказ старта
        with self.assertRaises(ValueError):
            load_config("/tmp/awg-panel-no-such-config-12345.ini")

    def test_users_errors_fail_closed(self):
        import tempfile
        from awg_panel.config import load_config
        cases = [
            # password.2 без user.2
            "[users]\nuser.1 = a\npassword.1 = p1\npassword.2 = p2\n",
            # user.2 без password.2
            "[users]\nuser.1 = a\npassword.1 = p1\nuser.2 = b\n",
            # дубль логина
            "[users]\nuser.1 = same\npassword.1 = p1\nuser.2 = same\npassword.2 = p2\n",
            # плохой логин
            "[users]\nuser.1 = bad name!\npassword.1 = p1\n",
            # пустой пароль
            "[users]\nuser.1 = a\npassword.1 = \n",
            # неизвестный ключ
            "[users]\nuser.1 = a\npassword.1 = p1\nfoo = bar\n",
            # индекс вне диапазона
            "[users]\nuser.255 = a\npassword.255 = p1\n",
            "[users]\nuser.0 = a\npassword.0 = p1\n",
        ]
        for body in cases:
            with self.subTest(body=body):
                with tempfile.NamedTemporaryFile("w+", suffix=".ini", delete=False) as f:
                    f.write("[server]\n" + body)
                    path = f.name
                with self.assertRaises(ValueError):
                    load_config(path)

    def test_users_duplicate_option_fails(self):
        import tempfile
        from awg_panel.config import load_config
        with tempfile.NamedTemporaryFile("w+", suffix=".ini", delete=False) as f:
            f.write("[users]\nuser.1 = a\npassword.1 = p1\nuser.1 = b\npassword.1 = p2\n")
            path = f.name
        with self.assertRaises(ValueError):
            load_config(path)

    def test_users_limit_254(self):
        import tempfile
        from awg_panel.config import MAX_USERS, load_config
        self.assertEqual(MAX_USERS, 254)
        lines = "".join(f"user.{i} = u{i}\npassword.{i} = p{i}\n" for i in range(1, 255))
        with tempfile.NamedTemporaryFile("w+", suffix=".ini", delete=False) as f:
            f.write("[server]\n[users]\n" + lines)
            path = f.name
        self.assertEqual(len(load_config(path).users), 254)
        with tempfile.NamedTemporaryFile("w+", suffix=".ini", delete=False) as f:
            f.write("[server]\n[users]\n" + lines + "user.255 = extra\npassword.255 = x\n")
            path2 = f.name
        with self.assertRaises(ValueError):
            load_config(path2)

    def test_update_user_password(self):
        import os, tempfile
        from awg_panel.config import update_user_password, load_config
        content = (
            "[server]\nhost = 0.0.0.0\n\n"
            "[users]\nuser.1 = admin\npassword.1 = oldpass\n"
            "user.2 = guest\npassword.2 = guestpass\n"
        )
        with tempfile.NamedTemporaryFile("w", suffix=".ini", delete=False,
                                         encoding="utf-8") as f:
            f.write(content)
            path = f.name
        try:
            update_user_password(path, "admin", "newpass123")
            cfg = load_config(path)
            self.assertEqual(cfg.users["admin"], "newpass123")
            self.assertEqual(cfg.users["guest"], "guestpass")
        finally:
            os.unlink(path)

    def test_update_user_password_not_found(self):
        import os, tempfile
        from awg_panel.config import update_user_password
        content = "[users]\nuser.1 = admin\npassword.1 = oldpass\n"
        with tempfile.NamedTemporaryFile("w", suffix=".ini", delete=False,
                                         encoding="utf-8") as f:
            f.write(content)
            path = f.name
        try:
            with self.assertRaises(ValueError):
                update_user_password(path, "nobody", "pw")
        finally:
            os.unlink(path)

    def test_auth_limits(self):
        import tempfile
        from awg_panel.config import load_config
        users = "[users]\nuser.1 = admin\npassword.1 = admin\n"
        with tempfile.NamedTemporaryFile("w+", suffix=".ini", delete=False) as f:
            f.write("[server]\nauth_max_attempts = 3\nauth_lock_minutes = 10\n" + users)
            path = f.name
        cfg = load_config(path)
        self.assertEqual(cfg.auth_max_attempts, 3)
        self.assertEqual(cfg.auth_lock_minutes, 10)
        # defaults + clamp
        with tempfile.NamedTemporaryFile("w+", suffix=".ini", delete=False) as f:
            f.write("[server]\nport = 8443\n" + users)
            path2 = f.name
        cfg2 = load_config(path2)
        self.assertEqual(cfg2.auth_max_attempts, 5)
        self.assertEqual(cfg2.auth_lock_minutes, 5)
        with tempfile.NamedTemporaryFile("w+", suffix=".ini", delete=False) as f:
            f.write("[server]\nauth_max_attempts = 0\nauth_lock_minutes = 99999\n" + users)
            path3 = f.name
        cfg3 = load_config(path3)
        self.assertEqual(cfg3.auth_max_attempts, 1)
        self.assertEqual(cfg3.auth_lock_minutes, 1440)
        with tempfile.NamedTemporaryFile("w+", suffix=".ini", delete=False) as f:
            f.write("[server]\nauth_max_attempts = garbage\nauth_lock_minutes = garbage\n" + users)
            path4 = f.name
        cfg4 = load_config(path4)
        self.assertEqual(cfg4.auth_max_attempts, 5)
        self.assertEqual(cfg4.auth_lock_minutes, 5)


class TestClientNames(unittest.TestCase):
    def _load(self, body: str):
        import tempfile
        from awg_panel.config import load_config
        users = "[users]\nuser.1 = admin\npassword.1 = admin\n"
        with tempfile.NamedTemporaryFile("w+", suffix=".ini", delete=False) as f:
            f.write(body + users)
            path = f.name
        return load_config(path)

    def test_defaults_without_section(self):
        cfg = self._load("[server]\nport = 8443\n")
        self.assertEqual(cfg.client_name_prefix, "user_")
        self.assertEqual(cfg.client_name_rand_bytes, 8)

    def test_custom(self):
        cfg = self._load("[server]\n[client_names]\nprefix = vpn-\nrand_bytes = 9\n")
        self.assertEqual(cfg.client_name_prefix, "vpn-")
        self.assertEqual(cfg.client_name_rand_bytes, 9)

    def test_garbage_and_clamp(self):
        cfg = self._load("[server]\n[client_names]\nprefix = \nrand_bytes = garbage\n")
        self.assertEqual(cfg.client_name_prefix, "user_")
        self.assertEqual(cfg.client_name_rand_bytes, 8)
        self.assertEqual(self._load("[server]\n[client_names]\nrand_bytes = 0\n").client_name_rand_bytes, 1)
        # 999 -> clamp 32, затем урезка под длину имени (<= 63):
        # префикс user_ (5) -> (63-5)//2 = 29, префикс из 1 символа -> 31.
        self.assertEqual(self._load("[server]\n[client_names]\nrand_bytes = 999\n").client_name_rand_bytes, 29)
        cfg5 = self._load("[server]\n[client_names]\nprefix = a\nrand_bytes = 999\n")
        self.assertEqual(cfg5.client_name_rand_bytes, 31)

    def test_bad_prefix_falls_back(self):
        for bad in ("bad name!", "../x", "a" * 62):
            with self.subTest(bad=bad):
                cfg = self._load(f"[server]\n[client_names]\nprefix = {bad}\n")
                self.assertEqual(cfg.client_name_prefix, "user_")

    def test_long_prefix_shrinks_rand_bytes(self):
        # префикс 32 символа -> не больше (63-32)//2 = 15 байт, иначе имя
        # не пройдёт valid_client_name() (<= 63).
        cfg = self._load("[server]\n[client_names]\nprefix = " + "p" * 32 + "\nrand_bytes = 32\n")
        self.assertEqual(cfg.client_name_prefix, "p" * 32)
        self.assertEqual(cfg.client_name_rand_bytes, 15)
        self.assertLessEqual(len(cfg.client_name_prefix) + 2 * cfg.client_name_rand_bytes, 63)
        self.assertTrue(valid_client_name(cfg.client_name_prefix + "f" * (2 * cfg.client_name_rand_bytes)))

    def test_example_has_client_names(self):
        example = (Path(__file__).resolve().parents[1] / "packaging" / "config.ini.example").read_text()
        self.assertIn("[client_names]", example)
        self.assertIn("prefix = user_", example)
        self.assertIn("rand_bytes = 8", example)


class TestManage(unittest.TestCase):
    def test_parse_ok_flag(self):
        from awg_panel.manage import _parse_json_output
        r = _parse_json_output('{"ok": true, "x": 1}', 0, "")
        self.assertTrue(r.ok)
        self.assertEqual(r.data["x"], 1)
        r2 = _parse_json_output('{"ok": false}', 0, "e")
        self.assertFalse(r2.ok)
        r3 = _parse_json_output("not json", 0, "e")
        self.assertFalse(r3.ok)

    def test_add_argv_order(self):
        # Regression: --expires must sit between --yes and add.
        import subprocess
        from unittest import mock
        from awg_panel import manage
        seen = {}

        def fake_run(cmd, **kw):
            seen["cmd"] = cmd
            return subprocess.CompletedProcess(cmd, 0, '{"ok": true}', "")

        with mock.patch.object(manage.subprocess, "run", fake_run):
            with mock.patch.object(manage, "_is_root", lambda: False):
                manage.cmd_add("/root/awg/manage_amneziawg.sh", ["alice"], "--expires=7d")
        cmd = seen["cmd"]
        # [..., "--json", "--no-color", "--yes", "--expires=7d", "add", "alice"]
        self.assertIn("--yes", cmd)
        yi = cmd.index("--yes")
        self.assertEqual(cmd[yi + 1], "--expires=7d")
        self.assertEqual(cmd[yi + 2], "add")

    def test_run_helper_allowlist(self):
        # Helper allowlist is enforced in code (manage._HELPER_CMDS):
        # unknown commands and stray args are rejected before exec.
        from awg_panel import manage
        with self.assertRaises(ValueError):
            manage.run_helper("/usr/sbin/awg-panel-helper", "reboot")
        with self.assertRaises(ValueError):
            manage.run_helper("/usr/sbin/awg-panel-helper", "server-pubkeys", "extra")
        with self.assertRaises(ValueError):
            manage.run_helper("/usr/sbin/awg-panel-helper", "client-conf", "bad;name")

    def test_root_runs_direct_without_sudo(self):
        # Service runs as root -> manage/helper called directly.
        # Sudo path is only a fallback for non-root dev runs.
        from unittest import mock
        from awg_panel import manage
        with mock.patch.object(manage, "_is_root", lambda: True):
            self.assertEqual(
                manage._base("/root/awg/manage_amneziawg.sh"),
                ["/bin/bash", "/root/awg/manage_amneziawg.sh"],
            )
            rc_holder = {}

            import subprocess

            def fake_run(cmd, **kw):
                rc_holder["cmd"] = cmd
                return subprocess.CompletedProcess(cmd, 0, b"", b"")

            with mock.patch.object(manage.subprocess, "run", fake_run):
                manage.run_helper("/usr/sbin/awg-panel-helper", "server-pubkeys")
            self.assertEqual(
                rc_holder["cmd"][:2],
                ["/usr/sbin/awg-panel-helper", "server-pubkeys"],
            )
            self.assertNotIn("/usr/bin/sudo", rc_holder["cmd"])


class TestSystemInfo(unittest.TestCase):
    def test_mem_info_malformed(self):
        from awg_panel import system_info
        orig = system_info._read
        system_info._read = lambda p: "MemTotal: broken\nMemFree:\n"
        try:
            out = system_info.mem_info()
            self.assertIn("used_kb", out)
        finally:
            system_info._read = orig


class TestPackaging(unittest.TestCase):
    def test_deb_files_root_owned(self):
        # Regression: 0.1.1 built as uid 1001 shipped files owned by 1001.
        build = (Path(__file__).resolve().parents[1] / "build_deb.sh").read_text()
        self.assertIn("root-owner-group", build)
        self.assertIn("chown -R 0:0", build)

    def test_postinst_no_sudoers(self):
        postinst = (Path(__file__).resolve().parents[1] / "packaging" / "DEBIAN" / "postinst").read_text()
        self.assertNotIn("sudoers", postinst)
        self.assertNotIn("visudo", postinst)
        postrm = (Path(__file__).resolve().parents[1] / "packaging" / "DEBIAN" / "postrm").read_text()
        self.assertNotIn("sudoers", postrm)
        conffiles = (Path(__file__).resolve().parents[1] / "packaging" / "DEBIAN" / "conffiles").read_text()
        self.assertNotIn("sudoers", conffiles)
        self.assertFalse(
            (Path(__file__).resolve().parents[1] / "packaging" / "sudoers").exists()
        )

    def test_postinst_tls_key_root_only(self):
        # Service runs as root -> key 600 root:root.
        postinst = (Path(__file__).resolve().parents[1] / "packaging" / "DEBIAN" / "postinst").read_text()
        self.assertIn("chmod 600 /etc/awg-panel/key.pem", postinst)
        self.assertIn("chown root:root /etc/awg-panel/key.pem", postinst)
        self.assertNotIn("chown root:awgpanel /etc/awg-panel/key.pem", postinst)

    def test_postinst_prints_next_steps(self):
        postinst = (Path(__file__).resolve().parents[1] / "packaging" / "DEBIAN" / "postinst").read_text()
        for marker in (
            "/etc/awg-panel/config.ini",
            "systemctl restart awg-panel",
            "awg-panel-set-password",
            "https://<IP",
            "[users]",
            "user.N/password.N",
        ):
            self.assertIn(marker, postinst)
        self.assertNotIn("webusername", postinst)
        self.assertNotIn("webpassword", postinst)
        # legacy password-file flow is gone (cleanup removed in stable)
        self.assertNotIn("/root/.awg-panel-initial-password", postinst)
        self.assertNotIn("awg-panel-set-password-internal", postinst)

    def test_postinst_no_web_credentials_migration(self):
        postinst = (Path(__file__).resolve().parents[1] / "packaging" / "DEBIAN" / "postinst").read_text()
        self.assertNotIn("webusername", postinst)
        self.assertNotIn("webpassword", postinst)
        self.assertIn("chmod 600 /etc/awg-panel/config.ini", postinst)

    def test_postrm_purge_full_cleanup(self):
        # 0.1.11: purge must remove what dpkg leaves behind — postinst-made
        # cert/key (not conffiles) and logs. /root/awg must never be touched.
        postrm = (Path(__file__).resolve().parents[1] / "packaging" / "DEBIAN" / "postrm").read_text()
        self.assertIn("purge)", postrm)
        for marker in (
            "rm -f /etc/awg-panel/cert.pem",
            "/etc/awg-panel/key.pem",
            "/etc/awg-panel/config.ini",
            "rm -rf /var/log/awg-panel",
        ):
            self.assertIn(marker, postrm)
        # Only real commands count — the comment names the protected paths.
        code = "\n".join(l for l in postrm.splitlines() if l.strip() and not l.strip().startswith("#"))
        self.assertNotIn("/root/awg", code)
        self.assertNotIn("/etc/amnezia", code)

    def test_service_runs_as_root_without_sudo_breaking_sandbox(self):
        # Regression: User=awgpanel + sandbox broke sudo, service runs as root.
        svc = (Path(__file__).resolve().parents[1] / "packaging" / "awg-panel.service").read_text()
        # Only real directives count — comments describe the old breakage.
        directives = [l for l in svc.splitlines() if l.strip() and not l.strip().startswith("#")]
        body = "\n".join(directives)
        self.assertIn("User=root", body)
        self.assertIn("Group=root", body)
        self.assertNotIn("CapabilityBoundingSet", body)
        self.assertNotIn("AmbientCapabilities", body)
        self.assertNotIn("NoNewPrivileges", body)
        self.assertNotIn("ReadOnlyPaths", body)
        self.assertNotIn("ProtectSystem=strict", body)
        self.assertNotIn("ProtectHome=read-only", body)

    def test_config_example_has_users_only(self):
        example = (Path(__file__).resolve().parents[1] / "packaging" / "config.ini.example").read_text()
        self.assertNotIn("webusername", example)
        self.assertNotIn("webpassword", example)
        self.assertNotIn("password_file", example)
        self.assertIn("[users]", example)
        self.assertIn("user.1 = admin", example)
        self.assertIn("password.1 = admin", example)
        self.assertIn("auth_max_attempts = 5", example)
        self.assertIn("auth_lock_minutes = 5", example)
        self.assertIn("http_redirect_port = 80", example)

    def test_control_no_sudo_dep(self):
        control = (Path(__file__).resolve().parents[1] / "packaging" / "DEBIAN" / "control").read_text()
        depends = next(l for l in control.splitlines() if l.startswith("Depends:"))
        self.assertNotIn("sudo", depends.split(":", 1)[1].split(","))

    def test_build_does_not_ship_internal_setter(self):
        build = (Path(__file__).resolve().parents[1] / "build_deb.sh").read_text()
        self.assertNotIn("awg-panel-set-password-internal", build)
        self.assertFalse(
            (Path(__file__).resolve().parents[1] / "bin" / "awg-panel-set-password-internal").exists()
        )


class TestClientPage(unittest.TestCase):
    def _render_client(self):
        from types import SimpleNamespace
        from unittest import mock
        from awg_panel import server as srv
        from awg_panel.config import PanelConfig
        from awg_panel.manage import ManageResult
        h = srv.Handler.__new__(srv.Handler)
        h.cfg = PanelConfig()
        long_line = "Endpoint = 1.2.3.4:51820 # " + "A" * 500
        conf = ("[Interface]\nPrivateKey = " + "B" * 60 + "\n"
                f"{long_line}\n[Peer]\nPublicKey = " + "C" * 60 + "\n")
        uri = "vpn://awg@" + "D" * 500
        with mock.patch.object(srv.Handler, "_sess",
                               lambda self: SimpleNamespace(csrf="t")), \
             mock.patch.object(srv, "cmd_list", lambda ms: ManageResult(
                 True, 0, [{"name": "alice", "ip": "10.0.0.2",
                            "status": "active", "expires_at": None}], "")), \
             mock.patch.object(srv, "cmd_stats", lambda ms: ManageResult(
                 True, 0, [{"name": "alice", "rx": 1, "tx": 2,
                            "last_handshake": 0}], "")), \
             mock.patch.object(srv, "run_helper") as rh:
            def side_effect(helper, *args, **kw):
                if args[:1] == ("client-conf",):
                    return 0, conf.encode(), ""
                if args[:1] == ("client-uri",):
                    return 0, (uri + "\n").encode(), ""
                return 1, b"", "no"
            rh.side_effect = side_effect
            return h._page_client("alice")

    def test_blocks_stacked_peer_conf_vpn_qr(self):
        body = self._render_client()
        self.assertIn("class=stack", body)
        self.assertNotIn("class=grid", body)
        i_peer = body.index("<h2>Пир</h2>")
        i_conf = body.index("<h2>Конфиг</h2>")
        i_vpn = body.index("<h2>vpn://</h2>")
        i_qr = body.index("<h2>QR</h2>")
        self.assertLess(i_peer, i_conf)
        self.assertLess(i_conf, i_vpn)
        self.assertLess(i_vpn, i_qr)

    def test_peer_buttons_and_qr_new_window(self):
        body = self._render_client()
        peer = body[body.index("<h2>Пир</h2>"):body.index("<h2>Конфиг</h2>")]
        self.assertIn(">Пересоздать<", peer)
        self.assertIn("Скачать .conf", peer)
        self.assertIn("QR.png", peer)
        self.assertIn("target=_blank", peer)
        self.assertIn("/client-qr?name=alice", peer)
        # each block is its own card
        self.assertEqual(body.count("<div class=card>"), 4)

    def test_peer_actions_single_row(self):
        body = self._render_client()
        peer = body[body.index("<h2>Пир</h2>"):body.index("<h2>Конфиг</h2>")]
        self.assertIn("<div class=actions>", peer)
        act = peer[peer.index("<div class=actions>"):]
        self.assertLess(act.index(">Пересоздать<"), act.index("Скачать .conf"))
        self.assertLess(act.index("Скачать .conf"), act.index("QR.png"))
        from awg_panel.server import STYLE_CSS
        self.assertIn(".actions{display:flex", STYLE_CSS)
        self.assertIn("margin-top:12px", STYLE_CSS)
        self.assertIn(".actions form{margin:0}", STYLE_CSS)

    def test_copy_buttons_conf_and_vpn(self):
        from awg_panel.server import COPY_JS, COPY_TAG
        body = self._render_client()
        i_conf_pre = body.index('id=conf-pre')
        i_vpn_pre = body.index('id=vpn-pre')
        self.assertLess(body.index("<h2>Конфиг</h2>"), i_conf_pre)
        self.assertLess(i_conf_pre, body.index("data-src=conf-pre"))
        self.assertLess(body.index("<h2>vpn://</h2>"), i_vpn_pre)
        self.assertLess(i_vpn_pre, body.index("data-src=vpn-pre"))
        self.assertEqual(body.count(">Скопировать<"), 2)
        # 0.1.9: CSP (script-src 'self') forbids inline scripts, so the page
        # only references the external file; the logic itself is asserted
        # against COPY_JS below and served by test_copy_js_static_route.
        self.assertIn(COPY_TAG, body)
        self.assertIn('/static/copy.js', body)
        self.assertNotIn("navigator.clipboard.writeText", body)
        self.assertIn("navigator.clipboard.writeText", COPY_JS)
        self.assertIn("execCommand('copy')", COPY_JS)
        self.assertIn("createElement('textarea')", COPY_JS)
        self.assertIn("Не скопировалось", COPY_JS)
        self.assertIn("DOMContentLoaded", COPY_JS)
        # 0.1.14: состояние «Скопировано» видно и цветом (класс copied),
        # disabled-кнопки — серым текстом вместо чёрного.
        self.assertIn("classList.add('copied')", COPY_JS)
        self.assertIn("classList.remove('copied')", COPY_JS)
        from awg_panel.server import STYLE_CSS as _CSS
        self.assertIn("button.copied{", _CSS)
        self.assertIn("button:disabled{", _CSS)

    def test_copy_js_static_route(self):
        # /static/copy.js must be served (200 + javascript) without auth,
        # otherwise CSP script-src 'self' leaves the buttons dead.
        from io import BytesIO
        from awg_panel import server as srv
        h = srv.Handler.__new__(srv.Handler)
        h.command = "GET"
        h.path = "/static/copy.js"
        h.wfile = BytesIO()
        sent = {}

        def send_response(code, msg=None):
            sent["code"] = code

        def send_header(k, v):
            sent.setdefault("hdrs", []).append((k, v))

        h.send_response = send_response
        h.send_header = send_header
        h.end_headers = lambda: sent.setdefault("ended", True)
        h.do_GET()
        self.assertEqual(sent.get("code"), 200)
        hdrs = dict(sent.get("hdrs", []))
        self.assertIn("javascript", hdrs.get("Content-Type", ""))
        csp = hdrs.get("Content-Security-Policy", "")
        self.assertIn("script-src 'self'", csp)
        raw = h.wfile.getvalue()
        self.assertIn(b"awgCopy", raw)
        self.assertEqual(raw.decode("utf-8"), srv.COPY_JS)

    def test_buttons_unified_font(self):
        from awg_panel.server import STYLE_CSS
        rule = STYLE_CSS.split("button,.btn{", 1)[1].split("}", 1)[0]
        # <button> uses the UA default font, <a class=btn> inherits the page
        # font — without font:inherit they render at different sizes.
        self.assertIn("font:inherit", rule)
        self.assertIn("padding:8px 14px", rule)

    def test_no_page_level_hscroll_css(self):
        from awg_panel.server import STYLE_CSS
        self.assertIn("body{", STYLE_CSS)
        self.assertIn("overflow-x:hidden", STYLE_CSS)
        self.assertNotIn(".grid", STYLE_CSS)
        self.assertNotIn(".tabs", STYLE_CSS)
        self.assertIn("min-width:0", STYLE_CSS)
        # overflowing element itself scrolls internally
        self.assertIn("pre{", STYLE_CSS)
        pre_rule = STYLE_CSS.split("pre{", 1)[1].split("}", 1)[0]
        self.assertIn("overflow:auto", pre_rule)
        self.assertIn("max-width:100%", pre_rule)


class TestClientsListPage(unittest.TestCase):
    def _render(self, prefix="user_", rand_bytes=8):
        from types import SimpleNamespace
        from unittest import mock
        from awg_panel import server as srv
        from awg_panel.config import PanelConfig
        from awg_panel.manage import ManageResult
        h = srv.Handler.__new__(srv.Handler)
        cfg = PanelConfig()
        cfg.client_name_prefix = prefix
        cfg.client_name_rand_bytes = rand_bytes
        h.cfg = cfg
        clients = [{"name": "alice", "ip": "10.0.0.2", "status": "active",
                    "status_code": "active", "expires_at": None}]
        with mock.patch.object(srv.Handler, "_sess",
                               lambda self: SimpleNamespace(csrf="t")), \
             mock.patch.object(srv, "cmd_list", lambda ms: ManageResult(True, 0, clients, "")), \
             mock.patch.object(srv, "cmd_stats", lambda ms: ManageResult(True, 0, [], "")), \
             mock.patch.object(srv, "run_helper", lambda helper, *a, **k: (0, b"", "")):
            return h._page_clients()

    def test_delete_disabled_until_checked(self):
        body = self._render()
        # кнопка удаления неактивна без выбора и сабмитит форму с чекбоксами
        self.assertIn('id=delbtn disabled', body)
        self.assertIn('form=delf', body)
        # JS включает/выключает её по чекбоксам (внешний файл, не инлайн)
        self.assertNotIn("getRandomValues", body)
        self.assertNotIn("<script>", body)
        from awg_panel.server import CLIENTS_JS, CLIENTS_TAG
        self.assertIn(CLIENTS_TAG, body)
        self.assertIn("getElementById('delbtn')", CLIENTS_JS)
        self.assertIn("b.disabled=!any", CLIENTS_JS)
        self.assertIn("DOMContentLoaded", CLIENTS_JS)

    def test_add_and_delete_single_row(self):
        body = self._render()
        i_add = body.index(">Добавить<")
        i_del = body.index(">Удалить выбранные<")
        self.assertLess(i_add, i_del)
        # обе кнопки лежат в одном <div class=row>, форма #delf (таблица)
        # идёт уже после него
        row_start = body.rindex("<div class=row>", 0, i_add)
        row_end = body.index("</div>", i_add)
        self.assertLess(i_del, row_end)
        self.assertIn("form=addf", body[row_start:row_end])
        self.assertIn("form=delf", body[row_start:row_end])
        self.assertIn("id=delf", body[row_end:])

    def test_generate_button_and_data_attrs(self):
        body = self._render(prefix="vpn-", rand_bytes=9)
        self.assertIn(">Сгенерировать имя<", body)
        self.assertIn("data-prefix='vpn-'", body)
        self.assertIn("data-rand-bytes='9'", body)
        self.assertIn("id=names", body)
        from awg_panel.server import CLIENTS_JS
        self.assertIn("getRandomValues", CLIENTS_JS)
        self.assertIn("Math.random", CLIENTS_JS)
        self.assertIn("data-prefix", CLIENTS_JS)

    def test_generate_appends_with_space(self):
        # повторный клик дописывает имя через пробел, а не затирает поле
        from awg_panel.server import CLIENTS_JS
        gen = CLIENTS_JS[CLIENTS_JS.index("function awgClientsGen"):]
        self.assertIn("cur.replace(", gen)
        self.assertIn("+' '+gen", gen)
        self.assertIn("cur.trim()", gen)

    def test_disabled_and_copied_styles(self):
        from awg_panel.server import STYLE_CSS
        dis = STYLE_CSS.split("button:disabled{", 1)[1].split("}", 1)[0]
        self.assertIn("color:#9ca3af", dis)
        self.assertIn("cursor:not-allowed", dis)
        cop = STYLE_CSS.split("button.copied{", 1)[1].split("}", 1)[0]
        self.assertIn("color:#9ca3af", cop)

    def test_clients_js_static_route(self):
        # /static/clients.js должен отдаваться (200 + javascript) без авторизации,
        # иначе CSP script-src 'self' оставит кнопки мёртвыми.
        from io import BytesIO
        from awg_panel import server as srv
        h = srv.Handler.__new__(srv.Handler)
        h.command = "GET"
        h.path = "/static/clients.js"
        h.wfile = BytesIO()
        sent = {}

        def send_response(code, msg=None):
            sent["code"] = code

        def send_header(k, v):
            sent.setdefault("hdrs", []).append((k, v))

        h.send_response = send_response
        h.send_header = send_header
        h.end_headers = lambda: sent.setdefault("ended", True)
        h.do_GET()
        self.assertEqual(sent.get("code"), 200)
        hdrs = dict(sent.get("hdrs", []))
        self.assertIn("javascript", hdrs.get("Content-Type", ""))
        csp = hdrs.get("Content-Security-Policy", "")
        self.assertIn("script-src 'self'", csp)
        raw = h.wfile.getvalue()
        self.assertIn(b"awgClients", raw)
        self.assertEqual(raw.decode("utf-8"), srv.CLIENTS_JS)


class TestClientsDeleteConfirm(unittest.TestCase):
    def _post(self, path, form, cmd_remove=None):
        from types import SimpleNamespace
        from awg_panel import server as srv
        from awg_panel.config import PanelConfig
        h = srv.Handler.__new__(srv.Handler)
        h.cfg = PanelConfig()
        h.path = path
        h.command = "POST"
        h.client_address = ("127.0.0.1", 12345)
        authed = SimpleNamespace(csrf="t", sid="s")
        h._authed = authed
        h._sess = lambda: authed
        h._require_auth = lambda: authed
        h._parse_form = lambda: form
        h._check_csrf = lambda f: True
        captured = {}
        h._send_auth = lambda code, body, *a, **k: captured.setdefault("send", (code, body))
        h._redirect = lambda where, cookie=None: captured.setdefault("redirect", where)
        if cmd_remove is not None:
            import unittest.mock as mock
            with mock.patch.object(srv, "cmd_remove", cmd_remove):
                h.do_POST()
        else:
            h.do_POST()
        return captured

    def test_delete_confirm_page(self):
        from types import SimpleNamespace
        from awg_panel import server as srv
        from awg_panel.config import PanelConfig
        h = srv.Handler.__new__(srv.Handler)
        h.cfg = PanelConfig()
        h._sess = lambda: SimpleNamespace(csrf="t")
        body = h._page_clients_delete_confirm(["alice", "bob"])
        self.assertIn("Удаление пользователей: Вы уверены?", body)
        self.assertIn("alice", body)
        self.assertIn("bob", body)
        self.assertIn("/clients/delete/confirm", body)
        self.assertIn("Подтвердить", body)
        self.assertIn("Отмена", body)

    def test_delete_first_post_does_not_remove(self):
        from awg_panel.manage import ManageResult
        calls = []
        cap = self._post("/clients/delete", {"sel": ["alice"], "csrf": "t"},
                         cmd_remove=lambda ms, names: calls.append(names) or ManageResult(True, 0, None, ""))
        self.assertEqual(calls, [])
        code, body = cap["send"]
        self.assertEqual(code, 200)
        self.assertIn("Удаление пользователей: Вы уверены?", body)

    def test_delete_confirm_post_removes(self):
        calls = []
        from awg_panel.manage import ManageResult
        cap = self._post("/clients/delete/confirm", {"sel": ["alice"], "csrf": "t"},
                         cmd_remove=lambda ms, names: calls.append(names) or ManageResult(True, 0, None, ""))
        self.assertEqual(calls, [["alice"]])
        self.assertEqual(cap.get("redirect"), "/clients")


class TestLoginPage(unittest.TestCase):
    def _page(self, err=""):
        from awg_panel import server as srv
        h = srv.Handler.__new__(srv.Handler)
        return h._page_login(err)

    def test_no_nav_on_login(self):
        body = self._page()
        # синий сайдбар с заголовком остался, пунктов меню нет
        self.assertIn("<aside>", body)
        self.assertIn("AWG Panel", body)
        self.assertIn("<nav></nav>", body)
        self.assertNotIn(">Система<", body)
        self.assertNotIn(">Клиенты<", body)
        self.assertNotIn(">Справка<", body)
        self.assertNotIn(">Выход<", body)
        self.assertNotIn("/logout", body)
        self.assertNotIn("/clients", body)
        self.assertNotIn("/system", body)
        self.assertNotIn("/help", body)

    def test_login_error_shown_without_nav(self):
        body = self._page("Неверный логин или пароль")
        self.assertIn("Неверный логин или пароль", body)
        self.assertIn("<nav></nav>", body)

    def test_autofocus_on_username(self):
        body = self._page()
        self.assertIn("<input name=user autofocus>", body)
        self.assertEqual(body.count("autofocus"), 1)

    def test_nav_present_elsewhere(self):
        from awg_panel import server as srv
        h = srv.Handler.__new__(srv.Handler)
        full = h._layout("T", "system", "b", "csrf")
        self.assertIn(">Система<", full)
        self.assertIn(">Клиенты<", full)
        self.assertIn(">Справка<", full)
        self.assertIn('href="/help"', full)

    def test_logout_pinned_to_bottom(self):
        from awg_panel import server as srv
        h = srv.Handler.__new__(srv.Handler)
        body = h._layout("T", "system", "b", "csrf")
        # «Выход» идёт последним в nav, CSS прижимает его к низу сайдбара
        self.assertLess(body.index("/clients"), body.index("navlogout"))
        self.assertIn("nav{display:flex", srv.STYLE_CSS)
        self.assertIn("flex-direction:column", srv.STYLE_CSS)
        logout_rule = srv.STYLE_CSS.split("nav form.navlogout{", 1)[1].split("}", 1)[0]
        self.assertIn("margin:auto 0 0", logout_rule)
        # сайдбар привязан к вьюпорту: низ меню = низ видимой части,
        # скроллить страницу ради «Выхода» не нужно
        aside_rule = srv.STYLE_CSS.split("aside{", 1)[1].split("}", 1)[0]
        self.assertIn("position:sticky", aside_rule)
        self.assertIn("top:0", aside_rule)
        self.assertIn("height:100vh", aside_rule)

    def test_version_without_github_link(self):
        from awg_panel import __version__
        from awg_panel import server as srv
        # ссылка на github убрана: версия осталась, констант больше нет
        self.assertFalse(hasattr(srv, "GITHUB_URL"))
        self.assertFalse(hasattr(srv, "INSTALLER_URL"))
        h = srv.Handler.__new__(srv.Handler)
        full = h._layout("T", "system", "b", "csrf")
        self.assertIn(f"v{__version__}", full)
        self.assertNotIn("github.com", full)


class TestHttpRedirect(unittest.TestCase):
    def test_build_url(self):
        from awg_panel.server import build_https_redirect_url
        self.assertEqual(
            build_https_redirect_url("10.129.110.110:80", "/", 8443),
            "https://10.129.110.110:8443/")
        self.assertEqual(
            build_https_redirect_url("10.129.110.110", "/system", 8443),
            "https://10.129.110.110:8443/system")
        # 443 не пишется в URL
        self.assertEqual(
            build_https_redirect_url("example.com:80", "/clients", 443),
            "https://example.com/clients")
        self.assertEqual(
            build_https_redirect_url("[::1]:80", "/", 8443),
            "https://[::1]:8443/")
        # CRLF в Host -> отказ (защита от response-splitting/open-redirect)
        self.assertIsNone(build_https_redirect_url("evil.com\r\nX: y", "/", 8443))
        self.assertIsNone(build_https_redirect_url("a/b", "/", 8443))
        self.assertIsNone(build_https_redirect_url(None, "/", 8443))
        self.assertIsNone(build_https_redirect_url("", "/", 8443))
        # CRLF в path -> сброс на /
        self.assertEqual(
            build_https_redirect_url("example.com", "/a\r\nb", 8443),
            "https://example.com:8443/")

    def test_config_redirect_port(self):
        import tempfile
        from awg_panel.config import load_config
        users = "[users]\nuser.1 = admin\npassword.1 = admin\n"
        with tempfile.NamedTemporaryFile("w+", suffix=".ini", delete=False) as f:
            f.write("[server]\nport = 8443\n" + users)
            p = f.name
        self.assertEqual(load_config(p).http_redirect_port, 80)
        with tempfile.NamedTemporaryFile("w+", suffix=".ini", delete=False) as f:
            f.write("[server]\nport = 8443\nhttp_redirect_port = 0\n" + users)
            p2 = f.name
        self.assertEqual(load_config(p2).http_redirect_port, 0)
        with tempfile.NamedTemporaryFile("w+", suffix=".ini", delete=False) as f:
            f.write("[server]\nport = 8443\nhttp_redirect_port = garbage\n" + users)
            p3 = f.name
        self.assertEqual(load_config(p3).http_redirect_port, 80)
        with tempfile.NamedTemporaryFile("w+", suffix=".ini", delete=False) as f:
            f.write("[server]\nport = 8443\nhttp_redirect_port = 99999\n" + users)
            p4 = f.name
        self.assertEqual(load_config(p4).http_redirect_port, 80)

    def test_live_redirect_only_301_no_cookies(self):
        import http.client
        import socket
        import time
        from awg_panel.config import PanelConfig
        from awg_panel.server import start_http_redirector

        def free():
            s = socket.socket()
            s.bind(("127.0.0.1", 0))
            p = s.getsockname()[1]
            s.close()
            return p

        rport, hport = free(), free()
        cfg = PanelConfig(host="127.0.0.1", port=hport, http_redirect_port=rport)
        srv = start_http_redirector(cfg)
        self.assertIsNotNone(srv)
        try:
            time.sleep(0.3)
            c = http.client.HTTPConnection("127.0.0.1", rport, timeout=5)
            c.request("GET", "/system", headers={"Host": "127.0.0.1"})
            r = c.getresponse()
            r.read()
            self.assertEqual(r.status, 301)
            self.assertEqual(r.getheader("Location"),
                             f"https://127.0.0.1:{hport}/system")
            self.assertIsNone(r.getheader("Set-Cookie"))
            # POST тоже только редирект (тело в cleartext отбрасывается)
            c2 = http.client.HTTPConnection("127.0.0.1", rport, timeout=5)
            c2.request("POST", "/login", body="user=admin",
                       headers={"Host": "127.0.0.1"})
            r2 = c2.getresponse()
            r2.read()
            self.assertEqual(r2.status, 301)
            # кривой Host -> 400, а не редирект наружу
            c3 = http.client.HTTPConnection("127.0.0.1", rport, timeout=5)
            c3.request("GET", "/", headers={"Host": "bad/host"})
            r3 = c3.getresponse()
            r3.read()
            self.assertEqual(r3.status, 400)
        finally:
            srv.shutdown()
            srv.server_close()

    def test_same_port_disables_redirector(self):
        from awg_panel.config import PanelConfig
        from awg_panel.server import start_http_redirector
        cfg = PanelConfig(host="127.0.0.1", port=8443, http_redirect_port=8443)
        self.assertIsNone(start_http_redirector(cfg))
        cfg2 = PanelConfig(host="127.0.0.1", port=8443, http_redirect_port=0)
        self.assertIsNone(start_http_redirector(cfg2))


class TestClientsSorting(unittest.TestCase):
    def test_sort_name(self):
        from awg_panel.server import sort_clients
        clients = [{"name": "bob"}, {"name": "Alice"}, {"name": "carol"}]
        got = [c["name"] for c in sort_clients(clients, {}, "name", "asc")]
        self.assertEqual(got, ["Alice", "bob", "carol"])
        got_d = [c["name"] for c in sort_clients(clients, {}, "name", "desc")]
        self.assertEqual(got_d, ["carol", "bob", "Alice"])

    def test_sort_ip_numeric(self):
        from awg_panel.server import sort_clients
        clients = [{"name": "a", "ip": "10.0.0.10"},
                   {"name": "b", "ip": "10.0.0.2"},
                   {"name": "c", "ip": "?"}]
        got = [c["name"] for c in sort_clients(clients, {}, "ip", "asc")]
        self.assertEqual(got, ["b", "a", "c"])
        got_d = [c["name"] for c in sort_clients(clients, {}, "ip", "desc")]
        self.assertEqual(got_d, ["c", "a", "b"])

    def test_sort_status_rank(self):
        from awg_panel.server import sort_clients
        clients = [{"name": "x", "status": "s", "status_code": "no_data"},
                   {"name": "a", "status": "s", "status_code": "active"},
                   {"name": "m", "status": "s", "status_code": "recent"}]
        got = [c["name"] for c in sort_clients(clients, {}, "status", "asc")]
        self.assertEqual(got, ["a", "m", "x"])

    def test_sort_traffic_sum(self):
        from awg_panel.server import sort_clients
        clients = [{"name": "a"}, {"name": "b"}, {"name": "c"}]
        stats = {"a": {"rx": 10, "tx": 5}, "b": {"rx": 100, "tx": 0}}
        got = [c["name"] for c in sort_clients(clients, stats, "traffic", "asc")]
        self.assertEqual(got, ["c", "a", "b"])
        got_d = [c["name"] for c in sort_clients(clients, stats, "traffic", "desc")]
        self.assertEqual(got_d, ["b", "a", "c"])

    def test_sort_expires_inf_last(self):
        from awg_panel.server import sort_clients
        clients = [{"name": "inf", "expires_at": None},
                   {"name": "old", "expires_at": 100},
                   {"name": "new", "expires_at": 200}]
        got = [c["name"] for c in sort_clients(clients, {}, "expires", "asc")]
        self.assertEqual(got, ["old", "new", "inf"])

    def test_sort_invalid_fallback(self):
        from awg_panel.server import sort_clients
        clients = [{"name": "b"}, {"name": "a"}]
        got = [c["name"] for c in sort_clients(clients, {}, "bad", "bad")]
        self.assertEqual(got, ["a", "b"])

    def test_table_headers_are_sort_links(self):
        from types import SimpleNamespace
        from unittest import mock
        from awg_panel import server as srv
        from awg_panel.config import PanelConfig
        from awg_panel.manage import ManageResult
        h = srv.Handler.__new__(srv.Handler)
        h.cfg = PanelConfig()
        clients = [{"name": "alice", "ip": "10.0.0.2", "status": "active",
                    "status_code": "active", "expires_at": None}]
        with mock.patch.object(srv.Handler, "_sess",
                               lambda self: SimpleNamespace(csrf="t")), \
             mock.patch.object(srv, "cmd_list", lambda ms: ManageResult(True, 0, clients, "")), \
             mock.patch.object(srv, "cmd_stats", lambda ms: ManageResult(True, 0, [], "")), \
             mock.patch.object(srv, "run_helper", lambda helper, *a, **k: (0, b"", "")):
            body = h._page_clients("", "ip", "asc")
        for field in ("sort=name", "sort=ip", "sort=status", "sort=traffic", "sort=expires"):
            self.assertIn(field, body)
        # active sort shows arrow and flips dir
        self.assertIn("sort=ip&dir=desc", body)
        self.assertIn("STYLE_CSS" if False else "th a{", srv.STYLE_CSS)

    def test_table_rows_follow_sort(self):
        from awg_panel.server import sort_clients
        # end-to-end via _clients_table order: bob (.2) before alice (.10) on ip asc
        from types import SimpleNamespace
        from unittest import mock
        from awg_panel import server as srv
        from awg_panel.config import PanelConfig
        from awg_panel.manage import ManageResult
        h = srv.Handler.__new__(srv.Handler)
        h.cfg = PanelConfig()
        clients = [{"name": "alice", "ip": "10.0.0.10", "status": "active",
                    "status_code": "active", "expires_at": None},
                   {"name": "bob", "ip": "10.0.0.2", "status": "active",
                    "status_code": "active", "expires_at": None}]
        with mock.patch.object(srv.Handler, "_sess",
                               lambda self: SimpleNamespace(csrf="t")), \
             mock.patch.object(srv, "cmd_list", lambda ms: ManageResult(True, 0, clients, "")), \
             mock.patch.object(srv, "cmd_stats", lambda ms: ManageResult(True, 0, [], "")), \
             mock.patch.object(srv, "run_helper", lambda helper, *a, **k: (0, b"", "")):
            body_ip = h._page_clients("", "ip", "asc")
        self.assertLess(body_ip.index("bob"), body_ip.index("alice"))
        _ = sort_clients  # keep import used


class TestSystemPage(unittest.TestCase):
    def _handler(self):
        from types import SimpleNamespace
        from awg_panel import server as srv
        from awg_panel.config import PanelConfig
        h = srv.Handler.__new__(srv.Handler)
        h.cfg = PanelConfig()
        h._sess = lambda: SimpleNamespace(csrf="t")
        return h, srv

    def test_blocks_order_no_tabs(self):
        from unittest import mock
        h, srv = self._handler()
        with mock.patch.object(srv.Handler, "_awg_block",
                               lambda self: "<div class=card><h2>AWG</h2></div>"), \
             mock.patch.object(srv.Handler, "_system_block",
                               lambda self: "<div class=card><h2>Система</h2></div>"), \
             mock.patch.object(srv.Handler, "_interfaces_block",
                               lambda self: "<div class=card><h2>Интерфейсы</h2></div>"), \
             mock.patch.object(srv.Handler, "_journal_block",
                               lambda self: "<div class=card><h2>Журнал входов</h2></div>"):
            body = h._page_system()
        self.assertNotIn("class=tabs", body)
        self.assertNotIn("tab=awg", body)
        i_sys = body.index("<h2>Система</h2>")
        i_if = body.index("<h2>Интерфейсы</h2>")
        i_awg = body.index("<h2>AWG</h2>")
        i_act = body.index("Перезагрузить сервер")
        i_jour = body.index("Журнал входов")
        self.assertLess(i_sys, i_if)
        self.assertLess(i_if, i_awg)
        self.assertLess(i_awg, i_act)
        self.assertLess(i_act, i_jour)
        self.assertIn("Перезапустить awg", body)
        self.assertIn("/system/reboot", body)
        self.assertIn("/system/awg-restart", body)

    def test_confirm_texts(self):
        h, _ = self._handler()
        reboot = h._page_system_confirm("reboot")
        self.assertIn("Перезагрузка сервера: Вы уверены?", reboot)
        self.assertIn("/system/reboot", reboot)
        awg = h._page_system_confirm("awg-restart")
        self.assertIn("Перезапуск AWG: Вы уверены?", awg)
        self.assertIn("/system/awg-restart", awg)

    def test_awg_restart_calls_systemctl(self):
        import subprocess
        from unittest import mock
        from awg_panel import manage
        seen = {}

        def fake_run(cmd, **kw):
            seen["cmd"] = cmd
            return subprocess.CompletedProcess(cmd, 0, "", "")

        with mock.patch.object(manage, "_is_root", lambda: True), \
             mock.patch.object(manage.subprocess, "run", fake_run):
            r = manage.cmd_awg_restart()
        self.assertTrue(r.ok)
        self.assertIn("systemctl", seen["cmd"][0])
        self.assertIn("awg-quick@awg0", seen["cmd"])

    def test_reboot_uses_systemctl_not_helper(self):
        from unittest import mock
        from awg_panel import manage
        from awg_panel import server as srv
        # reboot must not appear in helper allowlist (stays rejected)
        with self.assertRaises(ValueError):
            manage.run_helper("/usr/sbin/awg-panel-helper", "reboot")
        h, _ = self._handler()
        actions = h._actions_block("t")
        self.assertIn("systemctl restart awg-quick@awg0", actions)


class TestHelpPage(unittest.TestCase):
    def test_help_no_github_links(self):
        from types import SimpleNamespace
        from awg_panel import server as srv
        from awg_panel.config import PanelConfig
        h = srv.Handler.__new__(srv.Handler)
        h.cfg = PanelConfig()
        h._sess = lambda: SimpleNamespace(csrf="t")
        body = h._page_help()
        self.assertIn("<h1>Справка</h1>", body)
        self.assertNotIn("github.com", body)
        self.assertNotIn("amneziawg-installer", body)
        # активная навигация — справка
        self.assertIn('href="/help" class="on"', body)
        # ссылки на разделы справочной системы
        self.assertIn("href='/faq'", body)
        self.assertIn("href='/instructions'", body)


class TestSupportPage(unittest.TestCase):
    def test_support_page(self):
        from types import SimpleNamespace
        from awg_panel import server as srv
        from awg_panel.config import PanelConfig
        h = srv.Handler.__new__(srv.Handler)
        h.cfg = PanelConfig()
        h._sess = lambda: SimpleNamespace(csrf="t")
        body = h._page_support()
        self.assertIn("<h1>Поддержка</h1>", body)
        self.assertIn("t.me/thrsnknwldgthtsntpwr", body)
        self.assertIn('href="/support" class="on"', body)


class TestPasswordPage(unittest.TestCase):
    def _handler(self):
        from types import SimpleNamespace
        from awg_panel import server as srv
        from awg_panel.config import PanelConfig
        h = srv.Handler.__new__(srv.Handler)
        h.cfg = PanelConfig()
        h._sess = lambda: SimpleNamespace(csrf="t", username="admin")
        return h, srv

    def test_password_page_fields(self):
        h, _ = self._handler()
        body = h._page_password()
        self.assertIn("<h1>Сменить пароль</h1>", body)
        self.assertIn("name=old_password", body)
        self.assertIn("name=new_password", body)
        self.assertIn("name=new_password2", body)
        self.assertIn(">Сменить пароль<", body)
        self.assertIn('href="/system"', body)

    def test_password_confirm_page(self):
        h, _ = self._handler()
        body = h._page_password_confirm()
        self.assertIn(">Подтвердить<", body)
        self.assertIn(">Отмена<", body)
        self.assertIn("/password/confirm", body)


class TestFAQPage(unittest.TestCase):
    def test_faq_page(self):
        from types import SimpleNamespace
        from awg_panel import server as srv
        from awg_panel.config import PanelConfig
        h = srv.Handler.__new__(srv.Handler)
        h.cfg = PanelConfig()
        h._sess = lambda: SimpleNamespace(csrf="t")
        body = h._page_faq()
        self.assertIn("<h1>FAQ по панели управления</h1>", body)
        self.assertIn("Как добавить пользователя", body)
        self.assertIn("Как сменить пароль учётной записи", body)
        self.assertIn("Как перезагрузить сервер", body)
        self.assertIn("Как перезапустить AWG", body)
        self.assertIn("Как удалить клиента", body)
        self.assertIn("Как пересоздать ключи клиента (regen)", body)
        # аккордеон: details/summary
        self.assertIn("<details class=faq", body)
        self.assertIn("<summary", body)


class TestInstructionsPage(unittest.TestCase):
    def test_instructions_page(self):
        from types import SimpleNamespace
        from awg_panel import server as srv
        from awg_panel.config import PanelConfig
        h = srv.Handler.__new__(srv.Handler)
        h.cfg = PanelConfig()
        h._sess = lambda: SimpleNamespace(csrf="t")
        body = h._page_instructions()
        self.assertIn("<h1>Инструкции для клиентов</h1>", body)
        self.assertIn("AmneziaVPN", body)
        self.assertIn("AmneziaWG", body)
        self.assertNotIn("DefaultVPN", body)
        self.assertIn("docs.amnezia.org", body)
        self.assertIn("connect-via-text-key", body)
        self.assertIn("connect-via-config", body)
        self.assertIn("connect-via-qr-code", body)
        self.assertIn("use-amneziawg-app", body)
        self.assertNotIn("Windows", body)
        self.assertNotIn("Android", body)
        self.assertNotIn("iOS", body)
        # аккордеон: details/summary
        self.assertIn("<details class=acc", body)
        self.assertIn("<summary", body)


if __name__ == "__main__":
    unittest.main()
