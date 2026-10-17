-- Database made by Posture Cockpit 0.3.0 (tests/data/make_legacy_databases.py)
BEGIN TRANSACTION;
CREATE TABLE api_tokens (
        id INTEGER PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        name TEXT NOT NULL,
        token_hash TEXT UNIQUE NOT NULL,
        created_at TEXT NOT NULL,
        last_used TEXT
    );
INSERT INTO "api_tokens" VALUES(1,1,'home-assistant','1d07f0b8509d46abf282de35e3617f53e3ed68a752fe691b0816a1ccf048ed41','2026-10-17T07:02:46+00:00',NULL);
CREATE TABLE audit_log (
        id INTEGER PRIMARY KEY,
        at TEXT NOT NULL,
        user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
        username TEXT NOT NULL DEFAULT '',        -- kept when the account is deleted
        action TEXT NOT NULL,                     -- e.g. "login.failed", "perimeter.created", "scan.internal"
        target TEXT NOT NULL DEFAULT '',
        detail TEXT NOT NULL DEFAULT '{}',        -- JSON
        client TEXT NOT NULL DEFAULT ''           -- address of the browser or script
    );
INSERT INTO "audit_log" VALUES(1,'2026-10-17T07:02:46+00:00',1,'vincent','setup','','{}','192.0.2.10');
INSERT INTO "audit_log" VALUES(2,'2026-10-17T07:02:46+00:00',1,'vincent','login','','{}','192.0.2.10');
CREATE TABLE domains (
        id INTEGER PRIMARY KEY,
        name TEXT UNIQUE NOT NULL,                -- normalized: lower case, ASCII
        created_at TEXT NOT NULL,
        created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
        dns_host TEXT NOT NULL DEFAULT ''         -- DNS host chosen on the plan page ('' = detected)
    , perimeter_id INTEGER REFERENCES perimeters(id) ON DELETE RESTRICT);
INSERT INTO "domains" VALUES(1,'menuiserie-dupont.example','2026-10-17T07:02:46+00:00',1,'',NULL);
INSERT INTO "domains" VALUES(2,'example.org','2026-10-17T07:02:46+00:00',1,'',NULL);
CREATE TABLE findings (
        scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
        check_id TEXT NOT NULL,
        category TEXT NOT NULL,
        weight INTEGER NOT NULL,
        status TEXT NOT NULL,
        outcome TEXT NOT NULL,                    -- JSON, see Finding.outcome_json()
        PRIMARY KEY (scan_id, check_id)
    );
INSERT INTO "findings" VALUES(1,'mail.mx','mail',1,'info','{"summary": "mail.mx.list", "params": {"hosts": "mx1.mail.ovh.net, mx2.mail.ovh.net"}, "evidence": {"mx": ["1 mx1.mail.ovh.net.", "5 mx2.mail.ovh.net."]}}');
INSERT INTO "findings" VALUES(1,'mail.spf','mail',8,'ok','{"summary": "mail.spf.ok", "params": {"policy": "~all"}, "evidence": {"records": ["v=spf1 include:mx.ovh.com ~all"], "lookups": 1}}');
INSERT INTO "findings" VALUES(1,'mail.dmarc','mail',10,'fail','{"summary": "mail.dmarc.missing", "params": {}, "evidence": {}, "remedy": {"minutes": 10, "effort": "easy", "dns": [{"action": "add", "rtype": "TXT", "name": "_dmarc", "value": "v=DMARC1; p=none; rua=mailto:dmarc@menuiserie-dupont.example"}], "message": "", "how": "mail.dmarc.how"}}');
INSERT INTO "findings" VALUES(1,'mail.dkim','mail',4,'ok','{"summary": "mail.dkim.found", "params": {"selectors": "default"}, "evidence": {"selectors": {"default": "rsa 2048"}}}');
INSERT INTO "findings" VALUES(1,'mail.mta_sts','mail',3,'warn','{"summary": "mail.mta_sts.missing", "params": {}, "evidence": {}, "remedy": {"minutes": 30, "effort": "delegate", "dns": [], "message": "mail.mta_sts.message", "how": ""}}');
INSERT INTO "findings" VALUES(1,'mail.tls_rpt','mail',1,'warn','{"summary": "mail.tls_rpt.missing", "params": {}, "evidence": {"records": []}, "remedy": {"minutes": 5, "effort": "easy", "dns": [{"action": "add", "rtype": "TXT", "name": "_smtp._tls", "value": "v=TLSRPTv1; rua=mailto:tls-reports@menuiserie-dupont.example"}], "message": "", "how": "mail.tls_rpt.how"}}');
INSERT INTO "findings" VALUES(1,'tls.certificate','tls',10,'fail','{"summary": "tls.certificate.expires_soon", "params": {"host": "menuiserie-dupont.example", "days": 9, "issuer": "Sectigo Limited", "expires_on": "2026-10-19"}, "evidence": {"menuiserie-dupont.example": {"issuer": "Sectigo Limited", "expires": "2026-10-19", "names": ["menuiserie-dupont.example", "www.menuiserie-dupont.example"], "trusted": true, "problem": ""}, "www.menuiserie-dupont.example": {"issuer": "Sectigo Limited", "expires": "2026-10-19", "names": ["menuiserie-dupont.example", "www.menuiserie-dupont.example"], "trusted": true, "problem": ""}}, "remedy": {"minutes": 5, "effort": "delegate", "dns": [], "message": "tls.certificate.renew_message", "how": ""}}');
INSERT INTO "findings" VALUES(1,'tls.protocols','tls',5,'fail','{"summary": "tls.protocols.obsolete", "params": {"versions": "TLS 1.0, TLS 1.1"}, "evidence": {"accepted": {"menuiserie-dupont.example": {"TLSv1": true, "TLSv1.1": true, "TLSv1.3": true}, "www.menuiserie-dupont.example": {"TLSv1": true, "TLSv1.1": true, "TLSv1.3": true}}}, "remedy": {"minutes": 15, "effort": "delegate", "dns": [], "message": "tls.protocols.message", "how": ""}}');
INSERT INTO "findings" VALUES(1,'tls.key','tls',3,'ok','{"summary": "tls.key.ok", "params": {"key": "RSA 2048"}, "evidence": {"menuiserie-dupont.example": "RSA 2048", "www.menuiserie-dupont.example": "RSA 2048"}}');
INSERT INTO "findings" VALUES(1,'web.https_redirect','web',8,'ok','{"summary": "web.https_redirect.ok", "params": {}, "evidence": {"menuiserie-dupont.example": "301 http://menuiserie-dupont.example/ \u2192 https://www.menuiserie-dupont.example/", "www.menuiserie-dupont.example": "301 http://www.menuiserie-dupont.example/ \u2192 https://www.menuiserie-dupont.example/"}}');
INSERT INTO "findings" VALUES(1,'web.hsts','web',6,'warn','{"summary": "web.hsts.short", "params": {"host": "www.menuiserie-dupont.example", "days": 1}, "evidence": {"url": "https://www.menuiserie-dupont.example/", "header": "max-age=86400"}, "remedy": {"minutes": 15, "effort": "delegate", "dns": [], "message": "web.hsts.message", "how": ""}}');
INSERT INTO "findings" VALUES(1,'web.csp','web',4,'ok','{"summary": "web.csp.ok", "params": {}, "evidence": {"https://www.menuiserie-dupont.example/": "default-src ''self''; img-src ''self'' data:; frame-ancestors ''self''"}}');
INSERT INTO "findings" VALUES(1,'web.framing','web',3,'ok','{"summary": "web.framing.ok", "params": {}, "evidence": {"https://www.menuiserie-dupont.example/": {"x-frame-options": "", "content-security-policy": "default-src ''self''; img-src ''self'' data:; frame-ancestors ''self''"}}}');
INSERT INTO "findings" VALUES(1,'web.nosniff','web',2,'ok','{"summary": "web.nosniff.ok", "params": {}, "evidence": {"https://www.menuiserie-dupont.example/": "nosniff"}}');
INSERT INTO "findings" VALUES(1,'web.referrer','web',1,'ok','{"summary": "web.referrer.ok", "params": {}, "evidence": {"https://www.menuiserie-dupont.example/": "strict-origin-when-cross-origin"}}');
INSERT INTO "findings" VALUES(1,'web.server_banner','web',2,'warn','{"summary": "web.server_banner.version", "params": {"header": "server", "value": "Apache/2.4.41 (Ubuntu)"}, "evidence": {"url": "https://www.menuiserie-dupont.example/", "server": "Apache/2.4.41 (Ubuntu)"}, "remedy": {"minutes": 10, "effort": "delegate", "dns": [], "message": "web.server_banner.message", "how": ""}}');
INSERT INTO "findings" VALUES(1,'web.security_txt','web',1,'warn','{"summary": "web.security_txt.missing", "params": {"url": "https://menuiserie-dupont.example/.well-known/security.txt"}, "evidence": {"url": "https://menuiserie-dupont.example/.well-known/security.txt", "status": 404}, "remedy": {"minutes": 10, "effort": "delegate", "dns": [], "message": "web.security_txt.message", "how": ""}}');
INSERT INTO "findings" VALUES(1,'dns.nameservers','dns',4,'ok','{"summary": "dns.nameservers.ok", "params": {"count": 2, "zone": "menuiserie-dupont.example"}, "evidence": {"zone": "menuiserie-dupont.example", "nameservers": ["dns11.ovh.net", "ns11.ovh.net"]}}');
INSERT INTO "findings" VALUES(1,'dns.dnssec','dns',4,'warn','{"summary": "dns.dnssec.off", "params": {"zone": "menuiserie-dupont.example"}, "evidence": {"zone": "menuiserie-dupont.example"}, "remedy": {"minutes": 10, "effort": "easy", "dns": [], "message": "", "how": "dns.dnssec.how"}}');
INSERT INTO "findings" VALUES(1,'dns.caa','dns',2,'warn','{"summary": "dns.caa.missing", "params": {"ca": "sectigo.com"}, "evidence": {"records": [], "found_at": "menuiserie-dupont.example", "certificate_issuer": "Sectigo Limited"}, "remedy": {"minutes": 5, "effort": "easy", "dns": [{"action": "add", "rtype": "CAA", "name": "@", "value": "0 issue \"sectigo.com\""}], "message": "", "how": "dns.caa.how"}}');
INSERT INTO "findings" VALUES(2,'mail.mx','mail',1,'info','{"summary": "mail.mx.list", "params": {"hosts": "mx.example.net"}, "evidence": {"mx": ["10 mx.example.net."]}}');
INSERT INTO "findings" VALUES(2,'mail.spf','mail',8,'ok','{"summary": "mail.spf.ok", "params": {"policy": "-all"}, "evidence": {"records": ["v=spf1 mx include:_spf.example.net -all"], "lookups": 2}}');
INSERT INTO "findings" VALUES(2,'mail.dmarc','mail',10,'ok','{"summary": "mail.dmarc.enforced", "params": {"policy": "reject", "parent": "example.org"}, "evidence": {"records": ["v=DMARC1; p=reject; rua=mailto:dmarc@example.org"], "found_at": "_dmarc.example.org", "tags": {"v": "DMARC1", "p": "reject", "rua": "mailto:dmarc@example.org"}}}');
INSERT INTO "findings" VALUES(2,'mail.dkim','mail',4,'ok','{"summary": "mail.dkim.found", "params": {"selectors": "selector1"}, "evidence": {"selectors": {"selector1": "rsa 2048"}}}');
INSERT INTO "findings" VALUES(2,'mail.mta_sts','mail',3,'ok','{"summary": "mail.mta_sts.enforce", "params": {}, "evidence": {"records": ["v=STSv1; id=20261012"], "url": "https://mta-sts.example.org/.well-known/mta-sts.txt", "status": 200, "mode": "enforce", "mx_patterns": ["mx.example.net"], "max_age": 604800}}');
INSERT INTO "findings" VALUES(2,'mail.tls_rpt','mail',1,'ok','{"summary": "mail.tls_rpt.present", "params": {}, "evidence": {"record": "v=TLSRPTv1; rua=mailto:tls@example.org"}}');
INSERT INTO "findings" VALUES(2,'tls.certificate','tls',10,'ok','{"summary": "tls.certificate.ok", "params": {"host": "example.org", "days": 60, "issuer": "Let''s Encrypt", "expires_on": "2026-12-10"}, "evidence": {"example.org": {"issuer": "Let''s Encrypt", "expires": "2026-12-10", "names": ["example.org", "www.example.org"], "trusted": true, "problem": ""}, "www.example.org": {"issuer": "Let''s Encrypt", "expires": "2026-12-10", "names": ["example.org", "www.example.org"], "trusted": true, "problem": ""}}}');
INSERT INTO "findings" VALUES(2,'tls.protocols','tls',5,'ok','{"summary": "tls.protocols.ok", "params": {}, "evidence": {"accepted": {"example.org": {"TLSv1": false, "TLSv1.1": false, "TLSv1.3": true}, "www.example.org": {"TLSv1": false, "TLSv1.1": false, "TLSv1.3": true}}}}');
INSERT INTO "findings" VALUES(2,'tls.key','tls',3,'ok','{"summary": "tls.key.ok", "params": {"key": "EC 256"}, "evidence": {"example.org": "EC 256", "www.example.org": "EC 256"}}');
INSERT INTO "findings" VALUES(2,'web.https_redirect','web',8,'ok','{"summary": "web.https_redirect.ok", "params": {}, "evidence": {"example.org": "301 http://example.org/ \u2192 https://www.example.org/", "www.example.org": "301 http://www.example.org/ \u2192 https://www.example.org/"}}');
INSERT INTO "findings" VALUES(2,'web.hsts','web',6,'ok','{"summary": "web.hsts.ok", "params": {}, "evidence": {"headers": {"https://www.example.org/": "max-age=63072000; includeSubDomains"}}}');
INSERT INTO "findings" VALUES(2,'web.csp','web',4,'ok','{"summary": "web.csp.ok", "params": {}, "evidence": {"https://www.example.org/": "default-src ''self''; frame-ancestors ''none''"}}');
INSERT INTO "findings" VALUES(2,'web.framing','web',3,'ok','{"summary": "web.framing.ok", "params": {}, "evidence": {"https://www.example.org/": {"x-frame-options": "", "content-security-policy": "default-src ''self''; frame-ancestors ''none''"}}}');
INSERT INTO "findings" VALUES(2,'web.nosniff','web',2,'ok','{"summary": "web.nosniff.ok", "params": {}, "evidence": {"https://www.example.org/": "nosniff"}}');
INSERT INTO "findings" VALUES(2,'web.referrer','web',1,'ok','{"summary": "web.referrer.ok", "params": {}, "evidence": {"https://www.example.org/": "no-referrer"}}');
INSERT INTO "findings" VALUES(2,'web.server_banner','web',2,'ok','{"summary": "web.server_banner.ok", "params": {}, "evidence": {}}');
INSERT INTO "findings" VALUES(2,'web.security_txt','web',1,'ok','{"summary": "web.security_txt.ok", "params": {}, "evidence": {"url": "https://example.org/.well-known/security.txt", "status": 200}}');
INSERT INTO "findings" VALUES(2,'dns.nameservers','dns',4,'ok','{"summary": "dns.nameservers.ok", "params": {"count": 2, "zone": "example.org"}, "evidence": {"zone": "example.org", "nameservers": ["ns1.example.net", "ns2.example.net"]}}');
INSERT INTO "findings" VALUES(2,'dns.dnssec','dns',4,'ok','{"summary": "dns.dnssec.on", "params": {"zone": "example.org"}, "evidence": {"zone": "example.org", "ds": ["12345 13 2 ABCDEF"], "dnskey": 1}}');
INSERT INTO "findings" VALUES(2,'dns.caa','dns',2,'ok','{"summary": "dns.caa.present", "params": {"zone": "example.org"}, "evidence": {"records": ["0 issue \"letsencrypt.org\""], "found_at": "example.org", "certificate_issuer": "Let''s Encrypt"}}');
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
INSERT INTO "meta" VALUES('schema_version','3');
CREATE TABLE perimeters (
        id INTEGER PRIMARY KEY,
        name TEXT UNIQUE NOT NULL,
        networks TEXT NOT NULL,                   -- CIDR, one per line, inside the private ranges
        nameservers TEXT NOT NULL DEFAULT '',     -- IP addresses, one per line ('' = those of the system)
        ports TEXT NOT NULL DEFAULT '443 80',     -- ports a scan may connect to
        ca_pem TEXT NOT NULL DEFAULT '',          -- extra certificate authorities, PEM
        created_at TEXT NOT NULL,
        created_by INTEGER REFERENCES users(id) ON DELETE SET NULL
    );
CREATE TABLE rechecks (
        scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
        check_id TEXT NOT NULL,
        status TEXT NOT NULL,
        outcome TEXT NOT NULL,
        checked_at TEXT NOT NULL,
        PRIMARY KEY (scan_id, check_id)
    );
INSERT INTO "rechecks" VALUES(1,'mail.spf','ok','{"summary": "mail.spf.ok", "params": {"policy": "~all"}, "evidence": {"records": ["v=spf1 include:mx.ovh.com ~all"], "lookups": 1}}','2026-10-17T07:02:46+00:00');
CREATE TABLE recovery_codes (
        id INTEGER PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        code_hash TEXT NOT NULL,
        used_at TEXT
    );
CREATE TABLE "scans" (
            id INTEGER PRIMARY KEY,
            domain_id INTEGER NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
            started_at TEXT NOT NULL,
            duration_ms INTEGER NOT NULL,
            score INTEGER,                        -- NULL: not evaluated; updated after each recheck
            grade TEXT,                           -- NULL: not evaluated
            coverage REAL NOT NULL DEFAULT 1,     -- weight evaluated / weight applicable, 0 to 1
            version TEXT NOT NULL,                -- application version that ran the scan
            started_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
            perimeter TEXT NOT NULL DEFAULT ''    -- internal perimeter at the time of the scan ('' = Internet)
        );
INSERT INTO "scans" VALUES(1,1,'2026-10-09T12:00:00+00:00',3,57,'C',1.0,'0.3.0',1,'');
INSERT INTO "scans" VALUES(2,2,'2026-10-11T12:00:00+00:00',2,100,'A',1.0,'0.3.0',1,'');
CREATE TABLE totp (
        user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
        secret TEXT NOT NULL,
        last_step INTEGER NOT NULL DEFAULT 0,  -- last time step used: older codes are refused
        enabled_at TEXT
    );
CREATE TABLE users (
        id INTEGER PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        pw_hash TEXT NOT NULL,
        created_at TEXT NOT NULL,
        is_admin INTEGER NOT NULL DEFAULT 0,
        must_change_password INTEGER NOT NULL DEFAULT 0,  -- set when an administrator chose the password
        lang TEXT NOT NULL DEFAULT 'fr'
    );
INSERT INTO "users" VALUES(1,'vincent','scrypt$16384$8$1$3f59a41780a935f2f1e8578e68505caf$4dc18c91d34f294d10a5cdf063de28a022e720b7eea62b9f8195d166e983c9c3','2026-10-17T07:02:46+00:00',1,0,'fr');
INSERT INTO "users" VALUES(2,'lecteur','scrypt$16384$8$1$6bab99b41c3726f9f1d8844eb84feaff$169243e3dd9a0185dd463b03ad05afbad2419c16fc1e2982f90526ea08ee62cf','2026-10-17T07:02:46+00:00',0,0,'en');
CREATE INDEX audit_log_by_time ON audit_log(at);
CREATE INDEX scans_by_domain ON scans(domain_id, started_at);
COMMIT;
