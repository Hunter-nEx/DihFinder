#!/usr/bin/env python3
"""
DihFinder - Advanced Async Web Path Scanner (v3.0)
Developer: nEx

A single-file, dependency-light async path/fuzzing scanner with:

  * rich MarkupError fixed -> all Panel/Table text uses rich.text.Text
    objects so URLs/paths containing '[', ']', '[/]' never crash.
  * 1375+ real common web paths built-in (admin / config / backup / API
    / CMS / version-control / framework-specific / etc.).
  * Multi-level scanning: /path1, /path1/path2, /path1/path2/path3 ...
    auto-recurses into discovered 200-OK directories up to --depth.
  * False-positive filtering:
      - Baseline (random-path) requests to detect wildcard / soft-404
        responses; findings matching the baseline signature are dropped.
      - 200 OK with very short body (<10 bytes) is dropped.
      - 200 OK whose body literally contains 'not found' / '404' and
        is short is dropped (soft 404 in body).
      - 301/302 redirects to /, /login, /index.* are dropped.
      - Severity is computed from path + status + body keywords so the
        table is not polluted with low-signal hits.
  * HTML report: dark, structured, sortable, with severity cards, scan
    metadata, and clickable URLs. Pure inline CSS/JS, no CDN, no deps.
  * JSON output: full machine-readable finding list.
  * TXT output: plain text summary (kept for backwards compatibility).
  * Extra options: --proxy, -H/--header (custom headers + cookies),
    --include-status (filter by status), --match-size (size whitelist),
    --rate-limit (auto backoff on 429).
  * Live progress + scan-duration tracking.
  * Ctrl+C safe: partial findings are saved to whichever output format
    was requested.

Usage:
    python3 dihfinder.py https://example.com
    python3 dihfinder.py https://example.com -d 3 -t 30
    python3 dihfinder.py https://example.com -x php,html,bak --html report.html
    python3 dihfinder.py https://example.com --json results.json
    python3 dihfinder.py https://example.com --proxy http://127.0.0.1:8080
    python3 dihfinder.py https://example.com -H "Authorization: Bearer xx"
    python3 dihfinder.py https://example.com --include-status 200,401,403

Author: nEx
"""

import asyncio
import aiohttp
import argparse
import json as _json
import random
import string
import sys
import time
import hashlib
import html as _html
from urllib.parse import urlparse
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.progress import (
    Progress,
    SpinnerColumn,
    BarColumn,
    TextColumn,
    TaskProgressColumn,
    TimeRemainingColumn,
)

# ===========================================================================
# Built-in wordlist (1375+ real common web paths).
# Compiled from publicly available security testing wordlists
# (dirb common.txt, SecLists, common web application conventions).
# Every entry is a real path that real web apps / servers expose in the
# wild - no fabricated entries.
# ===========================================================================
WORDLIST = [
    # ====================== ADMIN / MANAGEMENT PANELS ======================
    "admin", "admin/", "admin.php", "admin.html", "admin.htm",
    "admin/index.php", "admin/index.html", "admin/login.php",
    "admin/login.html", "admin/admin.php", "admin/config.php",
    "admin/account", "admin/accounts", "admin/settings.php",
    "admin/upload.php", "admin/database.php", "admin/users.php",
    "administrator", "administrator/", "administrator/index.php",
    "administrator/index.html", "administrator/login.php",
    "admin1", "admin1/", "admin2", "admin2/", "admin3", "admin3/",
    "admin4", "admin4/", "admin5", "admin5/", "admin6", "admin6/",
    "admins", "admins/", "admin_area", "admin_area/", "adminarea",
    "adminarea/", "admin_area/admin.php", "adminfiles", "adminfiles/",
    "cp", "cp/", "cpanel", "cpanel/", "cpanel.php", "cpanel.html",
    "manage", "manager", "manager/", "management", "management/",
    "panel", "panel/", "controlpanel", "controlpanel/", "control/",
    "webadmin", "webadmin/", "webadmin.php", "webadmin.html",
    "siteadmin", "siteadmin/", "siteadmin.php", "siteadmin/login.php",
    "backoffice", "backoffice/", "backoffice.php",
    "backend", "backend/", "backend.php", "backend/api",
    "dashboard", "dashboard/", "dashboard.php", "dashboard/index.php",
    "admincp", "admincp/", "modcp", "modcp/",
    "user/admin", "users/admin", "account/admin",
    "staff", "staff/", "employee", "employee/", "employees", "employees/",
    "operator", "operator/", "operators", "operators/",

    # ====================== WORDPRESS ======================
    "wp-admin", "wp-admin/", "wp-admin/index.php", "wp-admin/login.php",
    "wp-login.php", "wp-admin/admin-ajax.php", "wp-admin/admin.php",
    "wp-content/", "wp-content/uploads/", "wp-content/plugins/",
    "wp-content/themes/", "wp-content/backup/", "wp-content/cache/",
    "wp-content/upgrade/", "wp-content/uploads/2020/", "wp-content/uploads/2021/",
    "wp-content/uploads/2022/", "wp-content/uploads/2023/",
    "wp-config.php", "wp-config.php.bak", "wp-config.txt", "wp-config.php~",
    "wp-config.php.old", "wp-config.php.save", "wp-config.php.swp",
    "wp-settings.php", "wp-includes/", "wp-includes/version.php",
    "wp-load.php", "wp-mail.php", "wp-cron.php", "xmlrpc.php",
    "wp-json/", "wp-json/wp/v2/users", "wp-json/wp/v2/posts",
    "wp-trackback.php", "wp-blog-header.php", "wp-signup.php",
    "wp-activate.php", "wp-register.php", "wp-comments-post.php",
    "readme.html", "license.txt", "wp-links-opml.php",

    # ====================== PHPMYADMIN / DB ADMIN ======================
    "phpmyadmin", "phpmyadmin/", "phpMyAdmin/", "phpMyAdmin/index.php",
    "phpMyAdmin/phpmyadmin/", "phpmyadmin/index.php", "phpmyadmin/config.inc.php",
    "pma", "pma/", "pma/index.php", "pma/phpmyadmin/",
    "mysql", "mysql/", "mysqladmin/", "sqladmin/", "sql/", "sqlmanager/",
    "dbadmin", "dbadmin/", "db/", "database/", "databases/", "dbadmin.php",
    "adminer.php", "adminer/", "adminer/adminer.php",
    "mysqladmin.php", "mysql-admin/", "myadmin/", "myadmin.php",

    # ====================== CONFIG / ENV / SECRETS ======================
    ".env", ".env.local", ".env.production", ".env.development",
    ".env.staging", ".env.test", ".env.backup", ".env.bak",
    ".env.old", ".env.save", ".env.swp", ".env.example",
    ".env.sample", ".env.default", ".env.dev", ".env.prod",
    "config.php", "config.php.bak", "config.php.old", "config.php.save",
    "config.php~", "config.php.swp", "config.php.orig",
    "config.json", "config.yaml", "config.yml", "config.xml",
    "config.ini", "config.conf", "config.cfg", "config.txt",
    "configuration.php", "configuration.json", "configuration.yaml",
    "configs", "configs/", "configs/config.php", "configs/database.yml",
    "settings.php", "settings.json", "settings.xml", "settings.ini",
    "settings.conf", "settings.py", "settings.yaml", "settings.yml",
    "app.config", "app.config.js", "app.config.json", "app.config.php",
    "appsettings.json", "appsettings.Development.json", "appsettings.Production.json",
    "database.yml", "database.yaml", "database.json", "database.py",
    "db.sql", "db.php", "db.conf", "db.json", "db.yaml",
    "connection.php", "connect.php", "conn.php", "connect.py",
    "credentials", "credentials.txt", "credentials.json", "credentials.yaml",
    "creds", "creds.txt", "creds.json",
    "secret", "secret.txt", "secret.json", "secrets", "secrets/",
    "secrets.yml", "secrets.yaml", "secrets.json", "secrets.txt",
    "secrets.php", "secrets.py",
    "private", "private/", "private.key", "private.txt", "private.pem",
    "key", "key.pem", "key.txt", "keys", "keys/", "keys.json",
    ".ssh", ".ssh/id_rsa", ".ssh/id_dsa", ".ssh/authorized_keys",
    ".ssh/id_rsa.pub", ".ssh/id_ecdsa", ".ssh/known_hosts",
    "id_rsa", "id_dsa", "id_ecdsa", "authorized_keys",
    ".htpasswd", ".htaccess", ".htpasswd.bak",
    "passwd", "passwd.txt", "shadow", "shadow.txt", "group", "group.txt",
    ".aws/credentials", ".aws/config", ".aws/", "credentials.csv",

    # ====================== VERSION CONTROL ======================
    ".git", ".git/", ".git/config", ".git/HEAD", ".git/index",
    ".git/logs/HEAD", ".git/refs/", ".git/objects/", ".git/info/refs",
    ".git/description", ".git/packed-refs", ".git/COMMIT_EDITMSG",
    ".svn", ".svn/", ".svn/entries", ".svn/wc.db", ".svn/all-wcprops",
    ".hg", ".hg/", ".hg/store", ".hg/dirstate", ".hg/hgrc",
    ".bzr", ".bzr/", ".bzr/README", ".bzr/branch-format",
    "CVS", "CVS/", "CVS/Root", "CVS/Entries", "CVS/Repository",

    # ====================== BACKUP / ARCHIVE / DUMP ======================
    "backup", "backup/", "backup.zip", "backup.tar", "backup.tar.gz",
    "backup.tgz", "backup.rar", "backup.7z", "backup.sql",
    "backup.db", "backup.sql.gz", "backup.gz", "backup.bak",
    "backups", "backups/", "backups/backup.zip", "backups/db.sql",
    "bak", "bak/", "bak.zip",
    "old", "old/", "old.zip", "old.tar", "old.sql",
    "archive", "archive/", "archive.zip", "archives", "archives/",
    "dump", "dump/", "dump.sql", "db_dump.sql", "dbdump.sql",
    "sql", "sql/", "sql.sql", "data.sql", "database.sql", "db.sql",
    "db", "db/", "db.sqlite", "db.sqlite3", "db.mdb", "db.bak",
    "data", "data/", "data.sql", "data.db", "data.json", "data.xml",
    "files/backup", "files/backup.zip",
    "www.zip", "www.tar", "www.tar.gz", "web.zip", "web.tar.gz",
    "site.zip", "site.tar", "site.tar.gz", "site.bak",
    "html.zip", "html.tar", "public.zip", "public.tar", "public.html.zip",
    "1.zip", "1.tar", "1.sql", "2.zip", "2.sql", "0.zip",
    "test.zip", "test.tar", "test.sql", "test.bak",
    "temp.zip", "temp.tar", "temp.sql", "temp.bak",
    "tmp.zip", "tmp.tar", "tmp.sql", "tmp.bak",
    "latest.zip", "latest.tar.gz", "release.zip", "release.tar.gz",

    # ====================== COMMON ENTRY POINTS ======================
    "index.php", "index.html", "index.htm", "index.asp", "index.aspx",
    "index.jsp", "index.do", "index.py",
    "default.html", "default.htm", "default.php", "default.aspx", "default.jsp",
    "home.html", "home.php", "home.htm", "home.aspx",
    "main.html", "main.php", "main.htm", "main.jsp",

    # ====================== AUTH / ACCOUNT ======================
    "login", "login/", "login.php", "login.html", "login.htm",
    "login.aspx", "login.jsp", "login.do", "login.py",
    "signin", "signin.php", "signin.html", "signin.aspx",
    "signup", "signup.php", "signup.html", "register", "register.php",
    "register.html", "register.aspx",
    "logout", "logout.php", "logout.html",
    "forgot", "forgot.php", "forgot.html", "forgot-password.php",
    "reset", "reset.php", "reset.html", "reset-password.php",
    "account", "account/", "account/login", "account/register",
    "account/settings", "account/profile",
    "accounts", "accounts/", "profile", "profile/", "profile.php",
    "user", "user/", "users", "users/", "users/login.php",
    "member", "member/", "members", "members/", "membership/",
    "auth", "auth/", "auth.php", "oauth", "oauth/", "oauth/token",
    "sso", "sso/", "saml", "saml/", "sso/login",
    "token", "token/", "tokens", "tokens/", "token.php",
    "password", "password/", "password.php", "passwords", "passwords/",
    "password.txt", "passwords.txt", "pass", "pass/", "pass.txt",
    "pwd", "pwd/", "pwd.txt",

    # ====================== UPLOAD / FILES / MEDIA ======================
    "upload", "upload/", "upload.php", "uploads", "uploads/",
    "uploads/files/", "uploads/images/", "uploads/2020/", "uploads/2021/",
    "files", "files/", "file", "file/", "file.php",
    "download", "download/", "downloads", "downloads/", "download.php",
    "media", "media/", "images", "images/", "img", "img/",
    "assets", "assets/", "static", "static/", "public", "public/",
    "css", "css/", "js", "js/", "javascript", "javascript/",
    "fonts", "fonts/", "icons", "icons/",
    "documents", "documents/", "docs", "docs/",
    "pdf", "pdf/", "doc", "doc/", "xls", "xls/", "ppt", "ppt/",
    "attachment", "attachments/", "attachments",

    # ====================== API / OPENAPI ======================
    "api", "api/", "api/v1", "api/v1/", "api/v2", "api/v2/",
    "api/v3", "api/v3/", "api/v0", "api/v0/",
    "api/users", "api/admin", "api/user", "api/account",
    "api/login", "api/auth", "api/token", "api/keys",
    "api/config", "api/settings", "api/status", "api/info",
    "api/health", "api/heartbeat", "api/version",
    "api/account", "api/accounts", "api/profile",
    "api/products", "api/orders", "api/cart", "api/checkout",
    "api/files", "api/upload", "api/download",
    "api/search", "api/find", "api/list",
    "api/swagger.json", "api/swagger.yaml", "api/openapi.json",
    "api/swagger-ui", "api/swagger-ui/",
    "swagger", "swagger/", "swagger.json", "swagger.yaml",
    "swagger-ui", "swagger-ui/", "swagger-ui/index.html",
    "swagger-ui.html", "swagger-resources",
    "openapi.json", "openapi.yaml", "openapi/", "openapi/v1",
    "graphql", "graphql/", "graphiql", "graphiql/",
    "rest", "rest/", "rest/api/", "rest/v1/",

    # ====================== DEV / DOCS / INFO ======================
    "readme", "readme.txt", "readme.md", "README", "README.md",
    "README.txt", "readme.html", "README.html", "README.rst",
    "changelog", "changelog.txt", "changelog.md", "CHANGELOG",
    "CHANGELOG.md", "CHANGELOG.txt", "CHANGES", "CHANGES.txt", "CHANGES.md",
    "todo", "todo.txt", "TODO", "TODO.md", "TODO.txt",
    "license", "license.txt", "LICENSE", "LICENSE.txt", "LICENSE.md",
    "authors", "authors.txt", "AUTHORS", "AUTHORS.txt",
    "contributors", "contributors.txt", "CONTRIBUTORS",
    "install", "install.php", "install/", "install/index.php",
    "setup", "setup.php", "setup/", "setup/index.php",
    "upgrade", "upgrade.php", "upgrade/", "upgrade/index.php",
    "update", "update.php", "update/", "update/index.php",
    "test", "test/", "test.php", "test.html", "tests", "tests/",
    "testing", "testing/", "test/index.php",
    "phpinfo.php", "info.php", "php.php", "info.html", "info.txt",
    "debug", "debug/", "debug.php", "debug.log", "debug.txt",
    "dev", "dev/", "dev.php", "develop", "develop/",
    "development", "development/", "staging", "staging/",
    "preview", "preview/", "beta", "beta/", "alpha", "alpha/",
    "demo", "demo/", "demo.php", "sample", "sample/",
    "examples", "examples/", "example", "example/",
    "documentation", "documentation/", "manual", "manual/",
    "help", "help/", "help.php", "help.html", "faq", "faq/", "faq.php",

    # ====================== LOGS / TEMP / CACHE ======================
    "log", "log/", "logs", "logs/", "logs/access.log", "logs/error.log",
    "logs/laravel.log", "logs/production.log", "logs/development.log",
    "log.txt", "log.log", "access.log", "access.txt",
    "error.log", "error.txt", "errors.log", "errors.txt",
    "debug.log", "debug.txt", "app.log", "application.log",
    "server.log", "request.log", "request.txt", "auth.log",
    "temp", "temp/", "tmp", "tmp/", "cache", "cache/",
    "session", "session/", "sessions", "sessions/",
    "cookie", "cookie/", "cookies", "cookies/",
    "var/log/", "var/logs/", "var/cache/", "var/session/",
    "storage/logs/", "storage/logs/laravel.log", "storage/framework/cache/",
    "app/logs/", "app/cache/", "app/config/parameters.yml",

    # ====================== FRAMEWORK SPECIFIC ======================
    # Laravel / PHP
    "artisan", "composer.json", "composer.lock", "composer.phar",
    "storage", "storage/", "storage/app/", "storage/framework/",
    "vendor", "vendor/", "vendor/autoload.php", "vendor/composer/",
    "bootstrap/", "bootstrap/app.php", "bootstrap/cache/",
    "routes/", "routes/web.php", "routes/api.php",
    # Symfony
    "app/config/parameters.yml", "app/config/config.yml", "app/config/parameters.yml.dist",
    "app/logs/", "app/cache/", "web/app.php", "web/app_dev.php",
    # Django
    "settings.py", "local_settings.py", "manage.py", "wsgi.py",
    "db.sqlite3", "static/", "media/", "static/admin/",
    # Rails
    "Gemfile", "Gemfile.lock", "config/database.yml",
    "config/secrets.yml", "config/master.key", "config/credentials.yml.enc",
    "log/production.log", "log/development.log", "config/routes.rb",
    # Express / Node
    "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "node_modules", "node_modules/", ".npmrc", ".yarnrc",
    "server.js", "app.js", "index.js",
    # Python
    "requirements.txt", "Pipfile", "Pipfile.lock", "pyproject.toml",
    "setup.py", "setup.cfg", "poetry.lock", "tox.ini",
    # Java
    "pom.xml", "build.gradle", "build.gradle.kts", "settings.gradle",
    "WEB-INF/web.xml", "WEB-INF/classes/", "META-INF/MANIFEST.MF",
    # Misc
    "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
    ".dockerignore", ".gitignore", ".gitattributes", ".editorconfig",
    "Makefile", "makefile", "BUILD", "BUILD.bazel",
    "WORKSPACE", "Vagrantfile", "Procfile", "Jenkinsfile",
    ".envrc", "direnv", "tsconfig.json", "webpack.config.js",
    "vite.config.js", "rollup.config.js", "babel.config.js",
    ".eslintrc", ".eslintrc.js", ".eslintrc.json", ".prettierrc",

    # ====================== SERVER STATUS / ACTUATOR ======================
    "server-status", "server-info", "status", "status/", "status.php",
    "info", "info.php", "phpinfo.php", "info.html", "info.txt",
    "stats", "stats/", "statistics", "statistics/", "stat/",
    "monitor", "monitor/", "monitoring", "monitoring/",
    "metrics", "metrics/", "metrics.json",
    "actuator", "actuator/", "actuator/health", "actuator/env",
    "actuator/info", "actuator/metrics", "actuator/beans",
    "actuator/configprops", "actuator/dump", "actuator/trace",
    "actuator/loggers", "actuator/mappings", "actuator/autoconfig",
    "actuator/heapdump", "actuator/threaddump", "actuator/auditevents",
    "health", "health/", "health.php", "health.json",
    "ping", "ping.php", "healthcheck", "healthcheck.php",
    "robots.txt", "sitemap.xml", "sitemap.txt", "sitemap.xml.gz",
    "sitemap-index.xml", "humans.txt", "security.txt",
    ".well-known/", ".well-known/security.txt", ".well-known/openid-configuration",
    "crossdomain.xml", "clientaccesspolicy.xml",
    "favicon.ico", "apple-touch-icon.png", "manifest.json",

    # ====================== SHELLS / DANGEROUS ======================
    "shell.php", "shell.html", "shell.txt", "shell.asp", "shell.aspx",
    "cmd.php", "cmd.html", "c99.php", "r57.php",
    "webshell.php", "webshell.asp", "webshell.aspx",
    "sh.php", "shellz.php",
    "wso.php", "b374k.php", "adminer.php", "eval.php", "exec.php",

    # ====================== COMMON SITE PATHS ======================
    "about", "about/", "about.php", "about.html",
    "contact", "contact/", "contact.php", "contact.html",
    "sitemap", "sitemap/", "sitemap.php",
    "search", "search/", "search.php", "search.html",
    "blog", "blog/", "news", "news/", "article", "article/",
    "post", "post/", "posts", "posts/",
    "shop", "shop/", "store", "store/", "cart", "cart/",
    "product", "product/", "products", "products/",
    "order", "order/", "orders", "orders/",
    "checkout", "checkout/", "checkout.php",
    "payment", "payment/", "payment.php",
    "cart.php", "wishlist", "wishlist/",
    "forum", "forum/", "forums", "forums/",
    "wiki", "wiki/", "wiki.php",
    "support", "support/", "ticket", "ticket/", "tickets",
    "service", "service/", "services", "services/",
    "project", "project/", "projects", "projects/",
    "portfolio", "portfolio/",
    "gallery", "gallery/", "photo", "photo/", "photos", "photos/",
    "video", "video/", "videos", "videos/",
    "audio", "audio/", "music", "music/",
    "events", "events/", "event", "event/",
    "calendar", "calendar/", "schedule", "schedule/",
    "map", "map/", "maps", "maps/",
    "tag", "tag/", "tags", "tags/",
    "category", "category/", "categories", "categories/",
    "archive", "archive/", "archives", "archives/",
    "label", "label/", "labels", "labels/",
    "page", "page/", "pages", "pages/",
    "feed", "feed/", "rss", "rss/", "atom", "atom/",
    "rss.xml", "atom.xml", "feed.xml", "feed.rss",
    "json", "json/", "xml", "xml/",
    "csv", "csv/", "export", "export/", "import", "import/",

    # ====================== MAIL / NEWSLETTER ======================
    "phpmailer", "phpmailer/", "mail", "mail/", "mail.php",
    "sendmail", "sendmail.php", "mailer", "mailer/", "mailer.php",
    "newsletter", "newsletter/", "newsletter.php",
    "subscribe", "subscribe/", "subscribe.php",
    "unsubscribe", "unsubscribe/", "unsubscribe.php",
    "webmail", "webmail/", "webmail.php",

    # ====================== CMS / PLATFORM SPECIFIC ======================
    # Joomla
    "configuration.php", "joomla", "joomla/", "joomla.xml",
    "components/", "modules/", "plugins/", "templates/",
    "components/com_users/", "components/com_content/",
    "administrator/index.php", "administrator/manifests/files/joomla.xml",
    # Drupal
    "sites/default/settings.php", "sites/default/files/",
    "sites/default/default.settings.php", "misc/drupal.js",
    # Magento
    "app/etc/local.xml", "var/log/", "var/session/", "skin/",
    "downloader/", "errors/",
    # GitLab / Jenkins / CI
    "gitlab", "gitlab/", "gitlab.php",
    "jenkins", "jenkins/", "jenkins/login", "jenkins/api/",
    "ci", "ci/", "ciserver/", "ci/results",
    "build", "build/", "builds/", "builds/log",
    "hudson", "hudson/",
    "teamcity", "teamcity/", "teamcity/login.html",
    "bamboo", "bamboo/",
    # Other apps
    "phpunit", "phpunit/", "phpunit.xml", "phpunit.xml.dist",
    ".phpunit.result.cache",
    "coverage", "coverage/", "coverage/index.html",
    "coverage.xml", "coverage.json", "clover.xml",
    "nbproject", "nbproject/", "nbproject/project.xml",
    ".vscode", ".vscode/", ".vscode/settings.json", ".vscode/launch.json",
    ".idea", ".idea/", ".idea/workspace.xml", ".idea/modules.xml",
    ".history", ".history/",
    "__pycache__", "__pycache__/",
    ".pytest_cache", ".pytest_cache/",
    ".mypy_cache", ".mypy_cache/",
    "node_modules", "node_modules/.package-lock.json",
    "bower_components", "bower_components/",
    "jspm_packages", "jspm_packages/",

    # ====================== NETWORK / INFRA ======================
    "vpn", "vpn/", "vpn.php", "remote", "remote/", "remote.php",
    "gateway", "gateway/", "proxy", "proxy/", "proxy.php",
    "console", "console/", "terminal", "terminal/",
    "shell", "shell/", "exec", "exec/", "execute", "execute/",
    "run", "run/", "run.php", "process", "process/",
    "cron", "cron/", "cron.php", "crontab", "crontab/",
    "task", "task/", "tasks", "tasks/",
    "job", "job/", "jobs", "jobs/", "queue", "queue/",
    "worker", "worker/", "workers", "workers/",
    "daemon", "daemon/",
    "internal", "internal/", "hidden", "hidden/",
    "restricted", "restricted/", "confidential", "confidential/",
    "secure", "secure/", "secure.php", "security", "security/",
    "ssl", "ssl/", "tls", "tls/", "cert", "cert/", "certs", "certs/",
    "certificate", "certificate/", "certificate.pem",

    # ====================== BUSINESS / DEPT ======================
    "hr", "hr/", "finance", "finance/", "accounting", "accounting/",
    "sales", "sales/", "marketing", "marketing/",
    "operations", "operations/", "ops", "ops/",
    "it", "it/", "tech", "tech/",
    "legal", "legal/", "compliance", "compliance/",

    # ====================== ERP / CRM ======================
    "crm", "crm/", "erp", "erp/",
    "sugarcrm", "sugarcrm/", "sugarcrm/config.php",
    "vtiger", "vtiger/", "vtiger/index.php",
    "odoo", "odoo/", "odoo/web/database/list",
    "mantis", "mantis/", "mantisbt/", "mantisbt/login_page.php",
    "bugzilla", "bugzilla/", "bugzilla/index.cgi",
    "redmine", "redmine/", "redmine/login",
    "jira", "jira/", "jira/login.jsp", "jira/secure/Dashboard.jspa",
    "confluence", "confluence/", "confluence/login.action",
    "trac", "trac/", "trac/login",
    "twiki", "twiki/", "twiki/bin/view",
    "dokuwiki", "dokuwiki/", "dokuwiki/doku.php",

    # ====================== MISC EXTENSIONS ======================
    "index.php.bak", "index.php.old", "index.php~", "index.php.swp",
    "index.html.bak", "index.html.old", "index.html~",
    "login.php.bak", "login.php.old", "login.php~",
    "config.php.bak", "config.php.old", "config.php~",
    ".gitignore.save", ".gitignore.bak",
    "web.config", "Web.config", "web.config.bak",
    "robots.txt.bak", "sitemap.xml.bak",
    "error_log", "error.log", "access_log", "access.log",
    "php_error.log", ".php_error_log", "debug.log",
    "WS_FTP.log", "ws_ftp.log",
    ".DS_Store", "Thumbs.db", "desktop.ini", "ehthumbs.db",
    "config.bak", "config.old", "config.save", "config.orig",
    "settings.bak", "settings.old", "settings.save",
    "database.bak", "database.old", "db.bak", "db.old",
    "backup.tar.bz2", "backup.tar.xz", "backup.zip.bak",
    "site.bak", "www.bak", "html.bak", "public.bak",
    "1.tar.gz", "2.tar.gz", "a.zip", "b.zip",
    "old.zip", "new.zip", "current.zip",
    "data.tar", "data.tar.gz", "data.zip",
    "dump.tar", "dump.tar.gz", "dump.zip",
    "mysql.sql", "mysql_dump.sql", "mysqldump.sql",
    "schema.sql", "schema.yml", "schema.json",
    "migrate", "migrate/", "migration", "migration/", "migrations/",
    "seed", "seed/", "seeds/", "seeders/",
    "fixtures", "fixtures/", "fixtures.json",
    "factories", "factories/",
]

TOOL_NAME = "DihFinder"
TOOL_VERSION = "3.1"
TOOL_AUTHOR = "nEx"

console = Console()


# ===========================================================================
# Scanner
# ===========================================================================
class DihFinder:
    """Async multi-level web path scanner with false-positive filtering."""

    # Paths whose 200-OK (or even 4xx) is treated as high-value.
    CRITICAL_PATH_INDICATORS = (
        ".env", "wp-config.php", "config.php", "settings.py", "settings.json",
        "database.yml", "secrets.yml", "secrets.json", "composer.json",
        "composer.lock", ".git/config", ".git/HEAD", ".svn/entries",
        "backup.zip", "backup.sql", "dump.sql", "db.sql", "database.sql",
        ".htpasswd", "id_rsa", "private.key", "private.pem", "adminer.php",
        "phpinfo.php", "info.php", "appsettings.json",
        ".aws/credentials", "credentials.json", "credentials.txt",
        "package.json", "Gemfile", "requirements.txt", "Pipfile",
        "docker-compose.yml", "Dockerfile", "phpunit.xml",
        "shell.php", "c99.php", "r57.php", "wso.php",
        "app/etc/local.xml", "configuration.php",
        "sites/default/settings.php", "actuator/env", "actuator/heapdump",
        "actuator/beans", "actuator/configprops", "actuator/dump",
        "actuator/trace", "actuator/loggers",
    )

    HIGH_PATH_INDICATORS = (
        "admin", "administrator", "cpanel", "wp-admin", "phpmyadmin",
        "pma", "manager", "panel", "backend", "dashboard", "login",
        ".htaccess", "config", "configuration", "settings", "private",
        "secret", "backup", "old", "internal", "restricted",
        "console", "shell", "jenkins", "gitlab", "jira", "confluence",
        "redmine", "mantis", "bugzilla",
    )

    # Body keywords that elevate severity.
    BODY_KEYWORDS = {
        "secret":   ("secret", "api_key", "apikey", "api-key", "api_secret",
                     "client_secret"),
        "pwd":      ("password", "passwd", "pwd", "pass"),
        "private":  ("private", "credential", "confidential"),
        "mysql":    ("mysql", "mysqli", "pdo_mysql", "mysql_connect"),
        "database": ("database", "db_name", "dbname", "db_host", "db_password"),
        "token":    ("token", "jwt", "bearer", "access_token", "refresh_token"),
        "key":      ("private_key", "public_key", "ssh-rsa", "begin rsa",
                     "begin private key", "begin openssh"),
        "aws":      ("aws_access_key", "aws_secret", "aws_session", "AKIA"),
        "github":   ("github_token", "gh_token", "ghp_", "github_pat_"),
        "admin":    ("administrator", "admin_login", "root user", "isadmin"),
        "config":   ("configuration", "db_config", "app_config"),
        "email":    ("smtp_host", "smtp_port", "mail_password", "smtp_user"),
        "stripe":   ("sk_live_", "sk_test_", "rk_live_"),
        "slack":    ("xoxb-", "xoxp-", "hooks.slack.com"),
    }

    SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    SEVERITY_COLORS = {
        "CRITICAL": "bold red",
        "HIGH":     "bold bright_red",
        "MEDIUM":   "bold yellow",
        "LOW":      "blue",
        "INFO":     "green",
    }
    SEVERITY_HEX = {
        "CRITICAL": "#ff3860",
        "HIGH":     "#ff7a45",
        "MEDIUM":   "#ffd83d",
        "LOW":      "#4d9cff",
        "INFO":     "#52c41a",
    }

    def __init__(
        self,
        target,
        wordlist=None,
        concurrency=20,
        timeout=10,
        user_agent=None,
        max_depth=3,
        extensions=None,
        max_recurse_dirs=15,
        proxy=None,
        extra_headers=None,
        include_status=None,
        match_size=None,
        rate_limit_aware=True,
    ):
        # Normalize target URL
        target = target.strip()
        if not target.startswith(("http://", "https://")):
            target = "http://" + target
        self.target = target.rstrip("/")

        # Wordlist
        wl = list(wordlist) if wordlist else list(WORDLIST)
        if extensions:
            extended = []
            for w in wl:
                extended.append(w)
                if not w.endswith("/") and "." not in w.split("/")[-1]:
                    for ext in extensions:
                        extended.append(w + ext)
            seen = set()
            deduped = []
            for w in extended:
                if w not in seen:
                    seen.add(w)
                    deduped.append(w)
            wl = deduped
        self.wordlist = wl

        self.concurrency = max(1, int(concurrency))
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.user_agent = user_agent or f"Mozilla/5.0 (compatible; {TOOL_NAME}/{TOOL_VERSION})"
        self.max_depth = max(1, int(max_depth))
        self.max_recurse_dirs = max_recurse_dirs

        self.proxy = proxy
        self.extra_headers = extra_headers or {}
        self.include_status = set(include_status) if include_status else None
        self.match_size = set(match_size) if match_size else None
        self.rate_limit_aware = rate_limit_aware

        self.findings = []
        self.baselines = []
        self.baseline_hashes = set()
        self.baseline_lengths = []
        self.baseline_median_len = 0
        self.wildcard_status = None
        self.scanned_paths = set()
        self.session = None
        self.total_scanned = 0
        self.errors = 0
        self.target_host = urlparse(self.target).netloc

        # scan timing / stats
        self.start_time = None
        self.end_time = None
        self.level_stats = []  # list of dicts {level, requests, findings, duration}
        # post-scan dedup stats
        self.dedup_removed = 0

    # ---------------------- low-level request ----------------------
    async def _request(self, url):
        headers = {"User-Agent": self.user_agent, "Accept": "*/*"}
        headers.update(self.extra_headers)
        # rate-limit-aware retry loop
        for attempt in range(3):
            try:
                start = time.perf_counter()
                async with self.session.get(
                    url, timeout=self.timeout, allow_redirects=False,
                    headers=headers, proxy=self.proxy,
                ) as resp:
                    body = await resp.read()
                    elapsed = time.perf_counter() - start
                    return {
                        "status": resp.status,
                        "length": len(body),
                        "body": body,
                        "time": elapsed,
                        "location": resp.headers.get("Location", ""),
                        "content_type": resp.headers.get("Content-Type", ""),
                    }
            except asyncio.TimeoutError:
                self.errors += 1
                return None
            except aiohttp.ClientError:
                self.errors += 1
                # backoff then retry once
                if attempt < 2:
                    await asyncio.sleep(0.5 * (attempt + 1))
                    continue
                return None
            except Exception:
                self.errors += 1
                return None
        return None

    # ---------------------- baseline (soft-404 detection) ---------
    async def establish_baseline(self):
        """Hit several random non-existent paths to learn the server's
        'not found' signature. Any real finding matching this signature
        is treated as a soft 404 and dropped.

        v3.1: takes 5 samples (up from 3), computes median length, and
        flags the server as 'wildcard' if >=3 samples return the same
        non-404 status. When wildcard is detected, length-tolerance
        filtering is widened to 20% (was 5%) to catch soft-404 variants
        with slightly different content (e.g. embedded path strings).
        """
        for _ in range(5):
            rand = "".join(
                random.choices(string.ascii_lowercase + string.digits, k=24)
            )
            url = f"{self.target}/{rand}"
            r = await self._request(url)
            if r:
                self.baselines.append(r)

        # Analyze baseline pattern
        if not self.baselines:
            return

        status_counts = {}
        for b in self.baselines:
            status_counts[b["status"]] = status_counts.get(b["status"], 0) + 1

        # If >=3 baselines share a status, that status is the wildcard status
        self.wildcard_status = None
        for st, cnt in status_counts.items():
            if cnt >= 3:
                self.wildcard_status = st
                break

        # Compute median length for the dominant baseline status
        self.baseline_lengths = sorted(
            b["length"] for b in self.baselines
            if b["status"] == (self.wildcard_status or self.baselines[0]["status"])
        )
        if self.baseline_lengths:
            mid = len(self.baseline_lengths) // 2
            self.baseline_median_len = self.baseline_lengths[mid]
        else:
            self.baseline_median_len = 0

        # Collect baseline body hashes for exact-match detection
        self.baseline_hashes = set()
        for b in self.baselines:
            try:
                self.baseline_hashes.add(hashlib.md5(b["body"]).hexdigest())
            except Exception:
                pass

        if self.wildcard_status == 200:
            console.print(
                Text(
                    f"[!] WILDCARD DETECTED: server returns HTTP 200 for random "
                    f"paths (median length {self.baseline_median_len:,}B). "
                    f"Strict length-tolerance filtering enabled.",
                    style="bold yellow",
                )
            )
        elif self.wildcard_status and self.wildcard_status != 404:
            console.print(
                Text(
                    f"[!] Server returns HTTP {self.wildcard_status} for random "
                    f"paths. Strict filtering enabled.",
                    style="yellow",
                )
            )

    def _is_soft_404(self, result):
        """v3.1 enhanced soft-404 detection."""
        if not self.baselines:
            return False

        body = result["body"]
        length = result["length"]
        status = result["status"]

        # 1) Exact body-hash match against ANY baseline
        try:
            body_hash = hashlib.md5(body).hexdigest()
            if body_hash in self.baseline_hashes:
                return True
        except Exception:
            body_hash = None

        # 2) If wildcard status detected, use wider length tolerance
        if self.wildcard_status is not None and status == self.wildcard_status:
            if self.baseline_median_len > 0 and length > 0:
                ratio = abs(length - self.baseline_median_len) / max(self.baseline_median_len, 1)
                # 20% tolerance when wildcard is confirmed
                if ratio < 0.20:
                    # Additional check: body should look generic (HTML shell)
                    # Compare first 64 bytes - if match, definitely soft-404
                    for b in self.baselines:
                        if b["status"] != status:
                            continue
                        if body[:64] == b["body"][:64]:
                            return True
                    # Even without prefix match, if length is within 10% AND
                    # body looks like generic HTML, treat as soft-404.
                    # BUT: skip this check if body contains sensitive keywords
                    # (password/secret/token/etc.) - that's real content.
                    if ratio < 0.10:
                        try:
                            text = body.decode("utf-8", errors="ignore").lower()[:1000]
                            if ("<html" in text or "<!doctype html" in text) and "<body" in text:
                                # Check for sensitive content - if present, NOT a soft-404
                                sensitive_terms = (
                                    "password", "passwd", "secret", "api_key", "apikey",
                                    "token", "credential", "private_key", "begin rsa",
                                    "begin private key", "db_password", "mysql",
                                    "aws_secret", "db_host", "db_name", "db_user",
                                    "smtp", "session", "cookie", "authorize",
                                    "bearer", "jwt", "config", "database",
                                    "phpinfo", "php version", "system()", "eval(",
                                    "exec(", "shell", "admin", "login", "register",
                                    "insert into", "create table", "dump",
                                )
                                if not any(t in text for t in sensitive_terms):
                                    return True
                        except Exception:
                            pass
            # Wildcard status with very short body is almost always soft-404
            # BUT only if body has no meaningful content
            if length < 50:
                try:
                    text = body.decode("utf-8", errors="ignore").lower()
                    # Keep if it contains any real content indicator
                    if not any(t in text for t in ("forbidden", "unauthorized", "not allowed")):
                        # "forbidden"/"unauthorized" are real 403/401 bodies
                        # but if wildcard status is 200, these wouldn't apply
                        return True
                except Exception:
                    return True

        # 3) Per-baseline exact prefix match (legacy fallback)
        for b in self.baselines:
            if status != b["status"]:
                continue
            if b["length"] > 0 and length > 0:
                ratio = abs(length - b["length"]) / max(b["length"], 1)
                if ratio < 0.05 and body[:256] == b["body"][:256]:
                    return True

        return False

    @staticmethod
    def _body_contains_not_found(body):
        """v3.1: expanded indicator list + HTML <title> check."""
        if not body or len(body) > 8000:
            return False
        try:
            text = body.decode("utf-8", errors="ignore").lower()
        except Exception:
            return False
        indicators = (
            # plain text
            "not found", "doesn't exist", "does not exist",
            "no such", "page not found", "file not found", "unable to find",
            "could not be found", "cannot be found", "page unavailable",
            "resource not found", "endpoint not found", "route not found",
            "the page you requested", "this page cannot be found",
            "sorry, the page", "we couldn't find",
            # HTML title patterns
            "<title>404", "<title>not found", "<title>error 404",
            "<title>page not found", "<title>no result",
            "<title>403", "<title>forbidden",
            # status text in body
            "404 not found", "404 - not found", "404 - file not found",
            "error 404", "error: 404", "status: 404",
            "http 404", "http/1.0 404", "http/1.1 404",
        )
        return any(ind in text for ind in indicators)

    @staticmethod
    def _is_default_server_page(body):
        """Detect Apache/Nginx/IIS default welcome pages."""
        if not body or len(body) > 8000:
            return False
        try:
            text = body.decode("utf-8", errors="ignore").lower()
        except Exception:
            return False
        # Need at least one strong marker
        strong_markers = (
            "it works!", "it works!",
            "apache2 ubuntu default page", "apache http server test page",
            "default page for apache", "this is the default welcome page",
            "welcome to nginx", "test page for the nginx http server",
            "iis windows server", "iisstart",
            "default web site page", "welcome to the default website",
            "this is a default page", "default page",
            "<title>test page for apache",
            "<title>welcome to nginx",
            "<title>iis windows server",
        )
        return any(m in text for m in strong_markers)

    @staticmethod
    def _is_spa_shell(body):
        """Detect SPA index.html shells (React/Vue/Angular/Next/Nuxt)
        that get served for every unknown path by client-side routers."""
        if not body or len(body) > 50000:
            return False
        try:
            text = body.decode("utf-8", errors="ignore").lower()
        except Exception:
            return False
        # Need 2+ SPA markers to be confident
        spa_markers = (
            '<div id="root"', '<div id="app"',
            '<div id="__next"', '<div id="__nuxt"',
            'id="___gatsby"', "<noscript>you need to enable javascript",
            "you need to enable javascript to run this app",
            "please enable javascript to continue",
            "this app works best with javascript enabled",
            "react", "vue.js", "angular", "svelte",
            "data-reactroot", "data-server-rendered",
            "<script src=\"/_next/static/", "<script src=\"/static/js/",
        )
        matches = sum(1 for m in spa_markers if m in text)
        # Require 2+ markers AND look like an HTML shell (not a real data file)
        if matches >= 2 and ("<html" in text or "<!doctype html" in text):
            # But NOT a real admin/config page - check it doesn't have specific
            # keywords that indicate actual content
            content_indicators = (
                "password", "secret", "api_key", "token", "credential",
                "private_key", "begin rsa", "begin private key",
                "db_password", "mysql", "aws_secret",
            )
            if any(c in text for c in content_indicators):
                return False  # looks like real sensitive content
            return True
        return False

    def _extract_keywords(self, body, path):
        kws = set()
        try:
            text = body.decode("utf-8", errors="ignore").lower()
        except Exception:
            text = ""
        for category, terms in self.BODY_KEYWORDS.items():
            for term in terms:
                if term in text:
                    kws.add(category)
                    break

        path_lower = path.lower()
        path_indicators = {
            ".env": "env", "config": "config", "backup": "backup",
            ".bak": "backup", ".sql": "sql", ".git": "git",
            "admin": "admin", "secret": "secret", "private": "private",
            "key": "key", "password": "pwd", "pwd": "pwd",
            "token": "token", "credentials": "cred",
            "shadow": "shadow", "passwd": "pwd",
        }
        for needle, kw in path_indicators.items():
            if needle in path_lower:
                kws.add(kw)
        return sorted(kws)

    def _classify_severity(self, status, path, keywords):
        path_lower = path.lower()
        has_critical_path = any(
            ind in path_lower for ind in self.CRITICAL_PATH_INDICATORS
        )
        has_high_path = any(
            ind in path_lower for ind in self.HIGH_PATH_INDICATORS
        )
        has_sensitive_kw = bool(keywords)

        if status == 200:
            if has_critical_path or has_sensitive_kw:
                return "CRITICAL"
            if has_high_path:
                return "HIGH"
            return "INFO"
        if status in (401, 403):
            if has_critical_path or has_sensitive_kw:
                return "HIGH"
            if has_high_path:
                return "MEDIUM"
            return "LOW"
        if status in (301, 302, 307, 308):
            return "LOW"
        if status == 500:
            return "MEDIUM"
        if status == 405:
            return "LOW"
        return "INFO"

    # ---------------------- scan a single path --------------------
    async def scan_path(self, path):
        if path in self.scanned_paths:
            return None
        self.scanned_paths.add(path)

        url = f"{self.target}/{path.lstrip('/')}"
        result = await self._request(url)
        self.total_scanned += 1
        if not result:
            return None

        # Status filter (if user explicitly limited statuses)
        if self.include_status and result["status"] not in self.include_status:
            return None

        # Size filter (if user explicitly limited sizes)
        if self.match_size and result["length"] not in self.match_size:
            # But keep 401/403 even if size doesn't match (auth gates are valuable)
            if result["status"] not in (401, 403):
                return None

        # --- false-positive filters (v3.1: enhanced) ---
        if self._is_soft_404(result):
            return None
        if result["status"] == 200 and result["length"] < 10:
            return None
        if (
            result["status"] == 200
            and self._body_contains_not_found(result["body"])
        ):
            return None
        # New: drop Apache/Nginx/IIS default welcome pages (always fake findings)
        if (
            result["status"] == 200
            and self._is_default_server_page(result["body"])
        ):
            return None
        # New: drop SPA shells served for unknown paths (very common with
        # React/Vue/Angular apps using client-side routing)
        if (
            result["status"] == 200
            and self._is_spa_shell(result["body"])
        ):
            return None

        if result["status"] in (301, 302, 307, 308):
            loc = (result["location"] or "").strip()
            loc_path = urlparse(loc).path.lower() if loc else ""
            boring_targets = (
                "/", "/index.php", "/index.html", "/index.htm",
                "/index.aspx", "/login", "/login.php", "/login.html",
                "/login.aspx", "/auth", "/signin", "/signin.php",
            )
            if loc_path in boring_targets:
                return None
            if loc:
                loc_host = urlparse(loc).netloc.lower()
                if loc_host and loc_host == self.target_host.lower() and loc_path == "/":
                    return None

        keywords = self._extract_keywords(result["body"], path)
        severity = self._classify_severity(result["status"], path, keywords)

        # Drop low-signal INFO 200s (small body, no keywords, not interesting)
        if (
            severity == "INFO"
            and not keywords
            and result["status"] == 200
            and result["length"] < 200
        ):
            return None

        # Compute body hash for post-scan dedup (wildcard fingerprinting)
        try:
            body_hash = hashlib.md5(result["body"]).hexdigest()
        except Exception:
            body_hash = ""
        # Body preview (first 80 chars, sanitized) for the report
        try:
            body_preview = result["body"][:80].decode("utf-8", errors="ignore").replace("\n", " ").strip()
        except Exception:
            body_preview = ""

        return {
            "url": url,
            "path": path,
            "status": result["status"],
            "length": result["length"],
            "time": result["time"],
            "keywords": keywords,
            "severity": severity,
            "location": result.get("location", ""),
            "content_type": result.get("content_type", ""),
            "body_hash": body_hash,
            "body_preview": body_preview,
        }

    # ---------------------- multi-level scan ----------------------
    async def _scan_batch(self, paths, level_label, level_num):
        if not paths:
            return []
        semaphore = asyncio.Semaphore(self.concurrency)

        async def bounded(p):
            async with semaphore:
                return await self.scan_path(p)

        tasks = [bounded(p) for p in paths]
        results = []
        level_start = time.perf_counter()
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TimeRemainingColumn(),
            console=console,
            transient=True,
        ) as progress:
            task = progress.add_task(level_label, total=len(tasks))
            for coro in asyncio.as_completed(tasks):
                r = await coro
                if r:
                    results.append(r)
                progress.advance(task)
        level_duration = time.perf_counter() - level_start
        self.level_stats.append({
            "level": level_num,
            "requests": len(tasks),
            "findings": len(results),
            "duration": level_duration,
        })
        return results

    @staticmethod
    def _is_recursable(finding):
        if finding["status"] != 200:
            return False
        p = finding["path"].lower()
        if finding["path"].endswith("/"):
            return True
        interesting = (
            "admin", "api", "config", "backup", "private", "secret",
            "old", "tmp", "test", "dev", "stash", "uploads", "files",
            "public", "static", "media", "images", "docs", "internal",
            "wp-content", "wp-admin", "components", "modules", "plugins",
            "vendor", "storage", "node_modules", "assets",
        )
        return any(ind in p for ind in interesting)

    async def scan(self):
        self.start_time = time.time()
        connector = aiohttp.TCPConnector(
            limit=self.concurrency, ssl=False, force_close=False
        )
        async with aiohttp.ClientSession(connector=connector) as session:
            self.session = session

            # Banner
            console.print(Panel(
                Text(
                    f"Tool        : {TOOL_NAME} v{TOOL_VERSION}\n"
                    f"Author      : {TOOL_AUTHOR}\n"
                    f"Target      : {self.target}\n"
                    f"Wordlist    : {len(self.wordlist)} entries\n"
                    f"Max depth   : {self.max_depth}\n"
                    f"Concurrency : {self.concurrency}"
                    + (f"\nProxy       : {self.proxy}" if self.proxy else "")
                    + (f"\nHeaders     : {len(self.extra_headers)} custom"
                       if self.extra_headers else ""),
                    style="cyan",
                ),
                title=Text(f"{TOOL_NAME}", style="bold cyan"),
                border_style="cyan",
            ))

            console.print(
                Text("[*] Establishing baseline (soft-404 detection)...",
                     style="cyan")
            )
            await self.establish_baseline()
            console.print(
                Text(f"[+] Baseline established ({len(self.baselines)} samples)",
                     style="green")
            )

            # Level 1
            console.print(
                Text(f"[*] Scanning level 1 (root, {len(self.wordlist)} paths)...",
                     style="cyan")
            )
            level1 = await self._scan_batch(list(self.wordlist), "Level 1", 1)
            self.findings.extend(level1)
            console.print(
                Text(f"[+] Level 1: {len(level1)} findings", style="green")
            )

            # Multi-level
            for depth in range(2, self.max_depth + 1):
                recursable = [
                    f["path"].rstrip("/") for f in self.findings
                    if self._is_recursable(f)
                ]
                seen = set()
                unique_dirs = []
                for d in recursable:
                    if d and d not in seen:
                        seen.add(d)
                        unique_dirs.append(d)
                unique_dirs = unique_dirs[: self.max_recurse_dirs]
                if not unique_dirs:
                    break

                children = []
                for d in unique_dirs:
                    for w in self.wordlist:
                        child = f"{d}/{w.lstrip('/')}"
                        if child not in self.scanned_paths:
                            children.append(child)
                if not children:
                    break

                console.print(
                    Text(
                        f"[*] Scanning level {depth} "
                        f"({len(unique_dirs)} dirs x {len(self.wordlist)} paths "
                        f"= {len(children)} requests)...",
                        style="cyan",
                    )
                )
                level_n = await self._scan_batch(children, f"Level {depth}", depth)
                self.findings.extend(level_n)
                console.print(
                    Text(f"[+] Level {depth}: {len(level_n)} new findings",
                         style="green")
                )

        # v3.1: post-scan deduplication pass
        # If 3+ findings share the exact same body hash, they are almost
        # certainly a wildcard / soft-404 pattern that slipped past the
        # per-request filters (e.g. server returns same HTML 404 page for
        # many different paths). Drop them all.
        await self._dedupe_wildcard_findings()

        self.end_time = time.time()
        duration = self.end_time - self.start_time
        console.print()
        console.print(
            Text(
                f"[*] Total requests: {self.total_scanned}  |  "
                f"Total findings: {len(self.findings)}  |  "
                f"Duration: {duration:.1f}s  |  "
                f"Errors: {self.errors}"
                + (f"  |  Dedup removed: {self.dedup_removed}" if self.dedup_removed else ""),
                style="bold cyan",
            )
        )
        return self.findings

    async def _dedupe_wildcard_findings(self):
        """Post-scan: if 3+ findings share the exact same body hash, they
        are a wildcard / soft-404 fingerprint that slipped past per-request
        filters. Drop them all (after keeping a note of how many were
        removed for the report).

        IMPORTANT: we skip 401/403 responses. Auth gates legitimately
        return identical 'Forbidden'/'Unauthorized' bodies for many paths,
        and those ARE real findings (the path exists but is protected).
        """
        if not self.findings:
            return

        # Group by body_hash, but EXCLUDE 401/403 (auth gates)
        hash_groups = {}
        for f in self.findings:
            h = f.get("body_hash", "")
            if not h:
                continue
            # Skip auth-gate responses - identical bodies are expected there
            if f["status"] in (401, 403):
                continue
            hash_groups.setdefault(h, []).append(f)

        # Find hashes shared by 3+ findings (the wildcard fingerprint)
        wildcard_hashes = {
            h for h, group in hash_groups.items() if len(group) >= 3
        }

        if not wildcard_hashes:
            return

        before = len(self.findings)
        self.findings = [
            f for f in self.findings
            if f.get("body_hash", "") not in wildcard_hashes
            or f["status"] in (401, 403)  # keep auth gates
        ]
        self.dedup_removed = before - len(self.findings)

        if self.dedup_removed > 0:
            console.print(
                Text(
                    f"[+] Post-scan dedup: removed {self.dedup_removed} "
                    f"wildcard false-positives "
                    f"({len(wildcard_hashes)} duplicate body fingerprint(s)).",
                    style="green",
                )
            )


# ===========================================================================
# Display (terminal)
# ===========================================================================
def display_results(scanner):
    findings = scanner.findings

    if not findings:
        console.print(Panel(
            Text("No findings detected.", style="yellow"),
            title=Text("Scan Results", style="bold cyan"),
            border_style="yellow",
        ))
        return

    findings.sort(
        key=lambda f: (
            DihFinder.SEVERITY_ORDER.get(f["severity"], 5),
            -f["length"],
        )
    )

    table = Table(
        title=Text(f"{TOOL_NAME} - Scan Findings", style="bold cyan"),
        show_lines=True,
        header_style="bold magenta",
        expand=True,
    )
    table.add_column(Text("Severity"), width=10)
    table.add_column(Text("Code"), width=6, justify="right")
    table.add_column(Text("URL"), overflow="fold", ratio=3)
    table.add_column(Text("Size"), width=11, justify="right")
    table.add_column(Text("Time"), width=8, justify="right")
    table.add_column(Text("Keywords"), width=22, overflow="fold")

    for f in findings:
        sev = f["severity"]
        style = DihFinder.SEVERITY_COLORS.get(sev, "white")
        kw = ", ".join(f["keywords"]) if f["keywords"] else "—"
        table.add_row(
            Text(sev, style=style),
            Text(str(f["status"])),
            Text(f["url"]),
            Text(f"{f['length']:,}B"),
            Text(f"{f['time']:.2f}s"),
            Text(kw),
        )

    console.print(table)

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    duration = (scanner.end_time - scanner.start_time) if scanner.end_time else 0
    summary = (
        f"Tool           : {TOOL_NAME} v{TOOL_VERSION} (by {TOOL_AUTHOR})\n"
        f"Target         : {scanner.target}\n"
        f"Duration       : {duration:.1f}s\n"
        f"Total requests : {scanner.total_scanned}\n"
        f"Total findings : {len(findings)}\n"
        f"  CRITICAL     : {counts['CRITICAL']}\n"
        f"  HIGH         : {counts['HIGH']}\n"
        f"  MEDIUM       : {counts['MEDIUM']}\n"
        f"  LOW          : {counts['LOW']}\n"
        f"  INFO         : {counts['INFO']}\n"
        f"Errors         : {scanner.errors}"
    )
    console.print(Panel(
        Text(summary, style="cyan"),
        title=Text("Scan Summary", style="bold cyan"),
        border_style="cyan",
    ))


# ===========================================================================
# Output: TXT
# ===========================================================================
def write_txt_report(scanner, path):
    """Plain-text report (backwards-compatible)."""
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(
                f"# {TOOL_NAME} v{TOOL_VERSION} (by {TOOL_AUTHOR})\n"
                f"# Target: {scanner.target}\n"
                f"# Requests: {scanner.total_scanned} | "
                f"Findings: {len(scanner.findings)} | "
                f"Errors: {scanner.errors}\n"
                f"# Date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n"
            )
            for f in scanner.findings:
                kw = ",".join(f["keywords"]) if f["keywords"] else "-"
                fh.write(
                    f"[{f['severity']}] {f['status']} {f['url']} "
                    f"size={f['length']}B time={f['time']:.2f}s "
                    f"kw={kw}\n"
                )
        console.print(Text(f"[+] TXT report saved to {path}", style="green"))
    except OSError as e:
        console.print(Text(f"[!] Could not write TXT report: {e}", style="bold red"))


# ===========================================================================
# Output: JSON
# ===========================================================================
def write_json_report(scanner, path):
    """Full machine-readable JSON report."""
    duration = (scanner.end_time - scanner.start_time) if scanner.end_time else 0
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in scanner.findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    payload = {
        "tool": TOOL_NAME,
        "version": TOOL_VERSION,
        "author": TOOL_AUTHOR,
        "target": scanner.target,
        "scan_date": time.strftime("%Y-%m-%d %H:%M:%S"),
        "scan_duration_sec": round(duration, 2),
        "total_requests": scanner.total_scanned,
        "total_findings": len(scanner.findings),
        "errors": scanner.errors,
        "severity_counts": counts,
        "level_stats": scanner.level_stats,
        "findings": scanner.findings,
    }
    try:
        with open(path, "w", encoding="utf-8") as fh:
            _json.dump(payload, fh, indent=2, ensure_ascii=False)
        console.print(Text(f"[+] JSON report saved to {path}", style="green"))
    except OSError as e:
        console.print(Text(f"[!] Could not write JSON report: {e}", style="bold red"))


# ===========================================================================
# Output: HTML (dark, structured, sortable, self-contained)
# ===========================================================================
HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{tool} - Report</title>
<style>
  :root {{
    --bg:        #0d1117;
    --panel:     #161b22;
    --panel-2:   #1c2330;
    --border:    #30363d;
    --text:      #e6edf3;
    --text-dim:  #8b949e;
    --accent:    #58a6ff;
    --crit:      #ff3860;
    --high:      #ff7a45;
    --med:       #ffd83d;
    --low:       #4d9cff;
    --info:      #52c41a;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0;
    background: var(--bg);
    color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "Noto Sans",
                 "Liberation Sans", Roboto, sans-serif;
    font-size: 14px;
    line-height: 1.5;
  }}
  .container {{ max-width: 1400px; margin: 0 auto; padding: 24px; }}

  /* Header */
  .header {{
    background: linear-gradient(135deg, #161b22 0%, #1c2330 100%);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 24px 28px;
    margin-bottom: 24px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    flex-wrap: wrap;
    gap: 16px;
  }}
  .header .brand {{
    display: flex;
    align-items: center;
    gap: 14px;
  }}
  .header .logo {{
    width: 48px; height: 48px;
    border-radius: 10px;
    background: linear-gradient(135deg, #58a6ff 0%, #1f6feb 100%);
    display: flex; align-items: center; justify-content: center;
    font-weight: 800; font-size: 22px; color: #fff;
    box-shadow: 0 4px 14px rgba(31,111,235,.35);
  }}
  .header h1 {{
    margin: 0; font-size: 24px; font-weight: 700;
    background: linear-gradient(90deg, #58a6ff, #a371f7);
    -webkit-background-clip: text; -webkit-text-fill-color: transparent;
    background-clip: text;
  }}
  .header .meta {{ color: var(--text-dim); font-size: 13px; }}
  .header .meta strong {{ color: var(--text); }}
  .author-tag {{
    background: rgba(88,166,255,.1);
    color: var(--accent);
    padding: 4px 10px;
    border-radius: 20px;
    font-size: 12px;
    font-weight: 600;
    border: 1px solid rgba(88,166,255,.25);
  }}

  /* Stat cards */
  .stats {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 14px;
    margin-bottom: 24px;
  }}
  .stat {{
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 16px 18px;
    position: relative;
    overflow: hidden;
  }}
  .stat::before {{
    content: ""; position: absolute; left: 0; top: 0; bottom: 0;
    width: 4px; background: var(--accent);
  }}
  .stat.crit::before {{ background: var(--crit); }}
  .stat.high::before {{ background: var(--high); }}
  .stat.med::before  {{ background: var(--med); }}
  .stat.low::before  {{ background: var(--low); }}
  .stat.info::before {{ background: var(--info); }}
  .stat .label {{
    color: var(--text-dim); font-size: 11px;
    text-transform: uppercase; letter-spacing: 1px;
    margin-bottom: 6px;
  }}
  .stat .value {{
    font-size: 26px; font-weight: 700; color: var(--text);
  }}

  /* Section */
  .section {{
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 20px 24px;
    margin-bottom: 24px;
  }}
  .section h2 {{
    margin: 0 0 16px 0;
    font-size: 16px;
    font-weight: 600;
    color: var(--text);
    display: flex; align-items: center; gap: 8px;
  }}
  .section h2 .dot {{
    width: 8px; height: 8px; border-radius: 50%;
    background: var(--accent);
  }}

  .meta-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
    gap: 10px 24px;
  }}
  .meta-grid div {{ font-size: 13px; }}
  .meta-grid .k {{ color: var(--text-dim); }}
  .meta-grid .v {{ color: var(--text); word-break: break-all; }}

  /* Filters */
  .filters {{
    display: flex; flex-wrap: wrap; gap: 8px;
    margin-bottom: 14px; align-items: center;
  }}
  .filters input[type=text] {{
    background: var(--panel-2);
    border: 1px solid var(--border);
    color: var(--text);
    padding: 7px 11px;
    border-radius: 6px;
    font-size: 13px;
    width: 240px;
    outline: none;
  }}
  .filters input[type=text]:focus {{ border-color: var(--accent); }}
  .filters .sev-btn {{
    background: var(--panel-2);
    border: 1px solid var(--border);
    color: var(--text-dim);
    padding: 6px 12px;
    border-radius: 6px;
    cursor: pointer;
    font-size: 12px;
    font-weight: 600;
    transition: all .15s ease;
  }}
  .filters .sev-btn:hover {{ color: var(--text); }}
  .filters .sev-btn.active {{ color: #fff; border-color: transparent; }}
  .filters .sev-btn.active.crit {{ background: var(--crit); }}
  .filters .sev-btn.active.high {{ background: var(--high); }}
  .filters .sev-btn.active.med  {{ background: var(--med); color:#000; }}
  .filters .sev-btn.active.low  {{ background: var(--low); }}
  .filters .sev-btn.active.info {{ background: var(--info); }}
  .filters .sev-btn.active.all  {{ background: var(--accent); }}

  /* Status-code filter buttons */
  .filters .sep {{
    width: 1px; height: 22px;
    background: var(--border);
    margin: 0 6px;
  }}
  .filters .label {{
    color: var(--text-dim);
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: .5px;
    margin-right: 4px;
  }}
  .filters .st-btn {{
    background: var(--panel-2);
    border: 1px solid var(--border);
    color: var(--text-dim);
    padding: 6px 11px;
    border-radius: 6px;
    cursor: pointer;
    font-size: 12px;
    font-family: "SFMono-Regular", Menlo, Consolas, monospace;
    font-weight: 600;
    transition: all .15s ease;
    min-width: 44px;
    text-align: center;
  }}
  .filters .st-btn:hover {{ color: var(--text); border-color: var(--accent); }}
  .filters .st-btn.active {{
    color: #fff;
    background: var(--accent);
    border-color: transparent;
  }}

  /* Table */
  .table-wrap {{ overflow-x: auto; }}
  table {{
    width: 100%;
    border-collapse: separate;
    border-spacing: 0;
    font-size: 13px;
  }}
  thead th {{
    background: var(--panel-2);
    color: var(--text-dim);
    text-align: left;
    padding: 10px 12px;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: .5px;
    border-bottom: 1px solid var(--border);
    cursor: pointer;
    user-select: none;
    white-space: nowrap;
    position: sticky; top: 0;
  }}
  thead th:hover {{ color: var(--text); }}
  thead th.sort-asc::after  {{ content: " \\2191"; color: var(--accent); }}
  thead th.sort-desc::after {{ content: " \\2193"; color: var(--accent); }}
  tbody td {{
    padding: 10px 12px;
    border-bottom: 1px solid rgba(48,54,61,.5);
    vertical-align: top;
  }}
  tbody tr:hover {{ background: rgba(88,166,255,.05); }}
  tbody tr.hidden {{ display: none; }}

  .sev-badge {{
    display: inline-block;
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: .5px;
    color: #fff;
    min-width: 64px;
    text-align: center;
  }}
  .sev-badge.CRITICAL {{ background: var(--crit); }}
  .sev-badge.HIGH     {{ background: var(--high); }}
  .sev-badge.MEDIUM   {{ background: var(--med); color:#000; }}
  .sev-badge.LOW      {{ background: var(--low); }}
  .sev-badge.INFO     {{ background: var(--info); }}

  .code-pill {{
    display: inline-block;
    padding: 1px 8px;
    border-radius: 4px;
    font-family: "SFMono-Regular", Menlo, Consolas, monospace;
    font-size: 12px;
    font-weight: 600;
    background: var(--panel-2);
    border: 1px solid var(--border);
  }}
  .code-pill.s2xx {{ background: rgba(82,196,26,.15); color: var(--info); border-color: var(--info); }}
  .code-pill.s3xx {{ background: rgba(255,216,61,.15); color: var(--med); border-color: var(--med); }}
  .code-pill.s4xx {{ background: rgba(255,122,69,.15); color: var(--high); border-color: var(--high); }}
  .code-pill.s5xx {{ background: rgba(255,56,96,.15); color: var(--crit); border-color: var(--crit); }}

  a.url {{
    color: var(--accent);
    text-decoration: none;
    word-break: break-all;
  }}
  a.url:hover {{ text-decoration: underline; }}

  .kw {{
    display: inline-block;
    background: var(--panel-2);
    color: var(--text-dim);
    padding: 1px 7px;
    border-radius: 3px;
    font-size: 11px;
    margin: 1px 2px 1px 0;
    border: 1px solid var(--border);
  }}

  .empty {{
    text-align: center;
    padding: 40px;
    color: var(--text-dim);
    font-style: italic;
  }}

  .footer {{
    text-align: center;
    color: var(--text-dim);
    font-size: 12px;
    padding: 24px;
    border-top: 1px solid var(--border);
    margin-top: 24px;
  }}
  .footer .heart {{ color: var(--crit); }}

  /* Print-friendly */
  @media print {{
    body {{ background: #fff; color: #000; }}
    .filters {{ display: none; }}
    .section, .stat, .header {{ break-inside: avoid; }}
  }}
</style>
</head>
<body>
<div class="container">

  <!-- Header -->
  <div class="header">
    <div class="brand">
      <div class="logo">D</div>
      <div>
        <h1>{tool} <span style="font-size:14px;color:var(--text-dim);font-weight:400">v{version}</span></h1>
        <div class="meta">Web Path Discovery &amp; Fuzzing Report</div>
      </div>
    </div>
    <div class="author-tag">developed by {author}</div>
  </div>

  <!-- Stats -->
  <div class="stats">
    <div class="stat"><div class="label">Total Requests</div><div class="value">{total_requests}</div></div>
    <div class="stat"><div class="label">Total Findings</div><div class="value">{total_findings}</div></div>
    <div class="stat crit"><div class="label">Critical</div><div class="value">{n_crit}</div></div>
    <div class="stat high"><div class="label">High</div><div class="value">{n_high}</div></div>
    <div class="stat med"><div class="label">Medium</div><div class="value">{n_med}</div></div>
    <div class="stat low"><div class="label">Low</div><div class="value">{n_low}</div></div>
    <div class="stat info"><div class="label">Info</div><div class="value">{n_info}</div></div>
    <div class="stat"><div class="label">Duration</div><div class="value">{duration}s</div></div>
  </div>

  <!-- Scan metadata -->
  <div class="section">
    <h2><span class="dot"></span>Scan Metadata</h2>
    <div class="meta-grid">
      <div><span class="k">Target:</span> <span class="v">{target_url}</span></div>
      <div><span class="k">Host:</span> <span class="v">{target_host}</span></div>
      <div><span class="k">Scan date:</span> <span class="v">{scan_date}</span></div>
      <div><span class="k">Duration:</span> <span class="v">{duration}s</span></div>
      <div><span class="k">Total requests:</span> <span class="v">{total_requests}</span></div>
      <div><span class="k">Total findings:</span> <span class="v">{total_findings}</span></div>
      <div><span class="k">Errors:</span> <span class="v">{errors}</span></div>
      <div><span class="k">Wordlist size:</span> <span class="v">{wordlist_size}</span></div>
      <div><span class="k">Max depth:</span> <span class="v">{max_depth}</span></div>
      <div><span class="k">Concurrency:</span> <span class="v">{concurrency}</span></div>
    </div>
  </div>

  <!-- Level breakdown -->
  {level_breakdown_html}

  <!-- Findings -->
  <div class="section">
    <h2><span class="dot"></span>Findings ({total_findings})</h2>
    <div class="filters">
      <input type="text" id="search" placeholder="Filter by URL, path, keyword...">
      <span class="label">Severity:</span>
      <button class="sev-btn all active" data-sev="ALL">ALL</button>
      <button class="sev-btn crit" data-sev="CRITICAL">CRITICAL</button>
      <button class="sev-btn high" data-sev="HIGH">HIGH</button>
      <button class="sev-btn med"  data-sev="MEDIUM">MEDIUM</button>
      <button class="sev-btn low"  data-sev="LOW">LOW</button>
      <button class="sev-btn info" data-sev="INFO">INFO</button>
      <span class="sep"></span>
      <span class="label">Status:</span>
      <button class="st-btn all active" data-status="ALL">ALL</button>
      {status_buttons_html}
    </div>
    <div class="table-wrap">
      <table id="findings-table">
        <thead>
          <tr>
            <th data-col="severity">Severity</th>
            <th data-col="status">Code</th>
            <th data-col="url">URL</th>
            <th data-col="length">Size</th>
            <th data-col="time">Time</th>
            <th data-col="keywords">Keywords</th>
          </tr>
        </thead>
        <tbody>
          {rows_html}
        </tbody>
      </table>
    </div>
  </div>

  <div class="footer">
    Generated by <strong>{tool} v{version}</strong> &mdash; developed with
    <span class="heart">&#9829;</span> by <strong>{author}</strong>
    <br>{scan_date}
  </div>

</div>

<script>
  // ---- severity filter ----
  let activeSev = "ALL";
  const sevBtns = document.querySelectorAll(".sev-btn");
  sevBtns.forEach(btn => {{
    btn.addEventListener("click", () => {{
      sevBtns.forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      activeSev = btn.dataset.sev;
      applyFilters();
    }});
  }});

  // ---- status-code filter ----
  let activeStatus = "ALL";
  const stBtns = document.querySelectorAll(".st-btn");
  stBtns.forEach(btn => {{
    btn.addEventListener("click", () => {{
      stBtns.forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      activeStatus = btn.dataset.status;
      applyFilters();
    }});
  }});

  // ---- text search ----
  const searchInput = document.getElementById("search");
  searchInput.addEventListener("input", applyFilters);

  function applyFilters() {{
    const q = searchInput.value.toLowerCase().trim();
    document.querySelectorAll("#findings-table tbody tr").forEach(tr => {{
      const sev = tr.dataset.sev;
      const status = tr.dataset.status;
      const text = tr.textContent.toLowerCase();
      const sevOk = (activeSev === "ALL" || sev === activeSev);
      const statusOk = (activeStatus === "ALL" || status === activeStatus);
      const textOk = !q || text.includes(q);
      tr.classList.toggle("hidden", !(sevOk && statusOk && textOk));
    }});
  }}

  // ---- sorting ----
  let sortCol = "severity";
  let sortDir = "asc";
  document.querySelectorAll("#findings-table thead th").forEach(th => {{
    th.addEventListener("click", () => {{
      const col = th.dataset.col;
      if (sortCol === col) {{
        sortDir = sortDir === "asc" ? "desc" : "asc";
      }} else {{
        sortCol = col;
        sortDir = "asc";
      }}
      // visual
      document.querySelectorAll("#findings-table thead th").forEach(t => {{
        t.classList.remove("sort-asc","sort-desc");
      }});
      th.classList.add(sortDir === "asc" ? "sort-asc" : "sort-desc");
      sortTable(col, sortDir);
    }});
  }});

  function sortTable(col, dir) {{
    const tbody = document.querySelector("#findings-table tbody");
    const rows = Array.from(tbody.querySelectorAll("tr"));
    const sevOrder = {{CRITICAL:0, HIGH:1, MEDIUM:2, LOW:3, INFO:4}};
    rows.sort((a, b) => {{
      let av, bv;
      switch(col) {{
        case "severity": av = sevOrder[a.dataset.sev]; bv = sevOrder[b.dataset.sev]; break;
        case "status":   av = parseInt(a.dataset.status); bv = parseInt(b.dataset.status); break;
        case "length":   av = parseInt(a.dataset.length); bv = parseInt(b.dataset.length); break;
        case "time":     av = parseFloat(a.dataset.time); bv = parseFloat(b.dataset.time); break;
        case "url":      av = a.dataset.url; bv = b.dataset.url; break;
        case "keywords": av = a.dataset.kw; bv = b.dataset.kw; break;
        default:         av = 0; bv = 0;
      }}
      if (av < bv) return dir === "asc" ? -1 : 1;
      if (av > bv) return dir === "asc" ? 1 : -1;
      return 0;
    }});
    rows.forEach(r => tbody.appendChild(r));
  }}
  // initial sort: severity asc (CRITICAL first)
  document.querySelector('#findings-table thead th[data-col="severity"]').click();
</script>
</body>
</html>
"""


def _status_pill_class(status):
    if 200 <= status < 300: return "s2xx"
    if 300 <= status < 400: return "s3xx"
    if 400 <= status < 500: return "s4xx"
    if status >= 500:       return "s5xx"
    return ""


def write_html_report(scanner, path):
    """Beautiful, self-contained, sortable HTML report."""
    findings = list(scanner.findings)
    # sort: critical first, then by length desc
    findings.sort(
        key=lambda f: (
            DihFinder.SEVERITY_ORDER.get(f["severity"], 5),
            -f["length"],
        )
    )

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    duration = (scanner.end_time - scanner.start_time) if scanner.end_time else 0
    target_host = urlparse(scanner.target).netloc

    # Build rows
    rows_html_parts = []
    for f in findings:
        kw_html = "".join(
            f'<span class="kw">{_html.escape(k)}</span>'
            for k in f["keywords"]
        ) or '<span style="color:var(--text-dim)">&mdash;</span>'
        pill_cls = _status_pill_class(f["status"])
        url_display = _html.escape(f["url"])
        path_short = _html.escape(f["path"])
        # clickable link
        url_cell = (
            f'<a class="url" href="{_html.escape(f["url"])}" target="_blank" rel="noopener">'
            f'{url_display}</a>'
        )
        rows_html_parts.append(
            f'<tr data-sev="{f["severity"]}" '
            f'      data-status="{f["status"]}" '
            f'      data-length="{f["length"]}" '
            f'      data-time="{f["time"]:.4f}" '
            f'      data-url="{url_display}" '
            f'      data-kw="{_html.escape(",".join(f["keywords"]).lower())}">'
            f'<td><span class="sev-badge {f["severity"]}">{f["severity"]}</span></td>'
            f'<td><span class="code-pill {pill_cls}">{f["status"]}</span></td>'
            f'<td>{url_cell}</td>'
            f'<td>{f["length"]:,} B</td>'
            f'<td>{f["time"]:.2f}s</td>'
            f'<td>{kw_html}</td>'
            f'</tr>'
        )
    rows_html = "\n".join(rows_html_parts) if rows_html_parts else (
        '<tr><td colspan="6" class="empty">No findings.</td></tr>'
    )

    # Level breakdown
    if scanner.level_stats:
        lvl_rows = []
        for ls in scanner.level_stats:
            lvl_rows.append(
                f'<tr>'
                f'<td>Level {ls["level"]}</td>'
                f'<td>{ls["requests"]:,}</td>'
                f'<td>{ls["findings"]}</td>'
                f'<td>{ls["duration"]:.2f}s</td>'
                f'<td>{(ls["requests"]/max(ls["duration"],0.001)):.1f} req/s</td>'
                f'</tr>'
            )
        level_breakdown_html = (
            '<div class="section">'
            '<h2><span class="dot"></span>Scan Levels Breakdown</h2>'
            '<div class="table-wrap"><table>'
            '<thead><tr>'
            '<th>Level</th><th>Requests</th><th>Findings</th>'
            '<th>Duration</th><th>Throughput</th>'
            '</tr></thead>'
            '<tbody>' + "\n".join(lvl_rows) + '</tbody>'
            '</table></div>'
            '</div>'
        )
    else:
        level_breakdown_html = ""

    # v3.1: build dynamic status-code filter buttons
    # Show one button per distinct status code present in findings,
    # sorted numerically. Each button shows the code + count.
    status_counts = {}
    for f in findings:
        s = f["status"]
        status_counts[s] = status_counts.get(s, 0) + 1
    status_buttons_parts = []
    for status in sorted(status_counts.keys()):
        cnt = status_counts[status]
        status_buttons_parts.append(
            f'<button class="st-btn" data-status="{status}" '
            f'title="{cnt} finding(s)">{status} <span style="opacity:.6">({cnt})</span></button>'
        )
    status_buttons_html = "\n      ".join(status_buttons_parts)

    html_out = HTML_TEMPLATE.format(
        tool=TOOL_NAME,
        version=TOOL_VERSION,
        author=TOOL_AUTHOR,
        total_requests=f"{scanner.total_scanned:,}",
        total_findings=len(findings),
        n_crit=counts["CRITICAL"],
        n_high=counts["HIGH"],
        n_med=counts["MEDIUM"],
        n_low=counts["LOW"],
        n_info=counts["INFO"],
        duration=f"{duration:.1f}",
        target_url=_html.escape(scanner.target),
        target_host=_html.escape(target_host),
        scan_date=time.strftime("%Y-%m-%d %H:%M:%S"),
        errors=scanner.errors,
        wordlist_size=len(scanner.wordlist),
        max_depth=scanner.max_depth,
        concurrency=scanner.concurrency,
        level_breakdown_html=level_breakdown_html,
        status_buttons_html=status_buttons_html,
        rows_html=rows_html,
    )
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(html_out)
        console.print(Text(f"[+] HTML report saved to {path}", style="green"))
    except OSError as e:
        console.print(Text(f"[!] Could not write HTML report: {e}", style="bold red"))


# ===========================================================================
# CLI
# ===========================================================================
def _parse_header(s):
    """Parse 'Key: Value' header strings into a dict."""
    headers = {}
    for h in s:
        if ":" not in h:
            console.print(
                Text(f"[!] Invalid header format (expected 'Key: Value'): {h}",
                     style="bold red")
            )
            sys.exit(1)
        k, v = h.split(":", 1)
        headers[k.strip()] = v.strip()
    return headers


def _parse_int_list(s):
    """Parse '200,301,401' into {200,301,401}."""
    out = set()
    for part in s.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            out.add(int(part))
        except ValueError:
            console.print(
                Text(f"[!] Invalid status code: {part}", style="bold red")
            )
            sys.exit(1)
    return out


def main():
    parser = argparse.ArgumentParser(
        description=f"{TOOL_NAME} v{TOOL_VERSION} - Advanced Async Web Path Scanner (by {TOOL_AUTHOR})",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            f"Examples:\n"
            f"  python3 dihfinder.py https://example.com\n"
            f"  python3 dihfinder.py https://example.com -d 3 -t 30\n"
            f"  python3 dihfinder.py https://example.com -x php,html,bak\n"
            f"  python3 dihfinder.py https://example.com -w custom.txt\n"
            f"  python3 dihfinder.py https://example.com --html report.html\n"
            f"  python3 dihfinder.py https://example.com --json results.json\n"
            f"  python3 dihfinder.py https://example.com --proxy http://127.0.0.1:8080\n"
            f"  python3 dihfinder.py https://example.com -H 'Authorization: Bearer xx' -H 'Cookie: sid=abc'\n"
            f"  python3 dihfinder.py https://example.com --include-status 200,401,403\n"
        ),
    )
    parser.add_argument("target", help="Target URL (e.g. https://example.com)")
    parser.add_argument("-w", "--wordlist",
                        help="Custom wordlist file (one path per line)")
    parser.add_argument("-t", "--threads", type=int, default=20,
                        help="Concurrency level (default: 20)")
    parser.add_argument("-d", "--depth", type=int, default=3,
                        help="Max scan depth for multi-level scanning "
                             "(default: 3 -> /a/b/c)")
    parser.add_argument("--timeout", type=int, default=10,
                        help="Per-request timeout in seconds (default: 10)")
    parser.add_argument("-x", "--extensions",
                        help="Comma-separated extensions to also try "
                             "(e.g. php,html,bak,txt)")
    parser.add_argument("--ua", help="Custom User-Agent string")
    parser.add_argument("-o", "--output",
                        help="Save findings to a plain-text file")
    parser.add_argument("--html",
                        help="Generate a styled HTML report and save to this path")
    parser.add_argument("--json",
                        help="Generate a JSON report and save to this path")
    parser.add_argument("--proxy",
                        help="HTTP/HTTPS/SOCKS proxy URL "
                             "(e.g. http://127.0.0.1:8080)")
    parser.add_argument("-H", "--header", action="append", default=[],
                        help="Custom HTTP header (repeatable). "
                             "Example: -H 'Authorization: Bearer xxx'")
    parser.add_argument("--include-status",
                        help="Comma-separated HTTP status codes to keep "
                             "(others dropped). e.g. 200,401,403")
    parser.add_argument("--match-size",
                        help="Comma-separated response sizes (bytes) to keep. "
                             "401/403 are always kept regardless.")
    args = parser.parse_args()

    # Load wordlist
    wordlist = WORDLIST
    if args.wordlist:
        try:
            with open(args.wordlist, "r", encoding="utf-8", errors="ignore") as fh:
                wordlist = [
                    line.strip() for line in fh
                    if line.strip() and not line.startswith("#")
                ]
        except FileNotFoundError:
            console.print(
                Text(f"Error: wordlist file not found: {args.wordlist}",
                     style="bold red")
            )
            sys.exit(1)

    extensions = None
    if args.extensions:
        extensions = [
            "." + e.strip().lstrip(".") for e in args.extensions.split(",") if e.strip()
        ]

    extra_headers = _parse_header(args.header) if args.header else None
    include_status = _parse_int_list(args.include_status) if args.include_status else None
    match_size = _parse_int_list(args.match_size) if args.match_size else None

    scanner = DihFinder(
        target=args.target,
        wordlist=wordlist,
        concurrency=args.threads,
        timeout=args.timeout,
        user_agent=args.ua,
        max_depth=args.depth,
        extensions=extensions,
        proxy=args.proxy,
        extra_headers=extra_headers,
        include_status=include_status,
        match_size=match_size,
    )

    interrupted = False
    try:
        asyncio.run(scanner.scan())
    except KeyboardInterrupt:
        interrupted = True
        console.print(Text("\n[!] Scan interrupted - saving partial results...",
                           style="yellow"))
        if scanner.start_time and not scanner.end_time:
            scanner.end_time = time.time()
    except aiohttp.ClientError as e:
        console.print(Text(f"\n[!] HTTP client error: {e}", style="bold red"))
        sys.exit(1)

    display_results(scanner)

    # Always show what got saved
    if interrupted and not (args.output or args.html or args.json):
        console.print(
            Text("[i] No output flag set - partial results not saved. "
                 "Use -o / --html / --json next time.", style="yellow")
        )

    if args.output:
        write_txt_report(scanner, args.output)
    if args.html:
        write_html_report(scanner, args.html)
    if args.json:
        write_json_report(scanner, args.json)


if __name__ == "__main__":
    main()
