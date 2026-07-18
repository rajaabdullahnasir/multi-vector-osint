"""
Built-in wordlists for directory/file brute-forcing — generic, extremely
common path conventions used across virtually every web stack (admin
panels, config/backup file naming conventions, standard framework and
CMS paths). No external downloads required.
"""

from __future__ import annotations

QUICK_WORDLIST: tuple[str, ...] = (
    "admin", "administrator", "login", "wp-admin", "wp-login.php",
    "dashboard", "panel", "cpanel", "phpmyadmin", "config",
    "config.php", "configuration.php", "settings", "backup", "backups",
    "db", "database", "sql", "test", "dev", "staging", "old", "new",
    "api", "api/v1", "api/v2", "docs", "swagger", "swagger-ui",
    ".env", ".git", ".git/config", ".htaccess", "robots.txt",
    "sitemap.xml", "server-status", "actuator", "actuator/health",
    "console", "manager", "manage", "uploads", "files", "tmp",
    "logs", "log", "debug",
)

_ADDITIONAL_COMMON: tuple[str, ...] = (
    "about", "account", "accounts", "ajax", "app", "apps", "archive",
    "assets", "auth", "backend", "beta", "billing", "blog", "cache",
    "cart", "checkout", "cgi-bin", "client", "clients", "cms",
    "components", "connect", "contact", "content", "core", "css",
    "customer", "data", "demo", "deploy", "docroot", "download",
    "downloads", "edit", "editor", "email", "error", "errors", "export",
    "extensions", "faq", "feed", "feedback", "forgot-password",
    "forum", "ftp", "help", "history", "home", "host", "hosting",
    "hr", "images", "img", "import", "include", "includes", "index",
    "info", "install", "internal", "invoice", "js", "json", "layout",
    "lib", "library", "license", "list", "local", "mail", "main",
    "maintenance", "media", "member", "members", "message", "messages",
    "meta", "mobile", "module", "modules", "monitor", "monitoring",
    "news", "newsletter", "node_modules", "notification",
    "notifications", "order", "orders", "output", "package", "page",
    "pages", "partner", "partners", "payment", "payments", "phpinfo.php",
    "plugin", "plugins", "portal", "preview", "private", "product",
    "products", "profile", "project", "projects", "public", "purchase",
    "queue", "register", "release", "report", "reports", "reset",
    "reset-password", "resource", "resources", "rest", "review",
    "reviews", "role", "roles", "root", "rss", "sales", "sample",
    "scripts", "search", "secret", "secure", "security", "service",
    "services", "session", "share", "shipping", "shop", "signin",
    "signup", "site", "sitemap", "source", "sql.php", "src", "ssh",
    "static", "status", "store", "stream", "style", "styles",
    "subscribe", "support", "system", "team", "template", "templates",
    "temp", "terms", "theme", "themes", "token", "tools", "tracking",
    "transfer", "unsubscribe", "update", "updates", "upload", "user",
    "users", "utils", "v1", "v2", "vendor", "verify", "version",
    "video", "videos", "view", "views", "web", "webmail", "wiki",
    "workspace", "xml",
)
COMMON_WORDLIST: tuple[str, ...] = tuple(dict.fromkeys(QUICK_WORDLIST + _ADDITIONAL_COMMON))

_ADDITIONAL_EXTENDED: tuple[str, ...] = (
    ".git/HEAD", ".git/index", ".gitignore", ".svn", ".svn/entries",
    ".hg", ".bzr", ".DS_Store", ".env.local", ".env.production",
    ".env.backup", ".env.example", "id_rsa", "id_rsa.pub",
    "credentials", "credentials.json", "secrets", "secrets.json",
    "secrets.yml", ".npmrc", ".dockercfg", "docker-compose.yml",
    "Dockerfile", ".well-known/security.txt",
    "backup.zip", "backup.tar.gz", "backup.sql", "backup.sql.gz",
    "site.zip", "site.tar.gz", "www.zip", "database.sql",
    "dump.sql", "site-backup", "old-site", "site.bak", "index.php.bak",
    "config.bak", "config.old", "web.config.bak",
    "wp-content", "wp-content/uploads", "wp-content/plugins",
    "wp-content/themes", "wp-includes", "wp-config.php",
    "wp-config.php.bak", "wp-json", "wp-json/wp/v2/users",
    "xmlrpc.php", "wp-cron.php",
    "administrator/index.php", "configuration.php.bak",
    "sites/default/settings.php", "sites/default/files",
    "core/install.php", "user/login", "CHANGELOG.txt",
    "laravel", ".env.dev", "storage/logs/laravel.log",
    "artisan", "vendor/composer", "app/config", "web.config",
    "global.asax", "Startup.cs", "appsettings.json",
    "django-admin", "manage.py", "settings.py", "urls.py",
    "__pycache__", "requirements.txt", "Pipfile",
    "next.config.js", "package.json", "package-lock.json",
    "yarn.lock", "tsconfig.json", "webpack.config.js",
    "api/health", "api/status", "api/ping", "api/docs",
    "graphql", "graphiql", "health", "healthz", "readiness",
    "liveness", "metrics", "prometheus", "grafana",
    "swagger.json", "openapi.json", "openapi.yaml",
    "jenkins", "gitlab", "sonarqube", "kibana", "elasticsearch",
    "rabbitmq", "portainer", "traefik", "adminer", "pma",
    "webmin", "plesk", "vtiger", "roundcube", "squirrelmail",
    "nagios", "zabbix", "grafana/login",
    ".aws", ".aws/credentials", "terraform.tfstate",
    "ansible.cfg", "kube-config", ".kube/config",
    "serverless.yml", "cloudformation.json",
    "phpinfo", "info.php", "test.php", "shell.php", "debug.php",
    "console.php", "adminer.php", "upload.php", "file.php",
    "readme.html", "README.md", "CHANGELOG.md", "LICENSE",
    "composer.json", "composer.lock", "Gemfile", "Gemfile.lock",
    "config.yaml", "config.yml", "application.yml",
    "application.properties", "web.xml",
)
EXTENDED_WORDLIST: tuple[str, ...] = tuple(
    dict.fromkeys(COMMON_WORDLIST + _ADDITIONAL_EXTENDED)
)

WORDLIST_TIERS: dict[str, tuple[str, ...]] = {
    "quick": QUICK_WORDLIST,
    "common": COMMON_WORDLIST,
    "extended": EXTENDED_WORDLIST,
}

WORDLIST_LABELS: dict[str, str] = {
    "quick": f"Quick ({len(QUICK_WORDLIST)} paths — fastest)",
    "common": f"Common ({len(COMMON_WORDLIST)} paths — balanced)",
    "extended": f"Extended ({len(EXTENDED_WORDLIST)} paths — most thorough, slowest)",
}
