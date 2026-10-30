COMMON_PATHS = """admin administrator login logout signin signup register account
accounts dashboard panel cpanel wp-admin wp-login.php phpmyadmin adminer api api/v1
api/v2 v1 v2 v3 internal private restricted dev stage staging test uat prod graphql
graphiql swagger swagger-ui swagger.json openapi.json openapi.yaml api-docs docs
redoc .well-known .well-known/security.txt robots.txt sitemap.xml humans.txt
metrics health healthz status ping version info debug console actuator actuator/env
actuator/health server-status server-info phpinfo.php test.php info.php config
config.php settings settings.py web.config app.config .env .env.local .env.prod
.git .git/HEAD .git/config .svn .svn/entries .hg .DS_Store backup backups bak old
tmp temp cache upload uploads files file download downloads assets static public
media images img css js scripts includes lib vendor node_modules dist build
db database sql dump.sql backup.sql data.json export.json users user profile
search results report reports logs log error errors mail email newsletter
cron jobs task tasks queue worker service services ws wss socket websocket
oauth oauth2 authorize token tokens sso saml callback redirect return
robots.txt crossdomain.xml clientaccesspolicy.xml manifest.json favicon.ico
index index.html index.php index.jsp default.aspx home main""".split()

BACKUP_EXT = [".bak", ".old", ".orig", ".save", ".swp", ".tmp", "~", ".zip", ".tar.gz", ".sql", ".txt", ".copy"]

SENSITIVE_FILES = [
    ".git/HEAD", ".git/config", ".git/index", ".svn/entries", ".hg/requires",
    ".DS_Store", ".env", ".env.local", ".env.dev", ".env.prod", ".env.backup",
    "config.php.bak", "config.json", "config.yaml", "config.yml", "settings.py",
    ".htaccess", ".htpasswd", "web.config", "appsettings.json", "credentials.json",
    "composer.json", "package.json", "yarn.lock", "docker-compose.yml", "Dockerfile",
    "id_rsa", "id_rsa.pub", ".aws/credentials", ".npmrc", ".git-credentials",
]

SUBDOMAIN_WORDS = """www mail remote blog webmail server ns1 ns2 dns smtp secure vpn
admin portal api dev test staging stage beta demo app apps mobile m shop store cdn
static assets img images media video files ftp git gitlab jenkins ci build repo wiki
docs help support forum community chat mx mx1 mx2 email web host cloud vps db
database sql proxy gateway lb intranet extranet partner client vendor old new backup
archive login sso auth oauth id account billing pay status monitor grafana""".split()

SECRET_PATTERNS = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "AWS Secret": r"(?i)aws.{0,20}?['\"]([0-9a-zA-Z/+]{40})['\"]",
    "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "Google OAuth": r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com",
    "Stripe Live": r"sk_live_[0-9a-zA-Z]{24}",
    "Stripe Test": r"sk_test_[0-9a-zA-Z]{24}",
    "Slack Token": r"xox[baprs]-[0-9a-zA-Z\-]{10,72}",
    "GitHub Token": r"gh[pousr]_[0-9A-Za-z]{36,}",
    "JWT": r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]+",
    "Private Key": r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
    "SendGrid": r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}",
    "Twilio": r"SK[0-9a-fA-F]{32}",
    "Mailgun": r"key-[0-9a-zA-Z]{32}",
    "Heroku": r"(?i)heroku[a-z0-9_ .\-]{0,20}['\"]([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['\"]",
    "Firebase URL": r"https://[a-z0-9-]+\.firebaseio\.com",
    "Generic API Key": r"(?i)(api[_-]?key|apikey)['\"]?\s*[:=]\s*['\"]([A-Za-z0-9_\-]{16,45})['\"]",
}
