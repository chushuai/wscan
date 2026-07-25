/**
* @Author: shaochuyu
* @Date: 6/16/2026 10:00
 */
package sensitivefile

// buildSensitiveFileEntries returns the built-in list of sensitive files
// to detect, inspired by AWVS PerFolder/Sensitive_Files.script and
// PerFolder/dotenv_File.script logic.
func buildSensitiveFileEntries() []*SensitiveFileEntry {
	return []*SensitiveFileEntry{
		// ---- Environment / Config Files ----
		{
			Name:        ".env",
			Pattern:     `(APP_ENV|DB_PASSWORD|DB_HOST|DB_DATABASE|REDIS_HOST|APP_DEBUG|MAIL_HOST|MAIL_PORT|MAIL_DRIVER|CACHE_DRIVER|QUEUE_DRIVER|APP_KEY)\s*=`,
			Description: "Environment configuration file exposing database credentials, API keys, and application secrets",
			Severity:    "high",
		},
		{
			Name:        "._env",
			Pattern:     `(APP_ENV|DB_PASSWORD|DB_HOST|DB_DATABASE|REDIS_HOST|APP_DEBUG|MAIL_HOST|MAIL_PORT|MAIL_DRIVER|CACHE_DRIVER|QUEUE_DRIVER|APP_KEY)\s*=`,
			Description: "Alternate environment file (._env) exposing credentials",
			Severity:    "high",
		},
		{
			Name:        "config/secrets.yml",
			Pattern:     `(production:|development:|test:|secret_key_base:|secret:|password:)\s`,
			Description: "Rails secrets configuration file exposing secret_key_base and credentials",
			Severity:    "critical",
		},
		{
			Name:        "database.yml",
			Pattern:     `(development:|production:|test:|adapter:|encoding:|database:|username:|password:|host:)\s`,
			Description: "Ruby on Rails database configuration file exposing database credentials",
			Severity:    "critical",
		},
		{
			Name:        "appsettings.json",
			Pattern:     `"(ConnectionStrings|AppSettings|Secret|ApiKey|Password|JwtKey|TokenKey|EncryptionKey)"`,
			Description: "ASP.NET application settings file exposing connection strings and secrets",
			Severity:    "critical",
		},
		{
			Name:        "wp-config.php",
			Pattern:     `(DB_PASSWORD|DB_USER|DB_NAME|DB_HOST|AUTH_KEY|SECURE_AUTH_KEY|LOGGED_IN_KEY|NONCE_KEY)`,
			Description: "WordPress configuration file exposing database credentials and authentication keys",
			Severity:    "critical",
		},

		// ---- SSH / Private Key Files ----
		{
			Name:        "id_rsa",
			Pattern:     `-----BEGIN RSA PRIVATE KEY-----`,
			Description: "RSA private key file exposed, allowing unauthorized SSH access",
			Severity:    "critical",
		},
		{
			Name:        "id_dsa",
			Pattern:     `-----BEGIN DSA PRIVATE KEY-----`,
			Description: "DSA private key file exposed, allowing unauthorized SSH access",
			Severity:    "critical",
		},
		{
			Name:        "id_ecdsa",
			Pattern:     `-----BEGIN EC PRIVATE KEY-----`,
			Description: "ECDSA private key file exposed, allowing unauthorized SSH access",
			Severity:    "critical",
		},
		{
			Name:        ".ssh/id_rsa",
			Pattern:     `-----BEGIN RSA PRIVATE KEY-----`,
			Description: "RSA private key in .ssh directory exposed",
			Severity:    "critical",
		},
		{
			Name:        ".ssh/authorized_keys",
			Pattern:     `ssh-(rsa|dss|ed25519|ecdsa)\s`,
			Description: "SSH authorized keys file exposed",
			Severity:    "high",
		},

		// ---- Shell History Files ----
		{
			Name:        ".bash_history",
			Pattern:     `(ls|cd|cat|vim|ssh|git|mysql|curl|wget|sudo|chmod|chown|mkdir|rm|cp|mv|grep|find|apt|yum|pip|npm|docker|kubectl)\s`,
			Description: "Bash history file exposing previously executed commands and potential credentials",
			Severity:    "medium",
		},
		{
			Name:        ".mysql_history",
			Pattern:     `(CREATE|GRANT|FLUSH|SELECT|UPDATE|INSERT|DELETE|DROP|ALTER|SHOW|USE)\s`,
			Description: "MySQL command history file exposing SQL operations and database interactions",
			Severity:    "medium",
		},
		{
			Name:        ".psql_history",
			Pattern:     `(CREATE|SELECT|INSERT|UPDATE|DELETE|ALTER|DROP|GRANT|\\d|\\c|\\l|\\q)\s`,
			Description: "PostgreSQL command history file exposing SQL operations",
			Severity:    "medium",
		},
		{
			Name:        ".zsh_history",
			Pattern:     `(ls|cd|cat|vim|ssh|git|mysql|curl|wget|sudo|chmod|pip|npm|docker)\s`,
			Description: "Zsh history file exposing previously executed commands",
			Severity:    "medium",
		},

		// ---- FTP / Server Config ----
		{
			Name:        "sftp-config.json",
			Pattern:     `"host"\s*:\s*".*?"\s*,\s*"user"\s*:\s*".*?"\s*,\s*"password"\s*:\s*".*?"`,
			Description: "SFTP configuration file (Sublime Text) exposing server credentials",
			Severity:    "critical",
		},
		{
			Name:        "recentservers.xml",
			Pattern:     `<Pass>`,
			Description: "FileZilla recent servers file exposing FTP server passwords",
			Severity:    "critical",
		},

		// ---- Apache / Web Server Config ----
		{
			Name:        ".htaccess",
			Pattern:     `(RewriteEngine|RewriteCond|RewriteRule|AuthType|AuthName|AuthUserFile|php_flag|php_value|deny|allow|Options)\s`,
			Description: "Apache configuration file exposing rewrite rules and authentication settings",
			Severity:    "medium",
		},
		{
			Name:        ".htpasswd",
			Pattern:     `:\$apr1\$|:\{SHA\}|:\$2[ayb]\$`,
			Description: "Apache password file exposing hashed credentials",
			Severity:    "high",
		},

		// ---- System / Metadata Files ----
		{
			Name:        ".DS_Store",
			Pattern:     `Bud1`,
			Description: "macOS directory metadata file exposing directory structure",
			Severity:    "low",
		},
		{
			Name:        ".gitignore",
			Pattern:     `(node_modules|vendor|\.env|secret|password|\.key|\.pem|\.log|\.cache|\.sql|backup|dump)\s`,
			Description: "Git ignore file revealing project structure and potentially sensitive excluded paths",
			Severity:    "low",
		},
		{
			Name:        "robots.txt",
			Pattern:     `(Disallow|Allow)\s*:\s*/`,
			Description: "Robots.txt file revealing restricted paths and administrative areas",
			Severity:    "info",
		},
		{
			Name:        "crossdomain.xml",
			Pattern:     `allow-access-from\s+domain`,
			Description: "Cross-domain policy file exposing permitted cross-origin access domains",
			Severity:    "medium",
		},

		// ---- Source Control ----
		{
			Name:        ".git/HEAD",
			Pattern:     `ref:\s+refs/heads/`,
			Description: "Git HEAD file indicating exposed git repository",
			Severity:    "high",
		},
		{
			Name:        ".svn/entries",
			Pattern:     `dir\s`,
			Description: "SVN entries file indicating exposed Subversion repository",
			Severity:    "high",
		},

		// ---- Docker / Container ----
		{
			Name:        "docker-compose.yml",
			Pattern:     `(environment|password|secret|MYSQL_ROOT_PASSWORD|POSTGRES_PASSWORD|API_KEY|TOKEN)\s*:`,
			Description: "Docker Compose file exposing container environment variables and passwords",
			Severity:    "critical",
		},
		{
			Name:        "docker-compose.yaml",
			Pattern:     `(environment|password|secret|MYSQL_ROOT_PASSWORD|POSTGRES_PASSWORD|API_KEY|TOKEN)\s*:`,
			Description: "Docker Compose YAML file exposing container environment variables and passwords",
			Severity:    "critical",
		},
		{
			Name:        "Dockerfile",
			Pattern:     `(FROM|ENV|ARG|RUN|COPY|EXPOSE|CMD)\s`,
			Description: "Dockerfile exposing build instructions and potential environment secrets",
			Severity:    "medium",
		},

		// ---- Cloud / Infrastructure ----
		{
			Name:        ".terraform.tfstate",
			Pattern:     `(resource|provider|output|variable|"secret"|token|access_key)\s`,
			Description: "Terraform state file exposing infrastructure configuration and secrets",
			Severity:    "critical",
		},
		{
			Name:        "terraform.tfstate",
			Pattern:     `(resource|provider|output|variable|"secret"|token|access_key)\s`,
			Description: "Terraform state file (without dot prefix) exposing infrastructure configuration",
			Severity:    "critical",
		},

		// ---- IDE / Development ----
		{
			Name:        ".idea/workspace.xml",
			Pattern:     `(project|component|option|name)\s`,
			Description: "IntelliJ IDEA workspace file revealing project structure and development paths",
			Severity:    "low",
		},
		{
			Name:        "nbproject/project.properties",
			Pattern:     `(javac|src|build|dist|libs)\s*=`,
			Description: "NetBeans project properties file exposing project configuration",
			Severity:    "low",
		},
		{
			Name:        ".vscode/settings.json",
			Pattern:     `"remote\.path"|"remote\.ssh"|"terminal\.integrated"|"python\.path"`,
			Description: "VS Code settings file revealing development environment configuration",
			Severity:    "low",
		},

		// ---- Log / Debug Files ----
		{
			Name:        "error.log",
			Pattern:     `(ERROR|FATAL|Exception|Stacktrace|Traceback|segfault|panic)\s`,
			Description: "Error log file exposing application errors, stack traces, and internal paths",
			Severity:    "medium",
		},
		{
			Name:        "debug.log",
			Pattern:     `(DEBUG|INFO|WARN|ERROR|FATAL)\s`,
			Description: "Debug log file exposing application debug information",
			Severity:    "medium",
		},

		// ---- Backup / Dump ----
		{
			Name:        "${dirname}.sql",
			Pattern:     `(INSERT\s+INTO|CREATE\s+TABLE|DROP\s+TABLE|MySQL|mysqldump|pg_dump)\s`,
			Description: "SQL dump file named after the directory, exposing database contents",
			Severity:    "critical",
		},
		{
			Name:        "${dirname}.bak",
			Pattern:     `(<?php|<!DOCTYPE|<html|<script|<asp|import\s|package\s|class\s)\s`,
			Description: "Backup file named after the directory, potentially exposing source code",
			Severity:    "high",
		},
		{
			Name:        "backup.sql",
			Pattern:     `(INSERT\s+INTO|CREATE\s+TABLE|DROP\s+TABLE|MySQL|mysqldump|pg_dump)\s`,
			Description: "Generic SQL backup file exposing database contents",
			Severity:    "critical",
		},
		{
			Name:        "db.sql",
			Pattern:     `(INSERT\s+INTO|CREATE\s+TABLE|DROP\s+TABLE|MySQL|mysqldump)\s`,
			Description: "Database SQL file exposing database contents",
			Severity:    "critical",
		},

		// ---- PHP Config ----
		{
			Name:        "phpinfo.php",
			Pattern:     `phpinfo\(\)|PHP\s+Version`,
			Description: "PHP info file exposing detailed PHP configuration and server environment",
			Severity:    "medium",
		},

		// ---- AWS / Cloud Keys ----
		{
			Name:        ".aws/credentials",
			Pattern:     `(aws_access_key_id|aws_secret_access_key)\s*=`,
			Description: "AWS credentials file exposing access keys",
			Severity:    "critical",
		},

		// ---- Kubernetes ----
		{
			Name:        "kubeconfig.yml",
			Pattern:     `(cluster|user|context|namespace|certificate|token)\s*:`,
			Description: "Kubernetes configuration file exposing cluster access credentials",
			Severity:    "critical",
		},
	}
}
