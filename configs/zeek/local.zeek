# VN-SOC Zeek local site policy — SOC-Tools deployment
# Path: /opt/zeek/share/zeek/site/local.zeek (edit after apt install zeek)

# Enable JSON output cho Filebeat ingest
@load policy/tuning/json-logs.zeek

# Load essential frameworks
@load base/frameworks/notice
@load base/frameworks/software
@load base/protocols/conn
@load base/protocols/http
@load base/protocols/dns
@load base/protocols/ssl
@load base/protocols/ssh
@load base/protocols/ftp
@load base/protocols/smtp

# Software detection — track versions HTTP User-Agent, SSH banner
@load protocols/http/software
@load protocols/ssh/software

# Detect common attack patterns
@load protocols/http/detect-sqli
@load protocols/http/detect-webapps

# SSH bruteforce detection
@load policy/protocols/ssh/detect-bruteforcing
redef SSH::password_guesses_limit = 10;

# DNS anomaly detection
@load policy/protocols/dns/detect-external-names
@load policy/protocols/dns/auth-addl

# TLS/SSL analysis
@load protocols/ssl/log-hostcerts-only
@load protocols/ssl/notary
@load policy/protocols/ssl/validate-certs
@load policy/protocols/ssl/log-hostcerts-only
@load policy/protocols/ssl/expiring-certs

# Intel framework — future IOC feed integration
@load frameworks/intel/seen
@load frameworks/intel/do_notice
# redef Intel::read_files += { "/opt/zeek/share/zeek/site/intel-feed.txt" };

# JA3/JA3S TLS fingerprint (ships default in Zeek 5+)
@load base/protocols/ssl

# VN-SOC lab custom notice
redef Notice::default_suppression_interval = 10min;

# Log rotation — hourly rotate + keep 30 days (aligned với ILM)
redef Log::default_rotation_interval = 1 hr;
