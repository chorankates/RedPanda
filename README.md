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
|     Request</title><style type="text/css">body {font-family:Tahoma,Arial,sans-serif;} h1, h2, h3, b {color:white;background-color:#525D76;} h1 {font-size:22px;} h2 {font-size:16px;} h3 {fo
nt-size:14px;} p {font-size:12px;} a {color:black;} .line {height:1px;background-color:#525D76;border:none;}</style></head><body><h1>HTTP Status 400
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


```
$ curl http://redpanda.htb:8080/search -X POST --data-raw 'name=#{{7*7}}'

    <h2 class="searched">You searched for: ??{7*7}_en_US??</h2>
      <h2>There are 0 results for your search</h2>

```

not injection, but modification



## flag

```
user:
root:
```
