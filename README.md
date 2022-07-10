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




## flag
```
user:
root:
```
