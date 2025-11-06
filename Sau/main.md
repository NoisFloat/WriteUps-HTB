
# Sau - CVEs encadenadas, SSRF to RCE
#### Recopilacion de Información

> Escaneo de puertos

<br>

```bash
┌─[us-dedivip-1]─[10.10.14.54]─[noisfloat@htb-uriohnwc1u]─[~/Desktop]
└──╼ [★]$ nmap 10.129.17.115
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-11-06 11:23 CST
Nmap scan report for 10.129.17.115
Host is up (0.0092s latency).
Not shown: 997 closed tcp ports (reset)
PORT      STATE    SERVICE
22/tcp    open     ssh
80/tcp    filtered http
55555/tcp open     unknown

```
<br>

***Se han detectado tres servicios principales: SSH, HTTP y un servicio desconocido. El puerto 80 no es accesible y, actualmente, no existe ninguna CVE aplicable a la versión de SSH en uso.***

<br>

> Con nmap -sV se identificó un servicio HTTP en el puerto 55555

<br>

```bash
┌─[us-dedivip-1]─[10.10.14.54]─[noisfloat@htb-uriohnwc1u]─[~/Desktop]
└──╼ [★]$ nmap -sV 10.129.17.115
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-11-06 11:23 CST
Nmap scan report for 10.129.17.115
Host is up (0.0089s latency).
Not shown: 997 closed tcp ports (reset)
PORT      STATE    SERVICE VERSION
22/tcp    open     ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
80/tcp    filtered http
55555/tcp open     unknown
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :

SF-Port55555-TCP:V=7.94SVN%I=7%D=11/6%Time=690CD9B5%P=x86_64-pc-linux-gnu%
SF:r(GetRequest,A2,"HTTP/1\.0\x20302\x20Found\r\nContent-Type:\x20text/htm
SF:l;\x20charset=utf-8\r\nLocation:\x20/web\r\nDate:\x20Thu,\x2006\x20Nov\
SF:x202025\x2017:24:05\x20GMT\r\nContent-Length:\x2027\r\n\r\n<a\x20href=\
SF:"/web\">Found</a>\.\n\n")%r(GenericLines,67,"HTTP/1\.1\x20400\x20Bad\x2
SF:0Request\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection
SF::\x20close\r\n\r\n400\x20Bad\x20Request")%r(HTTPOptions,60,"HTTP/1\.0\x
SF:20200\x20OK\r\nAllow:\x20GET,\x20OPTIONS\r\nDate:\x20Thu,\x2006\x20Nov\
SF:x202025\x2017:24:05\x20GMT\r\nContent-Length:\x200\r\n\r\n")%r(RTSPRequ
SF:est,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/pla
SF:in;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Reque
SF:st")%r(Help,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20
SF:text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\
SF:x20Request")%r(SSLSessionReq,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\n
SF:Content-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r
SF:\n\r\n400\x20Bad\x20Request")%r(TerminalServerCookie,67,"HTTP/1\.1\x204
SF:00\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r
SF:\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(TLSSessionReq,6
SF:7,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x
SF:20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request")%
SF:r(Kerberos,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20t
SF:ext/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x
SF:20Request")%r(FourOhFourRequest,EA,"HTTP/1\.0\x20400\x20Bad\x20Request\
SF:r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nX-Content-Type-Opti
SF:ons:\x20nosniff\r\nDate:\x20Thu,\x2006\x20Nov\x202025\x2017:24:30\x20GM
SF:T\r\nContent-Length:\x2075\r\n\r\ninvalid\x20basket\x20name;\x20the\x20
SF:name\x20does\x20not\x20match\x20pattern:\x20\^\[\\w\\d\\-_\\\.\]{1,250}
SF:\$\n")%r(LPDString,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Ty
SF:pe:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\
SF:x20Bad\x20Request")%r(LDAPSearchReq,67,"HTTP/1\.1\x20400\x20Bad\x20Requ
SF:est\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20
SF:close\r\n\r\n400\x20Bad\x20Request");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 90.12 seconds
```
<br>

![Img1](/Sau/static/Img1.png)   <!-- sin la barra inicial -->


***Se identifico gracias el footer la version del servicio, que es vulnerable a SSRF - CVE-2023-27163:***

[Github Advisories Database](https://github.com/advisories/GHSA-58g2-vgpg-335q)
[PoC PacketStorm](https://packetstorm.news/files/id/174128)


---

##### SSRF

La CVE, te detalla que el endpoint afectado es `http://<ip>:<port>/api/baskets/<someString> via POST`


```text
{"forward_url": "http://url_atacante_o_interna","proxy_response": true,"insecure_tls": false,"expand_path": true,"capacity": 250}
```

<br>

Una vez procesada la petición, el servidor se comporta como un proxy que permite realizar solicitudes al endpoint especificado en `payload.forward_url.`

<br>

> Ejemplo de explotación:

![Img2](/Sau/static/Img2.png)
![Img3](/Sau/static/Img3.png) 

Como puedes ver, ahora gracias a SSRF pude obtener un proxy a la maquina atacante a su puerto 80, que no esta disponible a acceso desde la ip externa que tiene la maquita victima.

***Ademas se identifico el uso de Meltrail 0.53, gracias a la respuesta obtenida del proxy***

![Img4](/Sau/static/Img4.png)

---

##### RCE

[PoC de RCE - Meltrail 0.53](https://packetstorm.news/files/id/174129)

![Img5](/Sau/static/Img5.png)

---

##### Escalación de Privilegios

El ejecutable /usr/bin/systemctl 245 (245.4-4ubuntu3.22) es vulnerable a CVE-2023-26604

[CVE - PoC](https://packetstorm.news/files/id/174130)



![Privilege Scalation](/Sau/static/Img6.png)