# Recon.py
This is the recon scanning tool I had to create as part of my Scripting module. I have copied the repository from my school account to also store it here for later reflection, as I may come back to this in the future to improve upon it in my own time, when I feel I am ready to do a better job.

# Assignment2, project overview:
Repository for assignment 2, recon.py <br>
This is a scanning tool called recon.py, designed to be used to gather information from a websites open ports, and output it to a readable json and csv file. It is ran through the CLI.
Video demo can be found here: https://setuo365-my.sharepoint.com/:f:/g/personal/c00306572_setu_ie/IgCQKlu7AGZ_SrDsxt-9T1OHAbuW7dfZ4cWUA0M9WMxSHN4?e=Yh1ubv
# Requirements:
The following is a list of all libraries used to create this file: <br>
socket, argparse, concurrent.futures, json, time, ssl, re, requests, hashlib, csv and datetime

# Running the Code:
To run the code, you must use the CLI through your terminal. Here is an example of an input to get the program running. The code runs by reading targets from the targets.txt file. If you wanted to change the target(s), you simple write to the targets file. This allows for multiple targets to be scanned at once. You can specify either one ore two ports, or provide a range, along with a timeout:
```
$ python3 recon.py --targets targets.txt --ports 80,443 --http --tls --timeout 4
```

# File Structure:
Originally I had two python files, and was planning to move my final product to the recon.py file from testing.py, however I simply renamed testing.py to recon.py to have it more clear, and now all commits are visible on recon.py, as that is the same file as testing.py but now renamed.

This is a list of the targets used in testing:
```
example.com
scanme.nmap.org
```
These are outlined in targets.txt and I have permission to scan these websites. <br>
PLease see AUTHORISATION.txt in this repositroy. <br>
Here is an example input for the cli that I use when testing:
```bash
$ python3 recon.py --targets targets.txt --ports 80,443 --http --tls --timeout 4
```
Note how I only used two ports here, as I know these are open. You can still do a range, but for testing I find it easier to do a small amount so I can 
easily check each function.

# Testing functions.
As a simple starting note, sometimes I recieve a null return from a port. An example would be with the server headers from example.com. Example.com simply hides its server header, and I am able to confirm this myself in my terminal using the following command:

``` bash
curl -I http://scanme.nmap.org
```
The output can be seen below, note the lack of a server header:
```
HTTP/2 200 
content-type: text/html
etag: "bc2473a18e003bdb249eba5ce893033f:1760028122.592274"
last-modified: Thu, 09 Oct 2025 16:42:02 GMT
cache-control: max-age=86000
date: Tue, 09 Dec 2025 19:42:01 GMT
alt-svc: h3=":443"; ma=93600
```
I can do the same for sitemap.xml for example, and also verify that it does not have one for example.com
```bash
curl -I https://example.com/sitemap.xml
```
Output:
```
HTTP/2 404 
```
I am aware of null returns for some ports, and I have done my best to investigate as to why I am getting these null returns. It appears that the two websites I am scanning simply hide some information. I just wanted to highlight that here, as I found it interesting. Although I will admit, it was a headache not being able to check everything at once, and caused some confusion for me.

# Overview of functions/features:
Here I will provide an overview of each function in its own heading: <br>

### load_targets()
The purpose of this function is to load and parse the list of targets from targets.txt. Each line in this file represents a host to be scanned. It ignores blank spaces and comments. Each valid target is returned as a string in a list called targets [ ] <br>
It uses the following parameters:
- path - Path to the targets file (targets.txt)

```python
def load_targets(path):
    #Looks at targets.txt file, basically read each line as each line will be a target website, then return that lines text as a target to feed into the functions
    targets = []    #initialise empty list
    with open(path, "r") as h: 
        for line in h:
            line = line.strip() #remove spaces before/after word
            if not line or line.startswith("#"):    #check for comment or empty line
                continue    #skip current line if empty/comment
            targets.append(line)   #add new found target to our list
    return targets  #return full list
```
Note: For the part of this function which checks for whitespace/spacebar, I followed the strip idea from parse_port_spec. This was actually one of the last functions made, as I orginally read the target from the CLI. Using AI, I asked how to ignore comments, as I was afraid that any comment made in the file would break it, and I couldnt figure it out for certain. I thought this would be a good way of implementing some error prevention.

AI provided lines:
```python
line = line.strip()
            if not line or line.startswith("#"):
                continue 
```

### probe_tcp()
This function is used to perform a TCP connect scan against the host and port to determine whether the port is open or closed.

It uses pythons socket library to do this. If the connection succeeds, then the port is open. We use standard TCP connections. 

Parameters:
- host - Target hostname or IP address
- port - TCP port number to probe
- timeout - Connection timeout in seconds (default: 2.0)
```python
def probe_tcp(host, port, timeout=2.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)   #Same as banner, AF_INET for ipv4 and SOCK_STREAM for tcp
    s.settimeout(timeout)   #set timeout
    try:
        s.connect((host, port)) #establish tcp connection with host and port
        s.close()   #close after successful connection
        return (port, True, None)   #return whether port is open and no error (tuple)
    except socket.timeout:
        return (port, False, "timeout") #return closed port, timeout
    except ConnectionRefusedError:
        return (port, False, "refused") #if connection is refused, also closed
    except Exception as e:
        return (port, False, str(e))
```

### parse_port_spec

This function is used to parse a user provided string of ports and organise into individual ports. Essentially takes the string of ports, for example a range, and then converts it to a list of individual ports as intergers. It then returns a sorted list of port numbers.


Parameters:
- spec - A string describing ports and/or ranges (e.g. "22,80,443,8000-8100")

```python
def parse_port_spec(spec):
    ports = set()   #initialise set
    for part in spec.split(","):    #split string where commas
        part = part.strip() #strip whitespace
        if "-" in part:         #check if - means port range
            a,b = part.split("-",1)     #splits range starting at a and ending at b
            ports.update(range(int(a), int(b)+1))   #adds all ports in range to set
        else:           #if single ports
            ports.add(int(part))    #convert to int and add to set
    return sorted(ports)    #return sorted ports
```
Note: This was derived from Lab 4-2 Phase 2.

### scan_host()
The purpose of this function is to scan multiple ports on a single host and collect the results. It coordinates TCP scanning by using a thread pool to probe multiple ports at once. It does one probe per port and waits for all scans to be complete. It then returns a sorted list of scan results that we can look at elsewhere.
```python
def scan_host(host, ports, workers, timeout):
    results = []    #initialise
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as exe: #Creat thread pool executer with maximum number of worker threads
        futures = {exe.submit(probe_tcp, host, p, timeout): p for p in ports}   #Submits one probe_tcp() task per port to the thread pool and stores the resulting Future objects in a dictionary.
        for fut in concurrent.futures.as_completed(futures):    #Iterates over futures as they complete, regardless of submission order.
            results.append(fut.result())    #take each scan result and put in list
    return sorted(results, key=lambda x: x[0])  #return sorted list

```

Note: This was derived from Lab 4-2 Phase 2. I had to use AI to explain some of this to me at first, specifically these three lines:
```python
with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as exe: #Creat thread pool executer with maximum number of worker threads
        futures = {exe.submit(probe_tcp, host, p, timeout): p for p in ports}   #Submits one probe_tcp() task per port to the thread pool and stores the resulting Future objects in a dictionary.
        for fut in concurrent.futures.as_completed(futures):    #Iterates over futures as they complete, regardless of submission order.
```

### grab_banner_tcp()
This function is used to get a service banner from an open port using TCP. <br>
To get a banner, I will use the code from lab4.2 as a starting point. This function will check if a port is open, and if it can get a banner, it will save it to the output files.
It uses the following parameters:
- host - Target hostname or IP address
- port - TCP port number to connect to
- timeout - Connection timeout in seconds (default: 2.0)
- send_bytes - Optional bytes to send after connecting (e.g. protocol probes)
- read_size - Maximum number of bytes to read from the socket (default: 1024)

We first initialise our banner to an empty string. We create a TCP socket with AF_INET and SOCK_STREAM, being IPv4 and TCP respectively. We also set a timeout to prevent hanging, along with specifying the target host and port. If a banner is found, it will be trimmed to a read size of 1024. If successful, the function returns the banner. If no banner is found then the function will return "null".
```python
def grab_banner_tcp(host, port, timeout=2.0, send_bytes=None, read_size=1024):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    banner = ""             #Initialise to empty, add to it from try below:
    try:
        s.connect((host, port)) #attempt tcp connection
        if send_bytes:  #check for optional send bytes
            s.sendall(send_bytes)
        try:
            data = s.recv(read_size)
            banner += data.decode(errors='replace') #decode recived bytes, and replace invalid chars
        except socket.timeout:  #if service doesnt send data before timeout
            pass
        s.close()   #close socket
        return True, banner.strip()[:1000]  #strip banner to 1000 chars
    except Exception as e:
        return False, str(e)
```
Note: This was derived from Lab 4-2 Phase 4

### fetch_tls_info()
This function will preform a TLS handshake and extrat certificate metadata. It establishes this conenction with a given host and port, and retreves the servers TLS certificate. We extract the Common Name, Issuer CN, SubjectAlternate Name (SAN), validity dates and whether the cert has expired.

Parameters:
- host - Target hostname or IP address
- port - TCP port expected to speak TLS
- timeout - Timeout for the TCP/TLS connection attempt
```python
def fetch_tls_info(host, port, timeout):
    """
    Perform a TLS handshake on a given host:port and extract certificate info.
    Returns a dictionary with certificate metadata or an error. No error, then error = null
    """
    #Initialise results to empty
    tls_result = {
        "subject_cn": None,
        "issuer_cn": None,
        "notBefore": None,
        "notAfter": None,
        "expired": None,
        "days_left": None,
        "san": [],
        "error": None
    }

    try:
        # --- Raw TCP connection
        conn = socket.create_connection((host, port), timeout)  #Create raw TCP connection to host and port

        # --- SSL context (no certificate verification)
        ctx = ssl.create_default_context()  #create a default SSL/TLS context, call it ctx
        ctx.check_hostname = False  #disables hostname verification to allow connections to any certificate
        ctx.verify_mode = ssl.CERT_NONE     #disable cert validation

        # was not getting any output, maybe because of cloudflare, is what google said, this should return some output instead of null, but i might just remove as still not getting outputs
        if hasattr(ssl, "OP_LEGACY_SERVER_CONNECT"):
            ctx.options |= ssl.OP_LEGACY_SERVER_CONNECT #legacy tls for non standard servers

        # --- TLS handshake
        ssl_sock = ctx.wrap_socket(conn, server_hostname=host)  #Wraps the TCP socket with TLS and initiates the TLS handshake.

        # --- Extract peer certificate
        cert = ssl_sock.getpeercert()   #just take cert and store as so
        ssl_sock.close()    #close tls socket after we get cert

        # If Python/OpenSSL returns empty dict, have an error message so i dont have my code start breaking/scaring me
        if not cert:    #if cert dictionary is empty, return an error
            tls_result["error"] = "Empty certificate returned"
            return tls_result

        # --- Subject Cert
        subject = cert.get("subject", [])   #get cert subject field
        for item in subject:    #find and sotre the subject Common Name /CN
            for key, value in item:
                if key.lower() == "commonname":
                    tls_result["subject_cn"] = value

        # --- Issuer Cert
        issuer = cert.get("issuer", []) #get cert issuer field
        for item in issuer:
            for key, value in item:
                if key.lower() == "commonname":
                    tls_result["issuer_cn"] = value #store issuer common name

        # --- SAN entries/Subject Alternative Name
        san_list = cert.get("subjectAltName", [])   #get SAN subject alternative name entires
        for typ, value in san_list:
            if typ.lower() == "dns":        #store all dns type san entries
                tls_result["san"].append(value)

        # --- Dates
        tls_result["notBefore"] = cert.get("notBefore") 
        tls_result["notAfter"] = cert.get("notAfter")   #Stores cert validity start and end dates

        # ---Expiration, notAfter was specified in brief, look for a date here with datetime
        if tls_result["notAfter"]:      #check if expirey present
            expiry = datetime.strptime(tls_result["notAfter"], "%b %d %H:%M:%S %Y %Z")  #parse with datetime
            now = datetime.utcnow() #get current time
            tls_result["expired"] = expiry < now            #Check if cert expired
            tls_result["days_left"] = (expiry - now).days   #check for days remaining in cert

    except Exception as e:
        tls_result["error"] = str(e)

    return tls_result
```
Note: This did require the assistance of AI as I struggled here. The main issues I had were extracting the peer cert, doing the TLS handshake, SSL and finally SAN entries. I have structured each section of this function in a way that you can see where each part is done, and also so its easier to show which parts were AI assisted. The dates and expiration were easy to do, along with the TCP connection. Error handling at the end taken from lab material, used throughout my file. So AI used on: TLS handshake, San entries, SSL, issuer certs,subject cert, peer cert and finaly the code used to check for legacy TLS servers, as I wasnt getting any information. This seemed to help.

### fetch_http_info()
This function performs a HTTP request to extract HTML and HTTP information. We do this by sending a HTTP GET request to a specified port and host, and extract information such as status code, cookies, headers and any error we may have if it fails. I wasnt sure if I could use beautiful soup or not, but as it wasnt specified I decided not to for safety. Instead I use regex where I can. In this function, we will build a url, consisting of a scheme (http or https, dending on port), a host address and finally a port. This is a structure I will be following again in this program, when we start performing checks for specific files, like robots.txt. <br>
Parameters:

- host - Target hostname or IP address
- port - TCP port number hosting the web service
- timeout - Timeout for the HTTP request in seconds
```python
def fetch_http_info(host, port, timeout):
    # Choose scheme based on port. port 443 is https, so if not on port 443, assume http. 
    scheme = "https" if port == 443 else "http"
    url = f"{scheme}://{host}:{port}/"
    #initialise http_result
    http_result = {
        "url": url,
        "final_url": None,
        "status_code": None,
        "title": None,
        "meta_description": None,
        "server_header": None,
        "cookies": [],
        "headers": {},
        "error": None
    }
    try:
        # Send request (verify=False to avoid TLS errors)
        r = requests.get(url, timeout=timeout, verify=False)
        html = r.text               #store response as text
        #for waf detection to work
        http_result["headers"] = dict(r.headers)   #store all http response headers

        http_result["final_url"] = r.url    #final url after redirects
        http_result["status_code"] = r.status_code  #http status code, example 200, 404 etc

        # Server header, if present extract it
        http_result["server_header"] = r.headers.get("Server")

        # Cookies returned by server
        #Cookie Name(session id) Cookie Value(ex: abc123), looping over structured cookie objects, f string to convert into simple string like: "sessionid=abc123"
        http_result["cookies"] = [f"{c.name}={c.value}" for c in r.cookies]

        # title with regex
        title_match = re.search(r"<title>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)   #regex for html title tags, extract content of title
        if title_match:
            http_result["title"] = title_match.group(1).strip() #if found, store it

        # meta description, again regex
        meta_match = re.search(
            r'<meta[^>]+name=["\']description["\'][^>]*content=["\'](.*?)["\']',
            html,
            re.IGNORECASE | re.DOTALL
        )
        if meta_match:
            http_result["meta_description"] = meta_match.group(1).strip()   #if meta description found, store it
    #Exception handling, basic and reused throughout my code. 
    except Exception as e:
        http_result["error"] = str(e)

    return http_result  #now we have populated http dictionary

```

Note: For cookies, I had to use AI assistance. My understanding is as follows:<br>
For cookies, they stored as structured cookie objects, inside a "cookiejar", which in this case comes from r.cookies, our request. <br>
If we had a HTTP header of: 
```
Set-Cookie: sessionid=abc123; HttpOnly; Secure
```
This cookie becomes an object inside r.cookies. So we loop over each cooke object as 'c', which as attributes such as c.name and c.value.
We turn these into a f-string, like the following example:
```
c.name  = "sessionid"
c.value = "abc123"
```
Theoritically, I should have a cookie name and value in my json file, however I only seem to get an empty set.

### fetch_robots_txt()
The function fetch_robots_txt() sends an HTTP request to the /robots.txt path on a target web service. The robots.txt file is a publicly accessible resource used to indicate which parts of a site should or should not be crawled. This is an interesting one to me, as these days many AI tools just disrespect this. I first encountered this in a PLC i did, and thus I followed the same theory with the code. The function records whether the file exists, the HTTP status code returned, and a short snippet of its contents. I built a url in the same fashion as before, but here I added a file to search for: /robots.txt. If we get a status code of 200, then the file exists.<br>
Parameters:
- host - Target hostname or IP address
- port - TCP port hosting the web service
- timeout - Timeout for the HTTP request in seconds
```python
def fetch_robots_txt(host, port, timeout):
    #Scheme is just https:// or http://, assuing http:// unless port 443 as 443 == https
    scheme = "https" if port == 443 else "http"
    url = f"{scheme}://{host}:{port}/robots.txt"    #build a path to search using scheme hostname and port, then /file name. Will reuse this in other file searches
    result = {
        "url": url,
        "exists": None,
        "status_code": None,
        "snippet": None,
        "error": None
    }
    try:
        r = requests.get(url, timeout=timeout, verify=False) #http get request to retrieve robots.txt, tls disbaled
        result["status_code"] = r.status_code   #store http status code from server

        if r.status_code == 200:
            result["exists"] = True
            text = r.text.strip()   #remove whitespace
            result["snippet"] = text[:200]  # Keep first 200 characters only
        else:
            result["exists"] = False
    #just basic exeption handling, not sure if it will break without but i wanted to be safe.
    except Exception as e:
        result["error"] = str(e)
        result["exists"] = False
    return result
```
Note: This was done myself. I had covered robots.txt in a PLC, and I just followed that theory, and used similar for next functions.

### fetch_sitemap_xml()
This function attempts to retrieve the /sitemap.xml file from a target web service over HTTP or HTTPS.A sitemap file is commonly used by websites to describe the structure of their pages for search engines. <br>
Again, I will follow the same idea as the robots.txt function. Here I also built a url, and added a file to it, being /sitemap.xml. If we get a status code of 200, then it exists, and we extract it. If not, return null and status code. <br>
Parameters:
- host — Target hostname or IP address
- port — TCP port hosting the web service
- timeout — Request timeout in seconds
```python
def fetch_sitemap_xml(host, port, timeout):
    scheme = "https" if port == 443 else "http" #if scanning port 443, use https, else not
    url = f"{scheme}://{host}:{port}/sitemap.xml" #build a path to search using scheme hostname and port, then /file name.
    result = {
        "url": url,
        "exists": None,
        "status_code": None,
        "snippet": None,
        "error": None
    }
    try:
        r = requests.get(url, timeout=timeout, verify=False)
        result["status_code"] = r.status_code

        if r.status_code == 200:
            result["exists"] = True
            text = r.text.strip()
            result["snippet"] = text[:200]  # first 200 chars only
        else:
            result["exists"] = False
    #Again, quick exception handling, same as before. Just to be safe.
    except Exception as e:
        result["error"] = str(e)
        result["exists"] = False
    return result
```

### fetch_wordpress_markers()
The function fetch_wordpress_markers() probes a target web service for two files that are strongly associated with WordPress installations:

- /wp-login.php – the WordPress authentication page

- /xmlrpc.php – an API endpoint commonly enabled in WordPress

The presence of either endpoint is often a strong indicator that the site is using WordPress as its CMS.
Again, very similar to the previous two functions, however this time I search for two files. I had to look up on Google exactly what to search for, and using the two that I read about online, I search for them.
```python
def fetch_wordpress_markers(host, port, timeout):
    scheme = "https" if port == 443 else "http" #if scanning port 443, use https, else not
    base = f"{scheme}://{host}:{port}"          #this is the base url we will build with host and then the port
    paths = ["/wp-login.php", "/xmlrpc.php"]     #just defining the wordpress related files i will look for
    results = {}        #Again, i just initialise it to empty
    for path in paths:      #loop through paths to test each one, build my entry
        url = base + path
        entry = {
            "url": url,
            "exists": None,
            "status_code": None,
            "error": None
        }
        #send http request, verify=false to avoid ssl cert errors, then store status. 200 means it exists. Store and return result
        try:
            r = requests.get(url, timeout=timeout, verify=False)
            entry["status_code"] = r.status_code
            entry["exists"] = (r.status_code == 200)    #if code = 200, then it exists. 404 not found, 403 exist but denied, so on. But i want 200
        #Ye ol reliable, yet again, if error then file isnt found, simple
        except Exception as e:
            entry["error"] = str(e)
            entry["exists"] = False
        results[path] = entry
    return results
```

### fetch_favicon_sha256()
This function will identify and fingerprint a web application by downloading its favicon and running a sha256 hash. Here we attempt to retrieve the /favicon.ico file from a target web service and, if successful, calculates a SHA-256 cryptographic hash of its raw binary contents. <br>
Parameters:
- host - Target hostname or IP address
- port - TCP port hosting the web service
- timeout - Request timeout in seconds
```python
def fetch_favicon_sha256(host, port, timeout):
    scheme = "https" if port == 443 else "http"     #https unless specified else
    url = f"{scheme}://{host}:{port}/favicon.ico"   #take http or https, concatinate the site address and port number, then look for file to read from.
    result = {
        "url": url,
        "exists": None,
        "status_code": None,
        "sha256": None,
        "error": None
    }
    try:
        r = requests.get(url, timeout=timeout, verify=False)
        result["status_code"] = r.status_code
        if r.status_code == 200:
            result["exists"] = True
            # Compute SHA256 from raw bytes, this needed AI assistance.
            sha = hashlib.sha256(r.content).hexdigest()
            result["sha256"] = sha
        else:
            result["exists"] = False
    #Again, quick exception handling, same as before. Just to be safe.
    except Exception as e:
        result["error"] = str(e)
        result["exists"] = False
    return result
```
Note: I needed AI assistance for the SHA256 has itself, for the rest of the function I just followed the same structure as what I have done already in previous functions to get the file.

### detect_waf_from_headers()
detect_waf_from_headers() inspects HTTP headers returned by a web server and attempts to guess whether the site is protected by a known Web Application Firewall. I only focuse on those listed in the brief. <br>
To do this, I take a dictionary of HTTP response headers, set all to lowercase to allow for matching, search for known header patterns associated with the three WAF providers, and finally collect any detected WAF identifiers into the list.<br>
Parameters:
- headers - A dictionary of HTTP response headers obtained from an HTTP request.
```python
def detect_waf_from_headers(headers):
    waf_tags = []   #currently empty, just want to initialise first
    h = {k.lower(): v.lower() for k, v in headers.items()}  # lowercase for easier matching
    # --- Cloudflare
    # Google says that Cloudflare usually sets: "server: cloudflare" so ill just look for that
    if "server" in h and "cloudflare" in h["server"]:
        waf_tags.append("cloudflare")
    # --- Sucuri
    # Again, google says that Sucuri often includes: "x-sucuri-id: ..." so ill look for that
    if "x-sucuri-id" in h:
        waf_tags.append("sucuri")
    # --- ModSecurity  Never actually heard of this one until this project
    # Again, buddy google says its usually found in "x-mod-security" or "x-mod-security-message", again just gonna look for that
    if "x-mod-security" in h or "x-mod-security-message" in h:
        waf_tags.append("modsecurity")
    #im sure there are more ways to check, but this is simpler for me to look for one thing at once.
    return waf_tags #now hopefully populated!
```
### detect_service_hint()
This function is primarily to help take information for my csv output. Basically, it attempts to guess the type of network service exposed on an open port. It combines port numbers, banner content, and TLS metadata to generate a simple service label.
```python
def detect_service_hint(port, banner, tls_info):
    #---- HTTP/HTTPS depending on port number
    if port == 80:
        return "http"
    if port == 443:
        return "https"
    #--- SSH detection
    if banner and "ssh" in banner.lower():
        return "ssh"
    #--- SMTP
    if banner and "smtp" in banner.lower():
        return "smtp"
    #---- FTP
    if banner and "ftp" in banner.lower():
        return "ftp"
    #--- TLS-only service, if cert is present
    if tls_info and tls_info.get("subject_cn"):
        return "tls"
    return "unknown"
```
### write_csv()
A simple function to write my output to a csv file. I use a prefix here which is simple the same name as the json file. If json file name changes, then csv file name changes. This keeps things easier to sort through. Default prefix is: scan_results
```python
def write_csv(flat_results, prefix):
    """
    Write flattened results into a CSV file.
    CSV filename = prefix + ".results.csv"
    """

    filename = prefix + ".results.csv"

    fieldnames = [
        "host",
        "port",
        "proto",
        "service_hint",
        "http_status",
        "title",
        "server_header",
        "cert_subject_cn",
        "cert_notAfter",
        "banner_snippet",
        "fingerprint_tags"
    ]

    with open(filename, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()

        for row in flat_results:
            writer.writerow(row)

    print(f"Wrote CSV to {filename}")
```

### Main Method.
The main method is where I specified all arguments, assigned my --help outputs, and wroye my CLI output. This is where we also assemble the json file. I used each of the previous functions to gather information, that we will invoke or call upon down here, and finally build our output.

## Reflection
This project was difficult, Ill admit. However, once I was able to implement the code from the labs to get a start, I was able to find my feet. I will admit, the TLS function gave me great difficultly. However, for smaller functions like robots.txt and sitemap.xml, I was confident because past experience came in handy here, and I felt I could undertsand what I was doing. While this project was definitly the most difficult one I have done to date, it is also the one I most enjoyed. <br>
In terms of what I could have done better, I believe the CSV file. To me, this was an afterthought compared to the JSON file, and I wish I had provided more time into making it better. I feel as if I didnt have a plan for the CSV file compared to the JSON file.<br>
In regards to the JSON file, I wish I would have simplified it more. Instead of showing redundant "information = null" type lines for closed ports, I should have simply stated the port as closed and moved on.<br>
I do genuinely believe I have gotten better at python, compared to last year. I only ever had a brief intoruction in my machine learning module of a PLC I did, where we did some brief scripting, which is how I recognised the robots.txt file. <br>
All in all, I will admit that compared to other projects, this isnt my best work, however I am still proud that I have a working script.
