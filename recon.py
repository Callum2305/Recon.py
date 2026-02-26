#Callum Matthews C00306572
# lab4-2_scan.py is the basic starting point, will add from there.

#!/usr/bin/env python3
import socket, argparse, concurrent.futures, json, time, ssl, re, requests, hashlib, csv
from datetime import datetime, timezone

#Read targets.txt file, helper function to do that
def load_targets(path):
    #Looks at targets.txt file, basically read each line as each line will be a target website, then return that lines text as a target to feed into the functions
    targets = []    #initialise empty list
    with open(path, "r") as h: 
        for line in h:
            line = line.strip() #remove spaces before/after word
            if not line or line.startswith("#"):    #check for comment or empty line
                continue    #skip current line if empty/comment
            targets.append(line)    #add new found target to our list
    return targets  #return full list

#Scan range, derived from lab4-2 Phase 3. Thank god for labs because without this i would have been stuck as where to start :)
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

#Derived from lab 4-2 Phase 3 verbatim
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

#Derived from Lab4-2 Phase 3 verbatim
def scan_host(host, ports, workers, timeout):
    results = []    #initialise
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as exe: #Creat thread pool executer with maximum number of worker threads
        futures = {exe.submit(probe_tcp, host, p, timeout): p for p in ports}   #Submits one probe_tcp() task per port to the thread pool and stores the resulting Future objects in a dictionary.
        for fut in concurrent.futures.as_completed(futures):    #Iterates over futures as they complete, regardless of submission order.
            results.append(fut.result())    #take each scan result and put in list
    return sorted(results, key=lambda x: x[0])  #return sorted list

#Banner grabbing function, derived from lab4-2 Phase 4, verbatim
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
    #This will be seen throughout my code, I will reuse this for exception handling.
    except Exception as e:
        return False, str(e)

#TLS handshake
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

#-------- HTTP INFO
#Note, i did not use beautiful soup like in labs, as was unsure if it was allowed as wasnt mentioned in brief.
#This is ran with regex and the requests library to be safe
def fetch_http_info(host, port, timeout):
    """
    Here i perform an HTTP GET request and extract following:
    - final URL after redirects
    - status code
    - <title>
    - <meta name="description">
    - Server header
    - Cookies
    """
    # Choose scheme based on port. port 443 is https, so if not on port 443, assume http. I know dhcp is 67 for example, but i didnt add a case for each port, as its easier to assume http
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
#Search for the robots.txt file
def fetch_robots_txt(host, port, timeout):
    """
    This simple file called robots.txt is one thing that I have done before in my plc, same theory in code here
    Attempt to retrieve /robots.txt and return:
    - exists (True/False)
    - status_code
    - snippet of content
    """
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
#Sitemap.xml Very similar to robots.txt
def fetch_sitemap_xml(host, port, timeout):
    """
    Attempt to retrieve /sitemap.xml and return:
    - exists (True/False)
    - status_code
    - snippet of content
    """

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
#WordPress detection
def fetch_wordpress_markers(host, port, timeout):
    '''
    Check two urls on my target, like example.com and scanme.org
    /wp-login.php and /xmlrpc.php These usually are proof that a site runs Wordpress
    My function will return the url tested, whether the file exists, http status and if any errors (hopefully not)
    '''
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

#Favicon Hashing
def fetch_favicon_sha256(host, port, timeout):
    """
    Attempt to download /favicon.ico and compute SHA256 hash.
    Returns:
    - url
    - exists (True/False)
    - status_code
    - sha256 (hex string or None)
    - error
    - Of course this is assuming i can access it or that there is a /favicon.ico file. If not, return null
    """
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

#WAF: Web Application Firewall, basically cloudflare and sucuri
def detect_waf_from_headers(headers):
    """
    Will look at HTTP headers and ust return a list of those detected
    These were specified in my brief, so just gonna do these:
    Cloudflare, sucuri and modsecurity. 
    """
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

#To help grab info for my csv file, assuming we even got information that i can grab:
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

#To write to my csv file
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


# ------------------- MAIN METHOD
#Basic structure here is from Lab4-2 Phase 3

if __name__ == '__main__':
    #Help functions written here across one line per arg, mainly because i find it easier to read, and it reduces line count.
    p = argparse.ArgumentParser()
    p.add_argument("--targets", required=True, help="Path to targets.txt file")
    p.add_argument("--ports", default="1-1024", help="Specify ports to be scanned. For example: 80,443 for two ports, or 1-100 for a range.")
    p.add_argument("--workers", type=int, default=50, help="Number of concurrent TCP scan workers. Default is 50")
    p.add_argument("--timeout", type=float, default=1.5, help="Per-connection timeout in seconds (float allowed)")
    p.add_argument("--out", default="scan_results.json", help="Output file prefix; writes scan_results.json and then reuse the same name for csv")
    p.add_argument("--tls", action="store_true",  help="Attempt TLS handshake and extract certificate metadata")
    p.add_argument("--http", action="store_true", help="Probe HTTP(S) services and extract headers, title, robots.txt, sitemap, and favicon hash")
    args = p.parse_args()

    ports = parse_port_spec(args.ports)

    targets = load_targets(args.targets)
    output = {
        "meta": {
            "run_started": datetime.now(timezone.utc).isoformat(),
            "args": vars(args),
            "resumed": False
        },
        "targets": {}
    }
    for host in targets:
        print(f"\n=== Scanning {host} ===") #Just wanted something nice to print to terminal
        start = time.time()
        res = scan_host(host, ports, args.workers, args.timeout)
        elapsed = time.time() - start

        open_ports = [r for r in res if r[1]]
        print(f"Scan complete in {elapsed:.2f}s — {len(open_ports)} open ports found")

        host_result = {
            "elapsed": elapsed,
            "ports": {}
        }
        # to put my json file output together
        for port, open_, reason in res:
            port_entry = {
                "port": port,
                "open": open_,
                "reason": reason,
                "banner": None,
                "tls": None,
                "http": None,
                "fingerprint_tags": []
            }

            #----Banner Exraction
            if open_:
                ok, banner = grab_banner_tcp(host, port, timeout=args.timeout)
                if ok and banner:
                    port_entry["banner"] = banner

            # ------TLS extraction
            if open_ and args.tls:
                port_entry["tls"] = fetch_tls_info(host, port, args.timeout)


            # ----- HTTP extraction Block
            #Ports 80 and 443 as default if no ports specified by user
            #This contains various parts, like robots and sitemap, waf, just grab information based off functions above main
            if open_ and args.http and port in (80, 443):
                http_info = fetch_http_info(host, port, args.timeout)

                #----- Robots file extraction
                robots_info = fetch_robots_txt(host, port, args.timeout)
                http_info["robots_txt"] = robots_info

                #----- Sitemap.xml extraction
                sitemap_info = fetch_sitemap_xml(host, port, args.timeout)
                http_info["sitemap_xml"] = sitemap_info

                # ---- Favicon Hashing
                favicon_info = fetch_favicon_sha256(host, port, args.timeout)
                http_info["favicon_sha256"] = favicon_info["sha256"]

                # ---- WordPress Detection
                wp_info = fetch_wordpress_markers(host, port, args.timeout)
                http_info["wordpress"] = wp_info

                #----- Waf detection
                waf_tags = detect_waf_from_headers(http_info.get("headers", {}))
                for tag in waf_tags:
                    port_entry["fingerprint_tags"].append(tag)

                port_entry["http"] = http_info
            else:
                port_entry["http"] = None

            host_result["ports"][str(port)] = port_entry
        output["targets"][host] = host_result

    #  -------------- Write to my JSON file,
    with open(args.out, "w") as fh:
        json.dump(output, fh, indent=2)
    print(f"Wrote results to {args.out}")

    # ------------- CSV FLATTENING
    flat_rows = []

    for host, hdata in output["targets"].items():
        for port_str, entry in hdata["ports"].items():
            if not entry["open"]:
                continue

            http = entry.get("http") or {}
            tls = entry.get("tls") or {}
            banner = entry.get("banner")

            service_hint = detect_service_hint(int(port_str), banner, tls)

            row = {
                "host": host,
                "port": int(port_str),
                "proto": "tcp",
                "service_hint": service_hint,
                "http_status": http.get("status_code"),
                "title": http.get("title"),
                "server_header": http.get("server_header"),
                "cert_subject_cn": tls.get("subject_cn"),
                "cert_notAfter": tls.get("notAfter"),
                "banner_snippet": (banner[:50] if banner else None),
                "fingerprint_tags": ",".join(entry.get("fingerprint_tags", []))
            }

            flat_rows.append(row)

    csv_prefix = args.out.replace(".json", "")
    write_csv(flat_rows, csv_prefix)
