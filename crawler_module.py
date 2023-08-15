import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import final
import sys

def crawl_web_app(file_content, start_url, max_depth=3):
    file_content+="\n\nXSS VULNERABILITY REPORT : "
    visited_urls = set()
    crawl_queue = [(start_url, 0)]

    while crawl_queue:
        current_url, depth = crawl_queue.pop(0)

        if depth > max_depth:
            break

        if current_url in visited_urls:
            continue

        try:
            response = requests.get(current_url)
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            continue

        visited_urls.add(current_url)

        file_content+=f"URL : {current_url} - Depth: {depth} "
        file_content+=final.testforXSS(current_url)
        
        soup = BeautifulSoup(response.text, 'html.parser')

        for link in soup.find_all('a', href=True):
            absolute_url = urljoin(current_url, link['href'])
            if is_same_domain(start_url, absolute_url) and absolute_url not in visited_urls:
                crawl_queue.append((absolute_url, depth + 1))
        file_content+="\n"+"-"*60+"\n"
    prevention = '''\n\n
Cross-Site Scripting (XSS) is a type of security vulnerability that occurs when an attacker injects malicious scripts into a web application, which then gets executed by unsuspecting users. To prevent XSS attacks, you can follow these best practices:\n\n
1. **Validate Inputs:** Check and clean all user inputs on the server side to ensure they're safe.

2. **Encode Outputs:** Before displaying data, encode it to prevent injected scripts from executing.

3. **Content Security Policy (CSP):** Set rules for allowed script sources to limit potential attack vectors.

4. **HTTP-Only Cookies:** Keep sensitive data in cookies secure from JavaScript access.

5. **Sanitize Rich Content:** Filter or use safe formats for user-generated content.

6. **Escape JavaScript Data:** Ensure user inputs are properly escaped in dynamically generated JavaScript.

7. **Stay Updated:** Keep software, frameworks, and plugins patched and current.

8. **Train Developers:** Teach secure coding practices and conduct code reviews.

9. **Use Security Headers:** Employ HTTP security headers to enhance protection.

10. **Regular Audits:** Perform security checks and tests to catch and fix vulnerabilities.

For more information visit https://portswigger.net/web-security/cross-site-scripting \n\n
REPORT GENERATED USING WEBSENTINAL PROJECT CODE : https://github.com/Madhvesh77/Web-application-fingerprinting-and-XSS-scanner'''
    file_content+=prevention
    with open("Websentinel_Report.txt", 'w')as f:
        f.write(file_content)    

def is_same_domain(url1, url2):
    return urlparse(url1).netloc == urlparse(url2).netloc

def get_web_info(url):
    try:
        file_content = f"\t\tWEBSENTINEL REPORT FOR {url}\n\nFINGERPRINTING INFORMATION : "
        response = requests.get(url)
        response_headers = response.headers
        server = response_headers.get('Server', 'N/A')
        powered_by = response_headers.get('X-Powered-By', 'N/A')
        soup = BeautifulSoup(response.text, 'html.parser')
        tech_stack = []
        for script_tag in soup.find_all('script'):
            src = script_tag.get('src', '')
            tech_stack.extend(src.split('/'))
        tech_stack = list(filter(None, tech_stack))
        web_frameworks = []
        if any("flask" in tech.lower() for tech in tech_stack):
            web_frameworks.append("Flask")
        if any("django" in tech.lower() for tech in tech_stack):
            web_frameworks.append("Django")
        file_content+="\n\nWeb Server : "+str(server) +"\nPowered By : "+str(powered_by)+"\nTechnology Stack : "+str(tech_stack)+"\nWeb Frameworks : "+str(web_frameworks)
        return file_content
    except requests.exceptions.RequestException as e:
        file_content+="\n\nError retrieving fingerprinting information !"+str(e)
        return file_content
    
if __name__ == "__main__":
    start_url = sys.argv[1]
    file_content = ''' 
* - * - @ ^ * - * - * - * - @ ^ * - # _ @ ^ @ ^ * - # _ @ ^ * # _ # @ ^ 
# _ @ ^ # _ # _ # _ @ ^ # _ # _ @ ^ # _ # _ # _ # _ @ ^ # _ # ^ @ ^ # _ 
^ # _ # _ @ ^ @ ^ # _ @ ^ # _ @ ^ @ ^ # _ @ ^ @ ^ @ ^ @ ^ @ ^ * - * @ ^ 
* - *   __        __   _    ____             _   _            _   ^ # _
# _ #	\ \      / /__| |__/ ___|  ___ _ __ | |_(_)_ __   ___| |  @ ^ *
^ @ ^ 	 \ \ /\ / / _ \ '_ \___ \ / _ \ '_ \| __| | '_ \ / _ \ |  * - #
* - *  	  \ V  V /  __/ |_) |__) |  __/ | | | |_| | | | |  __/ |  @ ^ *
# _ #  	   \_/\_/ \___|_.__/____/ \___|_| |_|\__|_|_| |_|\___|_|  # @ ^
^ @ ^                                                             # @ ^
* - * - @ ^ * - * - * - * - @ ^ * - # _ @ ^ @ ^ * - # _ @ ^ * # _ # @ ^ 
# _ @ ^ # _ # _ # _ @ ^ # _ # _ @ ^ # _ # _ # _ # _ @ ^ # _ # ^ @ ^ # _ 
^ # _ # _ @ ^ @ ^ # _ @ ^ # _ @ ^ @ ^ # _ @ ^ @ ^ @ ^ @ ^ @ ^ * - * @ ^ \n\n
          '''
    print(file_content)
    print("\n\n\nCollecting fingerprinting Information ...")
    file_content += get_web_info(start_url)
    print("\n\nTesting for XSS ...")
    crawl_web_app(file_content, start_url, max_depth=3)
    print('\n\nDone! Check the report stored with the name Websentinel_Report.txt for detailed information.\n\n')
