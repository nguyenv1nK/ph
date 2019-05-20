import requests
import re
import json


class SboxPlugin:

    def __init__(self):
        self.url = ""
        self.cookie = ""
        self.headers = ""
        self.response = ""

    def get_input(self):
        try:
            with open("../input.json", "r") as file:
                data = json.load(file)
                self.url = data['url']
                self.cookie = data["request_header"]["cookie"]
                self.headers = {"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                                "Accept-Language": "en", "Cache-Control": "no-cache",
                                'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) ', 'cookie': self.cookie}
        except Exception as e:
            print("Have error when get input")
            print(e)
            exit()

    def scan(self):
        self.get_input()
        self.check_url(self.url)

    def check_url(self, url):
        if url.split("/")[-1] == "phpinfo.php":
            r = requests.get(url)
            if r.status_code == 200:
                self.response = r.headers
                print("Phpinfo file has found !")
                allow_url_fopen = r'allow_url_fopen</td><td class="v">(.*)</td>'
                status_allow_url_fopen = self.find_info(allow_url_fopen, r.text)
                if status_allow_url_fopen != 'Off|Off':
                    print("Detect allow_url_fopen enabled: " + status_allow_url_fopen)

    def find_info(self, regex, text):
        p = re.findall(regex, text)
        if p:
            return p[0].replace("</td><td class=\"v\">", "|").replace("<i>", "").replace("</i>", "")
        else:
            return "No finding"

    def get_result(self, name):
            attack_details_vuln = {"Type": name}
            affects_vuln = self.url
            request_vuln = self.headers
            param_vuln = ""
            output_vuln = dict(self.response)
            json.dumps(output_vuln)
            data_vuln = {
                "attack_details": attack_details_vuln,
                "affects": affects_vuln,
                "requests": request_vuln,
                "param": param_vuln,
                "response": output_vuln,
                "port": 80
            }
            try:
                with open("../output.json", "w+") as output_file:
                    json.dump(data_vuln, output_file)
                output_file.close()
                print("Successful Data Export !!!")
            except Exception:
                print("Error When Open Output file !!!")


a = SboxPlugin()
a.scan()
