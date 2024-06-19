#!/usr/bin/env python

import subprocess
from cortexutils.analyzer import Analyzer

class LupovisProwlAnalyzer(Analyzer):
    def __init__(self):
        super().__init__()
        self.prowl_api_key = 'Enter Your API Key Here'  
        self.prowl_api_url = 'https://api.prowl.lupovis.io/GetIPReputation?ip='
        self.proxy = 'enter your proxy server here' (if needed)

    def summary(self, raw):
        # No need for summary in this example
        return []

    def run(self):
        ip = self.get_data()
        if not ip:
            self.error('No IP provided')
            return
        url = f'{self.prowl_api_url}{ip}'
        try:
            # Constructing the curl command
            curl_command = ['curl', '-H', f'x-api-key: {self.prowl_api_key}', url]
            # Executing the curl command and capturing output
            process = subprocess.Popen(curl_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env={'http_proxy': self.proxy, 'https_proxy': self.proxy})
            stdout, stderr = process.communicate()
            if process.returncode == 0:
                output = stdout.decode()
                result = {"ip": ip, "details": output}
                self.report(result)
            else:
                self.error(f'curl command failed with error: {stderr.decode()}')
        except Exception as e:
            self.error(f'Error executing curl command: {e}')

if __name__ == '__main__':
    LupovisProwlAnalyzer().run()
