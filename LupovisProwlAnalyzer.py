#!/usr/bin/env python3

import subprocess
import json
from cortexutils.analyzer import Analyzer

class LupovisProwlAnalyzer(Analyzer):
    def __init__(self):
        super().__init__()
        self.prowl_api_key = 'Enter your LupovisProwl API Key'
        self.prowl_api_url = 'https://api.prowl.lupovis.io/GetIPReputation?ip='
        self.proxy = 'enter proxy server if required'

    def summary(self, raw):
        ttps = raw.get('ttps', [])
        if ttps:
            return [
                {
                    'level': 'malicious',
                    'namespace': 'LupovisProwlAnalyzer',
                    'predicate': 'Threat',
                    'value': ttps[0] if isinstance(ttps, list) and ttps else 'Unknown threat'
                }
            ]
        else:
            return [
                {
                    'level': 'safe',
                    'namespace': 'LupovisProwlAnalyzer',
                    'predicate': 'Threat',
                    'value': 'No known malicious activity'
                }
            ]

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
                # Parse the JSON output
                output_json = json.loads(output)
                # Check if "ttps" field is empty or contains "no known malicious activity"
                if not output_json.get('ttps'):
                    details = "no known malicious activity"
                else:
                    details = json.dumps(output_json)
                result = {"ip": ip, "details": details, "ttps": output_json.get('ttps', [])}
                self.report(result)
            else:
                self.error(f'curl command failed with error: {stderr.decode()}')
        except Exception as e:
            self.error(f'Error executing curl command: {e}')

if __name__ == '__main__':
    LupovisProwlAnalyzer().run()
