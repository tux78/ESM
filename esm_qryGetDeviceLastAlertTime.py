# -*- coding: utf-8 -*-

import sys, getopt
import base64
import json
import time

from datetime import datetime, timezone

try:
    import requests
    requests.packages.urllib3.disable_warnings()
except ImportError:
    requests = None

class ESM():

    def __init__(self, esm_ip, username, password):
        self._login(esm_ip, username, password)

    #################################################################################################
    # ESM API IMPLEMENTATION
    #################################################################################################

    ###########################
    # Get DataSource Last Event Time
    ###########################
    def qryGetDeviceLastAlertTime(self):
        params = {}
        response = self._callEsmApi('qryGetDeviceLastAlertTime', params)
        return response

    #################################################################################################
    # HELPER FUNCTIONS
    #################################################################################################

    ########################### 
    # Login
    ###########################
    def _login(self, esm_ip, username, password):
        if requests is None:
            raise ValueError("Could not import 'requests'. Please install it.")

        # Log in to ESM
        enc_user = base64.b64encode(username.encode('utf-8')).decode()
        enc_password = base64.b64encode (password.encode('utf-8')).decode()

        headers = {'Content-Type': 'application/json'}
        data = {
            'username' : enc_user,
            'password' : enc_password,
            'locale' : 'en_US',
            'os' : 'Win32'
        }

        loginUrl = 'https://' + esm_ip + '/rs/esm/login'
        try:
            response = requests.post(
                loginUrl,
                data = json.dumps (data),
                headers = headers,
                verify = False
            )
        except requests.exceptions.ConnectionError:
            raise ValueError('Error connecting to ESM.')

        if response.status_code in [400, 401]:
            raise ValueError('Invalid username or password.')
        elif 402 <= response.status_code <= 600:
            raise ValueError('ESM login error: ' + response.text)

        # Store Cookie/XSRF Token for subsequent use
        self.auth_header = {'Content-Type': 'application/json'}
        self.auth_header['Cookie'] = response.headers.get('Set-Cookie')
        self.auth_header['X-Xsrf-Token'] = response.headers.get('Xsrf-Token')
        self.auth_header['SID'] = response.headers.get('Location')

        # Create base URL
        self.url = 'https://' + esm_ip + '/rs/esm/v2/'

    ########################### 
    # Call ESM API
    ###########################
    def _callEsmApi(self, method, params):
        response = requests.post (
            self.url + method,
            data = json.dumps (params),
            headers = self.auth_header,
            verify = False
        )
        retVal = response
        return retVal.json()

def runQuery(esm, header=False):

    time_string = "%m/%d/%Y %H:%M:%S"
    time_range = 15
    excludedTypes = [ 
        'McAfee Enterprise Log Manager',
        'McAfee Event Receiver',
        'McAfee Advanced Correlation Engine',
        'Correlation Engine',
        'NitroGuard IPS',
        'ePolicy Orchestrator'
    ]

    # Retrieve LastAlertTime for data sources
    retVal = esm.qryGetDeviceLastAlertTime()

    # Add header to output
    if header:
        output = 'deviceName'.ljust(60)
        output += 'deviceType'.ljust(60)
        output += 'Off'.ljust(5)
        output += 'lastEvent'.ljust(20)
        print(output)

        output = '=========='.ljust(60)
        output += '=========='.ljust(60)
        output += '==='.ljust(5)
        output += '========='.ljust(20)
        print(output)

    # Filter rows according to settings
    for row in retVal:
        if row['lastEvent']:
            difference = (datetime.now() - datetime.strptime(row['lastEvent'], time_string)).days
        else:
            difference = -1
        if (
            row['deviceType'] not in excludedTypes
            and (difference >= time_range or difference < 0)
        ):
            output = row['deviceName'].ljust(60)
            output += row['deviceType'].ljust(60)
            output += str(difference).ljust(5)
            output += row['lastEvent'].ljust(20)
            print(output)

def main(argv):

    host = ''
    username = ''
    password = ''
    try:
        opts, args = getopt.getopt(argv,"h:u:p:",["host=","username=","password="])
    except getopt.GetoptError:
        print('esm.py -h <ESM IP> -u <username> -p <password>')
        sys.exit(2)
    for opt, arg in opts:
        if opt in ("-h", "--host"):
            host = arg
        elif opt in ("-u", "--username"):
            username = arg
        elif opt in ("-p", "--password"):
            password = arg
    if (host and username and password):
        # Prints filtered output to standard console
        runQuery(ESM(host, username, password), True)
        # returns full JSON Object
        retVal = ESM(host, username, password).qryGetDeviceLastAlertTime()
        print(json.dumps(retVal, indent=4))
    else:
        print('Missing parameter')

if __name__ == "__main__":
  main(sys.argv[1:])

