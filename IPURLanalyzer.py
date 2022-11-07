import requests
import time
import json
import re
import json
import whois
                                  

Target = input("Enter target address: ")

API_key1 = 'YOUR KEY'
url1 = 'https://www.virustotal.com/vtapi/v2/url/report'


parameters = {'apikey': API_key1, 'resource': Target}

response= requests.get(url=url1, params=parameters)
json_response= json.loads(response.text)
    
if json_response['response_code'] <= 0:
            print("\tNOT found please Scan it manually\n")
elif json_response['response_code'] >= 1:

        if json_response['positives'] <= 0:
            print("\t NOT malicious \n")
        else:
            txt = json.dumps(json_response)
            print("VIRUS TOTAL RESULTS:")
            print("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^")
            print(txt,"\n")

API_KEY2 = 'YOUR KEY'
url2 = 'https://api.abuseipdb.com/api/v2/check'

headers = {
    'Accept': 'application/json',
    'Key': API_KEY2
}

parameters = {
        'ipAddress': Target,
        'maxAgeInDays': '90'}

respnse= requests.get( url=url2,headers=headers,params=parameters)
json_Data = json.loads(respnse.content)

print("ABUSE IPD RESULTS:")
print("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^")
print(json_Data,"\n")

print("WHO IS RESULTS:")
print("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^")
dnslookup = whois.whois(Target)
print(dnslookup,"\n")

print("\n\nURLSCAN.IO RESULTS:")
print("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^")
headers = {'API-Key':'YOUR KEY','Content-Type':'application/json'}
data = {"url": Target, "visibility": "public"}
response = requests.post('https://urlscan.io/api/v1/scan/',headers=headers, data=json.dumps(data))
print(response)
print(response.json())



                    
time.sleep(15)