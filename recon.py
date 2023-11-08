#!/usr/bin/python3

import argparse
import os
import subprocess
import requests
import re
import logging

class Recon:
    def __init__(self, FilePath):
        self.logger = self.log()
        self.FilePath = FilePath
        self.ScopeLinks = self.ReadFile(FilePath)


    def ReadFile(self, Path):
        if self.checkIfFileExist(Path):
            try:
                with open(Path, 'r') as file:
                    Lines = [line.strip() for line in file.readlines() if line.strip()]
                    return Lines
            except:
                self.logger.error("Error in reading file {}".format(Path))
        else:
            self.logger.error("File does not exist")


    def checkIfFileExist(self, Path):
        return os.path.isfile(Path)

    def checkIfDir(self, dirPath):
        return os.path.isdir(dirPath)

    def ExcuteCommand(self, command):
        return subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    def checkCommandResult(self, result):
        if result.returncode == 0:
            return True
        else:
            return False

    def writeToFile(self, FileName, Data):
        with open(FileName, "w") as file:
            for i in Data:
                file.write(i+'\n')
            file.close()

    def sendRequest(self, url):
        return requests.get(url)
   
    def FindFireWall(self):
            if self.checkIfFileExist(self.FilePath):
                command = "wafw00f -i {} -o wafwoof.txt".format(self.FilePath)
                result = self.ExcuteCommand(command)
                if self.checkCommandResult(result):
                    self.logger.info("Done finding firewall for all socpe result in waffwoff.txt")
                    return True
                else:
                    self.logger.error("Error in finding firewall")
                    return False

    def FindFireWallForSingleUrl(self, Url):
        command = "wafw00f {}".format(Url)
        result = self.ExcuteCommand(command)
        if self.checkCommandResult(result):
            if "No WAF" in result.stdout:
                return False
            elif "is behind" in result.stdout:
                return True
        else:
            self.logger.error("Error in finding firewall")

    def CreateScopeFoldars(self):
        for i in self.ScopeLinks:
            command  = "mkdir Scope/{}".format(i)
            result = self.ExcuteCommand(command)
        else:
            self.logger.info("Done making foldars of the scope")

    def FindScopeHost(self):
        for i in self.ScopeLinks:
            command = "host {} >> host.txt".format(i)
            result = self.ExcuteCommand(command)
        else:
            self.logger.info("Done find host ips")

    def CollectIpsFromHost(self):
        if self.checkIfFileExist("host.txt"):
            command = "grep -E -o '([0-9]{1,3}\.){3}[0-9]{1,3}' host.txt > hostIps.txt"
            self.ExcuteCommand(command)
        else:
            self.logger.error("host file not found")

    def chekcTool(self, tool):
        command = f"which {tool}"
        result = self.ExcuteCommand(command)
        if self.checkCommandResult(result):
            return True
        else:
            self.logger.error(f"This {tool} is not installed")
            return False



    def log(self):
        # .debug .info .warning .error .critical
        # Create a logger for your script
        logger = logging.getLogger('recon')
        logger.setLevel(logging.DEBUG)  # Set the log level to DEBUG

        # Create a file handler for writing log messages to a file
        file_handler = logging.FileHandler('recon.log')
        file_handler.setLevel(logging.DEBUG)  # Set the desired log level
        file_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
        logger.addHandler(file_handler)  

        # Create a stream handler for displaying log messages on the console
        stream_handler = logging.StreamHandler()
        stream_handler.setLevel(logging.DEBUG)  # Set the desired log level
        stream_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
        logger.addHandler(stream_handler)
        return logger


    def runSublist3r(self):
        if self.chekcTool("sublist3r"):
            for i in self.ScopeLinks:
                if self.checkIfDir(i):
                    command = f"sublist3r -d {i} -o {i}/{i}.sublist3r.txt"
                    result = self.ExcuteCommand(command)
                else:
                    self.logger.error(f"can't find {i} Directory")
            else:
                self.logger.info("Done sublist3r")
                return True
        else:
            return False


    def runSubfinder(self):
        if self.chekcTool("subfinder"):
            for i in self.ScopeLinks:
                if self.checkIfDir(i):
                    command = f"subfinder -d {i} -o {i}/{i}.subfinder.txt"
                    result = self.ExcuteCommand(command)
                else:
                    self.logger.error(f"can't find {i} Directory")
            else:
                self.logger.info("Done subfinder")
                return True
        else:
            return False
    
    def runAmass(self):
        if self.chekcTool("amass"):
            for i in self.ScopeLinks:
                if self.checkIfDir(i):
                    command = f"enum --passive -d {i} -o {i}/{i}.passiveAmass.txt"
                    result = self.ExcuteCommand(command)
                    command = f"enum --active -d {i} -o {i}/{i}.ActiveAmass.txt"
                    result = self.ExcuteCommand(command)
                else:
                    self.logger.error(f"can't find {i} Directory")
            else:
                self.logger.info("Done amass")
                return True
        else:
            return False

    def runAssetfinder(self):
        if self.chekcTool("assetfinder"):
            for i in self.ScopeLinks:
                if self.checkIfDir(i):
                    command = f"assetfinder {i} > {i}/{i}.assetfinder.txt"
                    result = self.ExcuteCommand(command)
                else:
                    self.logger.error(f"can't find {i} Directory")
            else:
                self.logger.info("Done assetfinder")
                return True
        else:
            return False

    def runCrtsh(self):
        for i in self.ScopeLinks:
            if self.checkIfDir(i):
                crtUrlSite = f'https://crt.sh/?q=%.{i}&output=json'
                response = self.sendRequest(crtUrlSite)
                if response.status_code == 200:
                    data = response.text
                    subdomains = set(re.findall(r'\b(?:[a-zA-Z0-9.-]+\.)*' + re.escape(i) + r'\b', data))
                    FileName = f"{i}/{i}.crtSh.txt"
                    self.writeToFile(FileName, subdomains)
                else:
                    self.logger.error(f'Error in geting crt.sh: {response.status_code}')
            else:
                    self.logger.error(f"can't find {i} Directory")


    def runWaybacruls(self):
        if self.chekcTool("waybackurls"):
            for i in self.ScopeLinks:
                if self.checkIfDir(i):
                    command = f"waybackurls {i} > {i}/{i}.waybackurls.txt"
                    result = self.ExcuteCommand(command)
                else:
                    self.logger.error(f"can't find {i} Directory")
            else:
                self.logger.info("Done waybackurls")
                return True
        else:
            return False


    def runMasscanOnScope(self):
        # Don't forget to check if it's a firewall or a site ip
        pass

    def runNmapOnScope(self):
        pass

    def run_whois(self, ip):
            try:
                result = subprocess.run(['whois', ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
                return result.stdout
            except subprocess.CalledProcessError as e:
                return e.stderr

    def is_firewall_ip(self, ip_info):
        # Define keywords to identify firewall or proxy IPs in whois information.
        firewall_keywords = ["waf","amazon","firewall", "proxy", "cdn", "cloudflare","aws" ,"generic","edgecast","akamai","modsecurity","imperva incapsula","f5 webSafe","akamai web application protecto"]
        pattern = "|".join(map(re.escape, firewall_keywords))
        matches = re.search(pattern, ip_info,re.IGNORECASE)
        if matches:
            return True
        else:
            return False

    def isFireWallIp(self, ip):
        ipInfo = self.run_whois(ip)
        isFirewall = self.is_firewall_ip(ipInfo)
        return isFirewall



if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Recon script to automate boring recon stuff',add_help=False)
    parser.add_argument('-f', '--FilePath', help='path to the scope.txt file')
    parser.add_argument('--help', '-h', action='help', help='-f scop file path')
    args = parser.parse_args()

    # Access the values of the arguments
    FilePath = args.FilePath
    if FilePath:
        print("hello this is recon")
        r1 = Recon(FilePath)
        r1.logger.info("this is an info")
        #ips = r1.ReadFile("/home/mr124/Documents/SitesToHunt/PorscheH1C/hostIp.txt")
        for i in r1.ScopeLinks:
            if r1.FindFireWallForSingleUrl(i):
                print(f"{i} is an FireWall IP")
            else:
                print(f"{i} is a website IP")
    else:
        print("run recon.py -h --help")