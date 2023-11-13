#!/usr/bin/python3

import argparse
import re
from BaseClass import *

logger = logSetup.log("recon","ReconLog.txt")

class Recon:
    def __init__(self, FilePath):
        self.logger = logger
        self.FilePath = FilePath
        self.ScopeLinks = BaseClass.ReadFile(FilePath)

   
    def FindFireWall(self):
            if BaseClass.checkIfFileExist(self.FilePath):
                command = "wafw00f -i {} -o wafwoof.txt".format(self.FilePath)
                result = BaseClass.ExcuteCommand(command)
                if BaseClass.checkCommandResult(result):
                    self.logger.info("Done finding firewall for all socpe result in waffwoff.txt")
                    return True
                else:
                    self.logger.error("Error in finding firewall")
                    return False

    def FindFireWallForSingleUrl(self, Url):
        command = "wafw00f {}".format(Url)
        result = BaseClass.ExcuteCommand(command)
        if BaseClass.checkCommandResult(result):
            if "No WAF" in result.stdout:
                return False
            elif "is behind" in result.stdout:
                return True
        else:
            self.logger.error("Error in finding firewall")

    def CreateScopeFoldars(self):
        for i in self.ScopeLinks:
            command  = "mkdir -p Scope/{}".format(i)
            result = BaseClass.ExcuteCommand(command)
            if BaseClass.checkCommandResult(result):
                self.logger.info("Done making Scope Foldar")
            else:
                self.logger.error("Can't make scope foldar")
        else:
            self.logger.info("Done Creating Foldar Function")

    def FindScopeHost(self):
        if BaseClass.checkIfFileExist("host.txt"):
            self.logger.info("found host.txt file")
            return True
        else:
            for i in self.ScopeLinks:
                command = "host {} >> host.txt".format(i)
                result = BaseClass.ExcuteCommand(command)
            else:
                self.logger.info("Done find host ips")
                return True

    def CollectIpsFromHost(self):
        if BaseClass.checkIfFileExist("host.txt"):
            command = "grep -E -o '([0-9]{1,3}\.){3}[0-9]{1,3}' host.txt > hostIps.txt"
            BaseClass.ExcuteCommand(command)
            return True
        else:
            self.logger.error("host file not found")
            return False

    def runSublist3r(self):
        if BaseClass.chekcTool("sublist3r"):
            for i in self.ScopeLinks:
                FileExist = BaseClass.checkIfFileExist(f"Scope/{i}/{i}.sublist3r.txt")
                if BaseClass.checkIfDir(f"Scope/{i}") and not FileExist:
                    command = f"sublist3r -d {i} -o Scope/{i}/{i}.sublist3r.txt"
                    result = BaseClass.ExcuteCommand(command)
                else:
                    self.logger.info(f"file already exist or the scope foldar for {i} not exist")
            else:
                self.logger.info("Done sublist3r")
                return True
        else:
            return False


    def runSubfinder(self):
        if BaseClass.chekcTool("subfinder"):
            for i in self.ScopeLinks:
                FileExist = BaseClass.checkIfFileExist(f"Scope/{i}/{i}.subfinder.txt")
                if BaseClass.checkIfDir(f"Scope/{i}") and not FileExist:
                    command = f"subfinder -d {i} -o Scope/{i}/{i}.subfinder.txt"
                    result = BaseClass.ExcuteCommand(command)
                else:
                    self.logger.info(f"file already exist or the scope foldar for {i} not exist")
            else:
                self.logger.info("Done subfinder")
                return True
        else:
            return False
    
    def runAmass(self):
        if BaseClass.chekcTool("amass"):
            for i in self.ScopeLinks:
                FileExistPassive = BaseClass.checkIfFileExist(f"Scope/{i}/{i}.passiveAmass.txt")
                FileExistActive = BaseClass.checkIfFileExist(f"Scope/{i}/{i}.ActiveAmass.txt")
                if BaseClass.checkIfDir(f"Scope/{i}") and not FileExistPassive and not FileExistActive :
                    print("starting amass")
                    command = f"amass enum --passive -d {i} -o Scope/{i}/{i}.passiveAmass.txt"
                    result = BaseClass.ExcuteCommand(command)
                    command = f"amass enum --active -d {i} -o Scope/{i}/{i}.ActiveAmass.txt"
                    result = BaseClass.ExcuteCommand(command)
                else:
                    self.logger.info(f"file already exist or the scope foldar for {i} not exist")
            else:
                self.logger.info("Done amass")
                return True
        else:
            return False

    def runAssetfinder(self):
        if BaseClass.chekcTool("assetfinder"):
            for i in self.ScopeLinks:
                FileExist = BaseClass.checkIfFileExist(f"Scope/{i}/{i}.assetfinder.txt")
                if BaseClass.checkIfDir(f"Scope/{i}") and not FileExist:
                    command = f"assetfinder {i} > Scope/{i}/{i}.assetfinder.txt"
                    result = BaseClass.ExcuteCommand(command)
                else:
                    self.logger.info(f"file already exist or the scope foldar for {i} not exist")
            else:
                self.logger.info("Done assetfinder")
                return True
        else:
            return False

    def runCrtsh(self):
        for i in self.ScopeLinks:
            FileExist = BaseClass.checkIfFileExist(f"Scope/{i}/{i}.crtSh.txt")
            if BaseClass.checkIfDir(f"Scope/{i}") and not FileExist :
                crtUrlSite = f'https://crt.sh/?q=%.{i}&output=json'
                response = BaseClass.sendRequest(crtUrlSite)
                if response.status_code == 200:
                    data = response.text
                    subdomains = list(set(re.findall(r'\b(?:[a-zA-Z0-9.-]+\.)*' + re.escape(i) + r'\b', data)))
                    FileName = f"Scope/{i}/{i}.crtSh.txt"
                    BaseClass.writeToFile(FileName, subdomains)
                else:
                    self.logger.error(f'Error in geting crt.sh: {response.status_code}')
            else:
                    self.logger.info(f"file already exist or the scope foldar for {i} not exist")


    def runWaybacruls(self):
        if BaseClass.chekcTool("waybackurls"):
            for i in self.ScopeLinks:
                FileExist = BaseClass.checkIfFileExist(f"Scope/{i}/{i}.waybackurls.txt")
                if BaseClass.checkIfDir(f"Scope/{i}") and not FileExist :
                    command = f"waybackurls {i} > Scope/{i}/{i}.waybackurls.txt"
                    result = BaseClass.ExcuteCommand(command)
                else:
                    self.logger.info(f"file already exist or the scope foldar for {i} not exist")
            else:
                self.logger.info("Done waybackurls")
                return True
        else:
            return False

    # This recursive is useless thanks to MohamedSamehMohamed you can just check for file existence then create it first
    def findRealIpScope(self):
        # generate Real Ips from hostIp.txt
        if BaseClass.checkIfFileExist("hostIps.txt"):
            for i in BaseClass.ReadFile("hostIps.txt"):
                isFireWall = self.isFireWallIp(i)
                if isFireWall:
                    continue
                else:
                    BaseClass.writeToFile("scopeRealIps.txt",i)
            else:
                self.logger.info("done finding real ip")
        else:
            if BaseClass.checkIfFileExist("host.txt"):
                self.CollectIpsFromHost()
                self.findRealIpScope()
            else:
                self.FindScopeHost()
                self.CollectIpsFromHost()
                self.findRealIpScope()


    def runMasscanOnScope(self):
        # Don't forget to check if it's a firewall or a site ip
        if BaseClass.checkIfFileExist("scopeRealIps.txt"):
            for i in BaseClass.ReadFile("scopeRealIps.txt"):
                command = f"sudo msudo masscan -p- {i} > {i}.massScan.txt"
                BaseClass.ExcuteCommand(command)
                self.logger.info(f"done massscan on {i}")
            else:
                self.logger.info("Done Mass scan ") 
        else:
            self.logger.error("can't find realScopeIp.txt file")


    def runNmapOnScope(self):
        # Don't forget to check if it's a firewall or a site ip
        if BaseClass.checkIfFileExist("scopeRealIps.txt"):
            for i in BaseClass.ReadFile("scopeRealIps.txt"):
                command = f"sudo nmap -Pn -sS -sC -sV -F {i} -o {i}.namp.txt"
            else:
                self.logger.info("Done Nmap")
        else:
            self.logger.error("can't find realScopeIp.txt file")

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
        r1.CreateScopeFoldars()
        r1.FindScopeHost()
        r1.CollectIpsFromHost()
        r1.runSublist3r()
        r1.runSubfinder()
        r1.runCrtsh()
        r1.runAssetfinder()
        r1.runWaybacruls()
        r1.runAmass()
    else:
        print("run recon.py -h --help")