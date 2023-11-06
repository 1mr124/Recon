#!/usr/bin/python3

import argparse
import os
import subprocess

class Recon:
    def __init__(self, FilePath):
        self.FilePath = FilePath
        self.ScopeLinks = self.ReadFile(FilePath)


    def ReadFile(self, Path):
        if self.checkIfFileExist(Path):
            try:
                with open(Path, 'r') as file:
                    Lines = [line.strip() for line in file.readlines() if line.strip()]
                    return Lines
            except:
                print("Error in reading file {}".format(Path))
        else:
            print("File does not exist")


    def checkIfFileExist(self, Path):
        return os.path.isfile(Path)

    def FindFireWall(self):
            if self.checkIfFileExist(self.FilePath):
                command = "wafw00f -i {} -o wafwoof.txt".format(self.FilePath)
                result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                if result.returncode == 0:
                    print("Done finding firewall for all socpe result in waffwoff.txt")
                    return True
                else:
                    print("Error in finding firewall")
                    return False

    def FindFireWallForSingleUrl(self, Url):
        command = "wafw00f {}".format(Url)
        result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode == 0:
            if "No WAF" in result.stdout:
                return False
            elif "is behind" in result.stdout:
                return True
        else:
            print("Error in finding firewall")



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
        
    else:
        print("run recon.py -h --help")