import logSetup
import os
import subprocess
import requests

logger = logSetup.log("BaseClass","log.txt")

class BaseClass:

    @staticmethod
    def ReadFile(Path):
        if BaseClass.checkIfFileExist(Path):
            try:
                with open(Path, 'r') as file:
                    Lines = [line.strip() for line in file.readlines() if line.strip()]
                    return Lines
            except:
                logger.error("Error in reading file {}".format(Path))
        else:
            logger.error("File does not exist")

    @staticmethod
    def checkIfFileExist(Path):
        if Path:
            return os.path.isfile(Path)
        else:
            return False
    
    @staticmethod
    def checkIfDir(dirPath):
        return os.path.isdir(dirPath)

    @staticmethod
    def ExcuteCommand(command):
        return subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    @staticmethod
    def checkCommandResult(result):
        try:
            if result.returncode == 0:
                return True
            else:
                return False
        except:
            logger.error("command results doesn't have returecode")

    @staticmethod
    def writeToFile(FileName, Data):
        with open(FileName, "a") as file:
            if isinstance(Data, list):
                for i in Data:
                    file.write(i+'\n')
            elif isinstance(Data, str ):
                file.write(Data+'\n')
            else:
                logger.error("can't find the data Type ")

                
    @staticmethod
    def WriteImage(FileName, Data):
        with open(FileName, "wb") as file:
            file.write(Data)

    @staticmethod
    def sendRequest(url):
        return requests.get(url)

    @staticmethod
    def chekcTool(tool):
        command = f"which {tool}"
        result = BaseClass.ExcuteCommand(command)
        if BaseClass.checkCommandResult(result):
            return True
        else:
            logger.error(f"This {tool} is not installed")
            return False

    @staticmethod
    def checkResponseResult(response):
        try:
            if response.status_code == 200:
                return True
            else:
                return False
        except:
            logger.error("response doesn't have status_code")

