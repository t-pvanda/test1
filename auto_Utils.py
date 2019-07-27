#!/usr/bin/python
!\Users\dur\AppData\Local\Programs\Python\Python37-32
"""
 @file auto_Utils.py

 Copyright (c) 2006-2009 Awarepoint Corporation. All rights reserved.
 AWAREPOINT PROPRIETARY/CONFIDENTIAL. Use is subject to license terms.
"""

import os
import sys
import time
import re
import socket
import array
import struct
import importlib
import cStringIO
import json
import binascii
#import d2xx
import subprocess
import tempfile
from buzhug import TS_Base
from packet import awpDcpNvp
from Core import sim_Utils
try:
    from PySTAF import *
except ImportError:
    print("Couldn't get STAF!!!")
try:
    from pcap import pcapFile
    from pcap import pcapPacket
except ImportError:
    pass
try:
    d2xx = importlib.import_module('d2xx')
except ImportError:
    pass
        
AUTO_DUT = 'dut.conf'

# Some common NVP Oids for Db lookup purposes

class CommonNvpOids():
    OID_CONST_PWR_BLINK_INTERVAL_S         = ((0x07 << 8) | 0x02)
    OID_CONST_PWR_CONFIG_INTERVAL_S        = ((0x07 << 8) | 0x03)
    OID_CONST_PWR_BLINK_REPORT_INTERVAL_MS = ((0x07 << 8) | 0x06)
    OID_CONST_PWR_CHANNEL_LIST             = ((0x07 << 8) | 0x0A)
    
    OID_BATT_DEVICE_BLINK_INTERVAL_SEC     = ((0x08 << 8) | 0x0C)
    OID_BATT_DEVICE_CONFIG_INTERVAL_SEC    = ((0x08 << 8) | 0x0F)
    OID_BATT_DEVICE_CHANNEL_LIST           = ((0x08 << 8) | 0x18)
    OID_BATT_DEVICE_ASSIGNED_ID            = ((0x08 << 8) | 0x35)
    
    OID_ZIGNET_CHANNEL              = ((0x0B << 8) | 0x02)

# Customized STAF wrapper class for automating tcpdump, file retrieval from
# Appliance (some day)

class STAFWrapper():
    #APPLIANCE = "10.6.5.33"
    def __init__(self, handleName="test", appliance="10.6.103.2", testMachine="10.6.5.139"):
        # create the STAF handle
        try:
            self.stafHandle = STAFHandle(handleName)
        except:
            print "Error creating STAF handle, make sure STAF on local machine is running"
            os._exit(1)
        self.handleNum = self.stafHandle.handle
        self.applianceIp = appliance
        self.testMachIp = testMachine
        self.dumpFile = "C:/temp/tcpdump/dumptest"
    
    # Method designed to test access to appliance server and/or see if STAF
    # is running on the appliance server
    def testCommunication(self, bail=None):
        #submitStr = self.applianceIp + "," + "'ping'" + "," + "'ping'"
        pingSubmit = self.stafHandle.submit(self.applianceIp, "ping", "ping")
        result = self.evalRC(pingSubmit.rc)
        if bail is not None and result != 'Success':
            raise SystemExit(result)
        else:
            return result
    
    def evalRC(self, rc=None):
        if rc is not None:
            if rc == 0:
                self.rcMsg = "Success"
            elif rc == 7:
                self.rcMsg = "Invalid STAF submit string - check syntax"
            elif rc == 10:
                self.rcMsg = "OS error = check command syntax"
            elif rc == 16:
                self.rcMsg = "STAF not running on Appliance, or Appliance IP incorrect"
            elif rc == 22:
                self.rcMsg = "No communication across network"
            elif rc == 25:
                self.rcMsg = "Access Denied"
            elif rc == 48:
                self.rcMsg = "Directory or file does not exist"
            elif rc == 49:
                self.rcMsg = "Directory or file already exists"
            else:
                self.rcMsg = "Error! Return Code: %d" % rc
            return self.rcMsg
        else: print "Must pass in a non-None return code!"
        
    def makeTmpDir(self, directory="/tmp/tcpdump"):
        request = 'CREATE DIRECTORY %s' % (directory) + ' FAILIFEXISTS'
        result = self.stafHandle.submit(self.applianceIp, 'FS', request)
        rc = self.evalRC(result.rc)
        return rc
    
    def deleteTmpDir(self, directory="/tmp/tcpdump"):
        request = 'DELETE ENTRY %s' % (directory) + ' CONFIRM'
        result = self.stafHandle.submit(self.applianceIp, 'FS', request)
        rc = self.evalRC(result.rc)
        return rc
    
    def deleteCapFile(self, filename='/tmp/tcpdump/dumptest'):
        request = 'DELETE ENTRY %s' % (filename) + ' CONFIRM'
        result = self.stafHandle.submit(self.applianceIp, 'FS', request)
        rc = self.evalRC(result.rc)
        return rc
    
    def deleteLocalCapFile(self, filename='C:/temp/tcpdump/dumptest'):
        request = 'DELETE ENTRY %s' % (filename) + ' CONFIRM'
        result = self.stafHandle.submit('localhost', 'FS', request)
        rc = self.evalRC(result.rc)
        return rc
    
    
    def startProcCmd(self, command="/tmp/test.sh"):
        command = '"' + command + '"'
        request = 'START SHELL COMMAND %s' % command + ' &>/dev/null'
        print("STAF request: %s" % request)
        result = self.stafHandle.submit(self.applianceIp, 'PROCESS', request)
        if result.rc == 0:
            return result.result
        else:
            rc = self.evalRC(result.rc)
            return rc
        
    def pidCheck(self, process='tcpdump'):
        command = 'ps -C ' + process + ' -o pid=,ppid='
        command = '"' + command + '"'
        request = 'START SHELL COMMAND %s' % command + ' WAIT RETURNSTDOUT'
        result = self.stafHandle.submit(self.applianceIp, 'PROCESS', request)
        mcres = unmarshall(result.result)
        pidMap = mcres.getRootObject()
        #return result.result
        pidDataList = []
        fdatapid = {}
        for key in pidMap:
            if key == 'fileList':
                fdata = pidMap[key]
                fdatapid = fdata[0]
                for keys in fdatapid:
                    #print keys
                    if keys == 'data':
                        pidData = fdatapid[keys]
                        #print pidData
                        pidDataList.append(pidData)
            #else: print 'crappola batman!'
            #print key
        # split string and strip off newline char
        #pidData = pidData[:-1]
        #print pidDataList
        pidlist = pidDataList[0]
        pidRes = pidlist.split()
        return pidRes
        #return pidDataList
        #return pidMap
    
    def ipAddrFindStr(self, ipaddrintfc='Gigabit'):
        command = 'ipconfig /allcompartments /all'
        command = '"' + command + '"'
        request = 'START SHELL COMMAND %s' % command + ' WAIT RETURNSTDOUT'
        result = self.stafHandle.submit('localhost', 'PROCESS', request)
        mcres = unmarshall(result.result)
        ipRes = mcres.getRootObject()
        #print ipRes
        #return result.result
        pidDataList = []
        fdatapid = {}
        for key in ipRes:
            if key == 'fileList':
                fdata = ipRes[key]
                ipdata = fdata[0]
                for keys in ipdata:
                    if keys == 'data':
                        ipintfaces = ipdata[keys]
        # split string and search for IP Address on interface
        x = 0
        ipConfDataArr = ipintfaces.split('. :')
        for i in xrange(len(ipConfDataArr)):
            if(ipConfDataArr[i].find(ipaddrintfc) != -1):
                x = i
        for y in range(11):
            if(ipConfDataArr[x+y].find('IPv4') != -1):
                ipStr1 = ipConfDataArr[x+y+1]
                ipStr1 = ipStr1.rstrip()
                break
        try:
            ipStr1 = ipStr1.replace('(Preferred)','')
        except:
            pass
        try:
            indx = ipStr1.find('\r')
            ipStr = ipStr1[:(indx-1)]
            ipStr = ipStr.replace(' ','')
        except UnboundLocalError:
            return None
        
        return ipStr
    
    def stopProcess(self, handleNum):
        # handleNum is the return value from the startLocalCapture method
        handle = int(handleNum)
        request = 'STOP HANDLE %d' % handle + ' USING WM_CLOSE'
        result = self.stafHandle.submit('localhost', 'PROCESS', request)
        rc = self.evalRC(result.rc)
        return rc
    
    def killProcess(self, pid=[], singlePid='False'):
        # pid can come from output of pidCheck()
        command = ''
        #for i in range(len(pid)):
        if singlePid == 'False':
            pid1 = int(pid[1])
            pid0 = int(pid[0])
            killProc = '/bin/kill -15 %d %d' % (pid1, pid0)
        elif singlePid == 'True':
            pid0 = int(pid[0])
            killProc = '/bin/kill -15 %d %d' % pid0
        killProc = '"' + killProc + '"'
        #command = 'ssh -l root %s' % self.applianceIp + ' -fn ' + killProc
        #command = '"' + command + '"'
        request = 'START SHELL COMMAND %s' % killProc + ' WAIT'
            #result = self.stafHandle.submit(self.applianceIp, 'PROCESS', request)
        result = self.stafHandle.submit(self.applianceIp, 'PROCESS', request)
        rc = self.evalRC(result.rc)
        return rc
    
    # Method for tcpdump capture on appliance for parsing purposes
    def startCapture(self, filename='dumptest', LIPonly=False, DCPonly=False, ieee80211only=False):
        if LIPonly == True:
            command = 'tcpdump -i eth0 -s 0 port 8544 -w /tmp/tcpdump/%s' % (filename)\
                   + ' &>/dev/null'
        elif DCPonly == True:
            command = 'tcpdump -i eth0 -s 0 port 8400 -w /tmp/tcpdump/%s' % (filename)\
                   + ' &>/dev/null'
        elif ieee80211only == True:
            command = 'tcpdump -i wlan0 -s 0 -w /tmp/tcpdump/%s' % (filename)\
                   + ' &>/dev/null'
        else:
            command = 'tcpdump -i eth0 -s 0 port 8400 or port 8544 -w /tmp/tcpdump/%s' % (filename)\
                   + ' &>/dev/null'
        command = '"' + command + '"'
        request = 'START SHELL COMMAND %s' % command
        result = self.stafHandle.submit(self.applianceIp, 'PROCESS', request)
        if result.rc == 0:
            return result.result
        else:
            rc = self.evalRC(result.rc)
            return rc
        
    # Method to start tcpdump on appliance capturing messages to/from one specified
    # IP address
    def startIPCapture(self, filename='dumptest', ipaddress='', LIPonly=False, DCPonly=False):
        if LIPonly == True:
            command = 'tcpdump -i eth0 -s 0 src ' + ipaddress + ' or dst ' + ipaddress +\
                      ' and port 8544 -w /tmp/tcpdump/%s' % (filename) + ' &>/dev/null'
        elif DCPonly == True:
            command = 'tcpdump -i eth0 -s 0 src ' + ipaddress + ' or dst ' + ipaddress +\
                      ' and port 8400 -w /tmp/tcpdump/%s' % (filename) + ' &>/dev/null'
        else:
            #command = 'tcpdump -i eth0 -s 0 src ' + ipaddress + ' or dst ' + ipaddress +\
            #          ' and ' + '\\' + '(port 8400 or port 8544' + '\\' + ') -w /tmp/tcpdump/%s' % (filename)\
            #       + ' &>/dev/null'
            command = 'tcpdump -i eth0 -s 0 src ' + ipaddress + ' or dst ' + ipaddress +\
                      ' -w /tmp/tcpdump/%s' % (filename) + ' &>/dev/null'
        command = '"' + command + '"'
        #print command
        request = 'START SHELL COMMAND %s' % command
        #print request
        result = self.stafHandle.submit(self.applianceIp, 'PROCESS', request)
        if result.rc == 0:
            return result.result
        else:
            rc = self.evalRC(result.rc)
            return rc
    
    
    # Method to start WinDump on local Windows machine, assumes localhost interface
    # is #3 - wireless Gigabit ethernet interface, if not use 'getLocalInterface' method
    # to return correct interface number
    def startLocalCapture(self, filename='dumptest', intrface = 3, LIPonly=False, DCPonly=False, allPorts=False):
        if LIPonly == True:
            command = 'C:/Program Files/Wireshark/WinDump -i %d' % intrface + ' -s 0 -w C:/temp/tcpdump/%s'\
                      % (filename) + ' dst port 8544'
        elif DCPonly == True:
            command = 'C:/Program Files/Wireshark/WinDump -i %d' % intrface + ' -s 0 -w C:/temp/tcpdump/%s'\
                      % (filename) + ' port 8400'
        elif allPorts == True:
            command = 'C:/Program Files/Wireshark/WinDump -i %d' % intrface + ' -s 0 -w C:/temp/tcpdump/%s'\
                      % (filename)
        else:
            command = 'C:/Program Files/Wireshark/WinDump -i %d' % intrface + ' -s 0 -w C:/temp/tcpdump/%s'\
                      % (filename) + ' port 8400 or dst port 8544'
        command = '"' + command + '"'
        #print command
        request = 'START NEWCONSOLE COMMAND %s' % command
        #print request
        result = self.stafHandle.submit('localhost', 'PROCESS', request)
        #result = self.stafHandle.submit(self.testMachIp, 'PROCESS', request)
        if result.rc == 0:
            return result.result
        else:
            rc = self.evalRC(result.rc)
            return rc
        
    # Method to capture BLE/WiFi packets
    def startBLELocalCapture(self, filename='dumptest', intrface = 'Gigabit', DCPonly=True, DCPIonly=False, allPorts=False):
        # Use intrface="Gigabit" for local ethernet port, or intrface="AirPcap" for WiFi (Channel 1)
        # If capturing WiFi packets, set DCPonly=False and allPorts=True
        # Find the interface number
        #capInterface = self.getPcapInterface(intface=intrface) - won't work with STAX!
        capInterface = self.getLocalInterface(intface=intrface)
        if DCPIonly == True:
            command = 'C:/Program Files/Wireshark/WinDump -i %d' % capInterface + ' -s 0 -w C:/temp/tcpdump/%s'\
                      % (filename) + ' port 8301'
        elif DCPonly == True:
            command = 'C:/Program Files/Wireshark/WinDump -i %d' % capInterface + ' -s 0 -w C:/temp/tcpdump/%s'\
                      % (filename) + ' port 8300'
        elif allPorts == True:
            command = 'C:/Program Files/Wireshark/WinDump -i %d' % capInterface + ' -s 0 -w C:/temp/tcpdump/%s'\
                      % (filename)
        command = '"' + command + '"'
        #print command
        request = 'START NEWCONSOLE COMMAND %s' % command
        #print request
        result = self.stafHandle.submit('localhost', 'PROCESS', request)
        #result = self.stafHandle.submit(self.testMachIp, 'PROCESS', request)
        if result.rc == 0:
            return result.result
            #return filename
        else:
            rc = self.evalRC(result.rc)
            return rc
        
    def vibeController(self, vibetime, dutycycle ):
        command = 'python C:/AwarepointEng/Automation/tools/Vibrator.py %s' % vibetime + ' %s' % dutycycle
        command = '"' + command + '"'
        #print command
        request = 'START NEWCONSOLE COMMAND %s' % command
        #print request
        result = self.stafHandle.submit('localhost', 'PROCESS', request)
        #result = self.stafHandle.submit(self.testMachIp, 'PROCESS', request)
        if result.rc == 0:
            return result.result
            #return filename
        else:
            rc = self.evalRC(result.rc)
            return rc
    
    def getLocalInterface(self, intface="AirPcap"):
        ## Deprecated - use getPcapInterface("interface string") instead
        command = 'C:/Program Files/Wireshark/WinDump -D'
        command = '"' + command + '"'
        filename = "C:/temp/tcpdump/interfaces.txt"
        request = 'START NEWCONSOLE COMMAND %s' % command + ' STDOUT %s' % filename
        #request = 'START COMMAND %s' % command
        #print request
        result = self.stafHandle.submit('localhost', 'PROCESS', request)
        time.sleep(0.5)
        if result.rc == 0:
            for line in open(filename):
                if line.find(intface) != -1:
                    capInterface = line[:1]
                    capInterface = int(capInterface)
                    return capInterface
        else:
            rc = self.evalRC(result.rc)
            return rc
        
    def getPcapInterface(self, intface="AirPcap"):
        lresult = subprocess.Popen(["C:/Program Files/Wireshark/WinDump","-D"],stdout=subprocess.PIPE)
        lIpList = lresult.communicate()[0]
        ipList = lIpList.split("\r\n")
        for i in range(len(ipList)):
            if ipList[i].find(intface) != -1:
                capInterface = ipList[i][:1]
        return int(capInterface)
                
    
    def getTcpdumpFile(self, fromfile="/tmp/tcpdump/dumptest", tofile="C:/temp/tcpdump/dumptest"):
        request = 'COPY FILE %s' % (fromfile) + ' TOFILE %s' % (tofile) +\
        ' TOMACHINE %s' % self.testMachIp
        result = self.stafHandle.submit(self.applianceIp, 'FS', request)
        if result.rc == 0:
            request1 = 'DELETE ENTRY %s' % (fromfile) + ' CONFIRM'
            result = self.stafHandle.submit(self.applianceIp, 'FS', request1)
        rc = self.evalRC(result.rc)
        return rc
    
    def unRegAppl(self, handleNum):
        handleNum = str(handleNum)
        unregSubmit = self.stafHandle.submit(self.applianceIp, "handle", "delete", handleNum)
        return unregSubmit
    
    def unReg(self):
        try:
            unregSubmit = self.stafHandle.unregister()
        except STAFException, e:
            print "Error unregistering handle, RC = %d" % e.rc
            unregSubmit = e.rc
        rc = self.evalRC(unregSubmit)
        return rc
        
# Functions to support automated test cases run from TestPoint

# Class can be used to order dictionary values (not needed yet)
class OrderedDict():
    def __init__(self, dictionary=None):
        self.__keys = []
        self.__dict = {}
        if dictionary is not None:
            if isinstance(dictionary, OrderedDict):
                self.__dict = dictionary.__dict.copy()
                self.__keys = dictionary.__keys[:]
            else:
                self.__dict = dict(dictionary).copy()
                self.__keys = sorted(self.__dict.keys())
        result = []
        for key in self.__keys:
            result.append((key, self.__dict[key]))
        return result
    
# Class for dealing with the USB-to-Gigabit Adapter (ASIX AX88179)
# Check with development support before changing the driver model!!
class USBtoEthAdapter():
    def __init__(self, drivermodel="AX88179"):
        # Dictionary to translate the string input to changeEthFlowControl method
        # to a value for the registry
        self.flowControlTransDict = {
            "Disabled"  : 0,
            "Tx Only"   : 1,
            "Rx Only"   : 2,
            "Tx and Rx" : 3
        }
        # Dictionary to translate the string input to changeEthSpeed method
        # to a value for the registry
        self.speedTransDict = {
            "Auto-negotiate"  : 0,
            "10Mb half dup"   : 1,
            "10Mb full dup"   : 2,
            "100Mb half dup"  : 3,
            "100Mb full dup"  : 4,
            "1Gb full dup"    : 6
        }
        self.longstr = "HKLM\SYSTEM\ControlSet001\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}"
        self.driverModel = drivermodel
        # Painfully discover the version number of the registry key assigned to the Adapter
        # Do this using reg.exe query on the registry location above
        result = subprocess.Popen(["reg","query",self.longstr,"/s","/v","DriverDesc"], stdout=subprocess.PIPE)
        resultstr = result.communicate()[0]
        resultstr = resultstr.split("\r\n")
        keyversionstr = None
        # Search for ASIX AX88179 and grab the 4-digit version number associated with the driver key
        for i in range(len(resultstr)):
            if resultstr[i].find(self.driverModel) != -1:
                keyversionstr = resultstr[i-1]
        if keyversionstr != None:
            keyversion = keyversionstr[-4:]
        else:
            print "ERROR - Key/version not found in registry, call support immediately!"
            return -1
        # Update longstr appropriately
        self.longstr = self.longstr + "\\%s" % keyversion
        #print self.longstr
        
    # Methods to wrap the ASIX USB-to-ethernet adapter device in order to change parameters on
    # the adapter
    def changeEthFlowControl( self, flowcontrol="Tx and Rx" ):
        # Make the batch file to change the registry value (only clean way to do it!)
        # Convert the input string to value
        try:
            flowControlNum = self.flowControlTransDict[flowcontrol]
        except KeyError:
            print "Error - check input argument: %s" % flowcontrol
            return -1
        
        # Get current directory
        cwd = os.getcwd()
        fname = cwd +'\\reg_edit.bat'
        fhandle = open(fname, 'w')
        fhandle.write("reg add ")
        fhandle.write(self.longstr)
        fhandle.write(" /v *FlowControl")
        fhandle.write(" /t REG_SZ")
        fhandle.write(" /d ")
        fhandle.write(str(flowControlNum))
        fhandle.write(" /f")
        fhandle.close()
        
        # Execute the batch file
        result = subprocess.Popen('.\\reg_edit.bat', stdout=subprocess.PIPE)
        rc = result.communicate()[0]
        return rc
    
    def changeEthSpeed( self, speed="Auto-negotiate" ):
        # Make the batch file to change the registry value (only clean way to do it!)
        # Convert the input string to a value
        try:
            speedTrans = self.speedTransDict[speed]
        except KeyError:
            print "Error - check input argument: %s" % speed
            return -1
        
        # Get current directory
        cwd = os.getcwd()
        fname = cwd +'\\reg_edit2.bat'
        fhandle = open(fname, 'w')
        fhandle.write("reg add ")
        fhandle.write(self.longstr)
        fhandle.write(" /v *SpeedDuplex")
        fhandle.write(" /t REG_SZ")
        fhandle.write(" /d ")
        fhandle.write(str(speedTrans))
        fhandle.write(" /f")
        fhandle.close()
        
        # Execute the batch file
        result = subprocess.Popen('.\\reg_edit2.bat', stdout=subprocess.PIPE)
        rc = result.communicate()[0]
        return rc

# Pass in custom dut file if desired, otherwise dut.conf will be used
# If passing in custom file use format file = 'C:\\path\\filename'
# Function should return a list of devices MAC addresses
def loadAutoDutFile( dutfile=None ):
    if dutfile == None:
        wdir = os.getcwd()
        DEVICEFILE = wdir + '\\' + AUTO_DUT
    else:
        DEVICEFILE = dutfile
        
    lineCount = 0
    message = \
        """\n\tDevice File %s is empty. If you are using the GUI version,
        add the devices you intend to use and save the configuration.  If you
        are using the command line, stop the Emulator and edit the file directly,
        save and restart the Emulator.""" % DEVICEFILE
        
    try:
        config = open(DEVICEFILE, 'r')
    except IOError, e:
        config = open(DEVICEFILE, 'w')
        config.close()
        #logging.warning(message)
        return False
    
    macs = []
    # Parse the dut file
    for line in config:
            
        # Remove trailing and leading whitespace
        line = line.strip()

        # If the line begins with a hash or is
        # whitespace only, skip as a comment
        if line.startswith('#') or line == '': continue

        # Otherwise, it represents a device
        macStr = '0x' + line
        macs.append(macStr)

    config.close()
    print "macs found in dut file: ",macs
        
    if len(macs) == 0:
        #logging.warning(message)
        return "No devices found in dut file"
    else:
        return macs
    
# Function to get the devices under test by looking at
# databases' devices previously created in TestPoint
# It returns a list of MAC addresses for all devices found
# in the database
def lookupDatabaseDuts():
    cwd = os.getcwd()
    dbasedir = cwd + '/databases'
    devlist = []
    devlist = os.listdir(dbasedir)
    devlist.sort()
    
    if len(devlist) >= 2:
        devlist = devlist[:-1]
        return devlist
    else:
        return "No devices found in database"
    
# Function to read & print the database NVP values for a given
# device under test - the MAC can be obtained with the
# lookupDatabaseDuts function or supplied manually
# shortReport=True will give only a few key NVP values
# If oid=0x0713 (for example) were given only the NVP value for
# OID 0x0713 would be returned
# Usage:
#  result = auto_Utils.getDutDbConfig(['0014eb0100011b5d']) or
#  result = auto_Utils.getDutDbConfig(['0014eb0100011b5d','0014eb0100010b94'])
def getDutDbConfig(macaddresses, shortReport=False, oid=None):
    for dut in macaddresses:
        cwd = os.getcwd()
        dbasedir = cwd + '/databases/'
        configdir = dbasedir + dut + '/config'
        configdb = TS_Base(configdir)
        configdb.open()
        if oid == None: print 'DUT ----- ' + dut
        
        # Get the oid => value pairs from the config DB
        db_vals = {}
        for dbval in configdb:
            db_vals[dbval.oid] = dbval.value
        configdb.close()
        # Check to see if only one specific oid value is requested
        if oid != None:
            oidVal = db_vals[oid]
            return oidVal
        else:
            #for key in db_vals.keys():
            for key in sorted(db_vals):
                if shortReport == True:
                    oidname = awpDcpNvp.AwpDcpNvpInfo.getName(awpDcpNvp.AwpDcpNvpInfoDefault.OID_TO_INFO, int(key))
                    if key == 0x080f or key == 0x080c or key == 0x0702 or key == 0x0703 or key == 0x0d01 or key == 0x0d04:
                        print 'Oid: ', ('%x' % key), 'OidName: ', oidname, 'Val: ', db_vals[key]
                    if key == 0x0828:
                        db_vals[key] = hex(int(db_vals[key]))
                        print 'Oid: ', ('%x' % key), 'OidName: ', oidname, 'Val: ', db_vals[key]
                elif shortReport == False:
                    oidname = awpDcpNvp.AwpDcpNvpInfo.getName(awpDcpNvp.AwpDcpNvpInfoDefault.OID_TO_INFO, int(key))
                    if int(key) == 257 or int(key) == 258 or int(key) == 269 or int(key) == 2101 or int(key) == 1802 or int(key) == 2817 \
                    or int(key) == 2820 or int(key) == 270 or int(key) == 268 or int(key) == 272 or int(key) == 1811 or int(key) == 1812 \
                    or int(key) == 2072 or int(key) == 2088 or int(key) == 273 or int(key) == 275 or int(key) == 276 or int(key) == 281:
                        db_vals[key] = hex(int(db_vals[key]))
                    if int(key) == 777 or int(key) == 778:
                        db_vals[key] = db_vals[key].replace('\x0025','\x00')
                    if int(key) == 779:
                        db_vals[key] = db_vals[key].replace('\x01\x02','\x00\x00')
                    if int(key) == 782:
                        db_vals[key] = db_vals[key].replace('\x01','\x00')
                    print 'Oid: ', ('%x' % key), 'OidName: ', oidname, 'Val: ', db_vals[key]
    return
        
def getNvpDbDefaultVal(dut, oid):
    # Dut should be of the form 14eb0000024632, can be obtained from
    # lookupDatabaseDuts() method or from the device obj directly
    # oid should be of the form 0x0702, common ones are in the CommonNvpOids() class
    dutStr = ieeeAddrtoDbDir(dut)
    cwd = os.getcwd()
    dbasedir = cwd + '/databases/'
    configdir = dbasedir + dutStr + '/config'
    configdb = TS_Base(configdir)
    configdb.open()
    # Get the oid => value pairs from the config DB
    db_vals = {}
    for dbval in configdb:
        db_vals[dbval.oid] = dbval.value
        
    configdb.close()
    
    #oidStr = str(oid)
    #nvpDefault = db_vals[oidStr]
    nvpDefault = db_vals[oid]
    #nvpDefault = int(nvpDefault)
    #nvpDefault = '%x' % nvpDefault
    
    return nvpDefault

def makeShortAddr(deviceId):
    deviceIdsh = deviceId ^ 0x0014eb0000000000
    deviceIdstr = "%010x" % deviceIdsh
    deviceIdstr = '0x' + deviceIdstr
    #print deviceIdstr
    return deviceIdsh

def getCOMPortNum(devDescr):
    portList = []
    port = ''
    try:
        h = len(d2xx.listDevices())
        for i in range(0, h):

            try:
                p = d2xx.open(i)
                info = p.getDeviceInfo()
                if info['description'] == devDescr:
                    port = "COM%s" % p.getComPortNumber()
                    portList.append(port)
                        
            except d2xx.Error,  e:
                print("try 2 error: %s" % e)
                    

    except d2xx.Error,  e:
            print("try 1 error: %s" % e)

    if portList == []: print "No COM Port found - check device description!"
    return portList

# Older ethernet IP address search method
def getSecondIpAddr():
    # Method to check for a 2nd Ethernet interface on the local machine and get
    # the IP Address of that interface (for B3 testing, etc.)
    # Get main Interface IP associated with host machine
    hostname = socket.gethostname()
    hostIp = socket.gethostbyname(hostname)
    # Grab first 2 IP sub-values
    IPlistvals = hostIp.split('.')
    IPmatchlist = []
    # Make the ugly match string
    #matchstr = '[0-9]+\.[0-9]+\.[0-9]+\.(?!' + IPlistvals[3] + ')'
    matchstr = '10\.[0-9]+\.[0-9]+\.[0-9]+'
    # Get all address info for host machine, must specify either port 8400 or 8544
    hostIpInfo = socket.getaddrinfo(hostname, 8400)
    # Loop thru entries to find any IP address starting with the proper subnet values
    # (from above) but not the hostIP
    for i in range(len(hostIpInfo)):
        if re.match(matchstr, hostIpInfo[i][4][0]):
            secondIp = hostIpInfo[i][4][0]
            IPmatchlist.append(secondIp)
            print secondIp
    #return secondIp
    if len(IPmatchlist) == 1:
        IPmatchlist.append('None')
        IPmatchlist.append('None')
    elif len(IPmatchlist) == 2:
        IPmatchlist.append('None')
    return IPmatchlist

def getIpAddr(interFace):
    # Method to get IP Adress of specified ethernet interface -
    # 'Gigabit' or 'Fast Ethernet'
    if(('Gigabit' not in interFace) and ('Fast Ethernet' not in interFace)):
        print("Invalid Interface provided!! Bailout!")
    else:
        print "Looking for IF: %s" % interFace
        tempDir = tempfile.gettempdir()
        if(osDiscovery() is True):
            tempDir = tempDir.replace("\\","/")
        tempFile = tempDir + "/ifoutput"
        fhandle = open(tempFile,'w')
        lresult = subprocess.Popen(["ipconfig","/allcompartments","/all"],stdout=fhandle)
        fhandle.close()
        time.sleep(1.0)
        # Parse output
        outarr = []
        fhandlen = open(tempFile,'r')
        for line in fhandlen:
            #line = line.strip()
            outarr.append(line)
        fhandlen.close()
        #print "Num lines: %d" % len(outarr)
        os.remove(tempFile)
        
        x = 0
        for i in xrange(len(outarr)):
            if(outarr[i].find(interFace) != -1):
                x = i
            else:
                pass
        for y in range(11):
            try:
                if(outarr[x+y].find('IPv4') != -1):
                    ipStr1 = outarr[x+y]
                    ipStr1 = ipStr1.rstrip()
                    break
            except IndexError:
                pass
        try:
            #print ipStr1
            ipStr1 = ipStr1.replace('(Preferred)','')
            #print ipStr1
        except:
            pass
        try:
            ipStr = ipStr1.replace(' ','')
            indx = ipStr.find(':')
            ipStr = ipStr[(indx+1):]
            #ipStr = ipStr.replace(' ','')
        except UnboundLocalError:
            return None
        
        return ipStr
        
# Method to get hostname and append awarepoint.com to it
def getHostname():
    hostname = socket.gethostname()
    hostname = hostname + '.awarepoint.com'
    return hostname

def osDiscovery():
    # Simple method to discover whether OS is Windows or Linux
    # Used to determine which ipConfigParser method to use
    osPlatform = sys.platform
    if osPlatform.find('win') == 0:
        useWindowsScript = True
        # Figure out if Windows 7 or 10
        #lresult = subprocess.Popen(["ver"],stdout=subprocess.PIPE)
        osVerMinor = sys.getwindowsversion().minor
        #osVersion = lresult.communicate()[0]
        #match1 = re.match(".*[Version ([0-9]+).*", osVersion)
        if osVerMinor == 1:
            osVer = "win7"
        elif osVerMinor == 2:
            osVer = "win10"
    else:
        useWindowsScript = False
        osVer = None
    return useWindowsScript, osVer
    
def ipConfigParserLinux():
    # Method to parse output of 'ifconfig -a' command to find the ethernet
    # Interfaces to be used in TestPoint
    # Might have to send stderr into lala land....
    garbagefile = "/tmp/junkout.txt"
    #fhandle = open(garbagefile,'w')
    subprocess32 = importlib.import_module('subprocess32')
    args = ['ifconfig','-a']
    #lresult = subprocess32.Popen(args, stdout=subprocess32.PIPE, stderr=fhandle)
    lresult = subprocess32.Popen(args, stdout=subprocess32.PIPE)
    lIpList = lresult.communicate()[0]
    ipList = lIpList.split('\n')
    ipListDict = { 'Primary'   : 'None',
                   'Secondary' : 'None',
                   'Wireless'  : 'None'
                   }
    
    lanArray = []
    wanArray = []
    matchIp = ''
    for i in range(len(ipList)):
        match1 = re.match(".*inet addr:([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+).*", ipList[i])
        if match1 is not None:
            matchIP = match1.group(1)
            if matchIp.find("127") == 0:
                continue
            else:
                lanArray.append(matchIP)
    #print "Done with IP search"            
    if len(lanArray) > 1:
        ipListDict['Primary'] = lanArray[0]
        ipListDict['Secondary'] = lanArray[1]
    else:
        ipListDict['Primary'] = lanArray[0]
        
    #fhandle.close()
    return ipListDict
        
def ipConfigParser(osver):
    # Method to parse the output of the 'ipconfig /allcompartments' command
    # and save the IPv4 addresses it finds in the returned dictionary (to
    # be used in TestPoint to supply the server IP address list)
    lresult = subprocess.Popen(["ipconfig","/allcompartments"],stdout=subprocess.PIPE)
    lIpList = lresult.communicate()[0]
    ipList = lIpList.split("\r\n")
    ipListDict = { 'Primary'   : 'None',
                   'Secondary' : 'None',
                   'Wireless'  : 'None'
                   }
    
    if osver == "win7":
        print ("OS Windows 7")
        for i in range(len(ipList)):
            if ipList[i].find("Local Area Connection") != -1:
                if ipList[i][-2:-1] != 'n':
                    ipKey = 'Secondary'
                    if ipList[i+4].find("IPv4") != -1:
                        m = re.search('(?<=:\s)\S+', ipList[i+4])
                        ipListDict[ipKey] = m.group(0)
                else:
                    ipKey = 'Primary'
                    if ipList[i+4].find("IPv4") != -1:
                        m = re.search('(?<=:\s)\S+', ipList[i+4])
                        ipListDict[ipKey] = m.group(0)
            elif ipList[i].find("Wireless Network Connection") != -1:
                ipKey = 'Wireless'
                if ipList[i+4].find("IPv4") != -1:
                    m = re.search('(?<=:\s)\S+', ipList[i+4])
                    ipListDict[ipKey] = m.group(0)
    elif osver == "win10":
        print ("OS Windows 10")
        for i in range(len(ipList)):
            if ipList[i].find("Ethernet adapter Ethernet:") != -1:
                ipKey = 'Primary'
                if ipList[i+4].find("IPv4") != -1:
                        m = re.search('(?<=:\s)\S+', ipList[i+4])
                        ipListDict[ipKey] = m.group(0)
            if ipList[i].find("Ethernet adapter Ethernet 2:") != -1:
                ipKey = 'Secondary'
                if ipList[i+4].find("IPv4") != -1:
                        m = re.search('(?<=:\s)\S+', ipList[i+4])
                        ipListDict[ipKey] = m.group(0)
    return ipListDict

def ipConfigParserSTAX():
    # Method to parse the output of the 'ipconfig /allcompartments' command
    # and save the IPv4 addresses it finds in the returned dictionary (to
    # be used in TestPoint to supply the server IP address list)
    fname = "C:/AwarepointEng/Automation/ipconfigout"
    fhandle = open(fname,'w')
    lresult = subprocess.call(["ipconfig","/allcompartments"],stdout=fhandle)
    time.sleep(0.5)
    fhandle.close()
    time.sleep(0.2)
    ipListDict = { 'Primary'   : 'None',
                   'Secondary' : 'None',
                   'Wireless'  : 'None'
                   }
    ipfile = open(fname,'r')
    #for line in open(fname,'r'):
    for line in ipfile:
        line = line.rstrip()
        if line.find("IPv4") != -1:
            m = re.search('(?<=:\s)\S+', line)
            ipAddr = m.group(0)
            ipKey = 'Primary'
            ipListDict[ipKey] = ipAddr
            #print ipAddr
    ipfile.close()
    return ipListDict
    

def ieeeAddrtoDbDir(deviceIeeeAddr):
    # Pass in the device.ieeeAddr() to convert to a Database directory string
    addr1 = ('%x' % deviceIeeeAddr)
    #addr1hex = hex(int(addr1))
    addr1hex = '00' + addr1
    #addr1hex = addr1hex[:-1]
    #addr1str = addr1hex[2:]
    maclist = []
    maclist.append(addr1hex)
    return addr1hex

# Useful methods for GUI stuff

# Convert hex string (like 'F02B') to binary string
def hexStrToBinStr(hexStr='FFFF',bits=None):
    
    # Check for valid hex string
    if bits == None:
        base = 16
        num_of_bits = 16
    else:
        base = bits
        num_of_bits = bits
    if hexStr[1] == 'x' or hexStr[1] == 'X':
        hexStr = hexStr[2:]
    try:
        intChk = int(hexStr, base)
    except ValueError:
        errStr = 'Enter valid hex string (max 0xffffffff) - ' + hexStr
        return errStr
    # Covert if valid hex string
    #num_of_bits = 16
    #xbstr = bin(int(hexStr, base))[2:].zfill(num_of_bits)
    binStr = bin(intChk)[2:].zfill(num_of_bits)
    return binStr

# Convert binary string to hex string
def binStrToHexStr(binStr='0000000000000000',bits=None):
    # Error check for dummies
    if binStr[1] == 'b' or binStr[1] == 'B':
        binStr = binStr[2:]
    if bits == None:
        base = 16
    else: base = bits
    if len(binStr) < base:
        binStr = binStr[0:].zfill(base)
    try:
        intChk = int(binStr, 2)
    except ValueError:
        errStr = 'Enter valid binary string (ex. 01000101010) - ' + binStr
        return errStr
    if len(binStr) > base:
        errStr = 'You entered too many bits - ' + binStr
        return errStr
    # Convert to hex string
    hexStr = str(hex(intChk))[2:]
    #hexStr = '%04x' % int(hexStr)
    hexStrLen = 4 - len(hexStr)
    if hexStrLen != 0:
        for i in range(hexStrLen):
            hexStr = '0' + hexStr
    hexStr = '0x' + hexStr
    return hexStr

# Method to parse xml files for Feature Control register name lists
def getFeatContrlNames(device):

    import xml.etree.ElementTree as ET

    #filename = sys.argv[1]
    #devType = sys.argv[1]
    #relNum = sys.argv[2]
    devType = device
    #relNum = rel
    errmsg = None
    # devType must be one of the following: S3, T3E, T3X
    # relNum should look like x.y.z

    cwd = os.getcwd()
    deviceDir = cwd + '\\DeviceDefinitions\\' + devType
    #xmlDir = deviceDir + '\\' + relNum
    
    try:
        ldir = os.listdir(deviceDir)
        xmlDir = deviceDir + '\\' + ldir.pop()
        filename = xmlDir + '\\' + os.listdir(xmlDir)[0]

        #print "File to be parsed is: " + filename
        xmldoc = ET.parse(filename)
        root = xmldoc.getroot()

        # Find the NVP "Feature Control - root[1] is the Nvps list
        fcnvp = []
        for nvp in root[1]:
            if nvp[0].text == 'Feature Control':
                fcnvp = nvp
                break

        # Find Bitmask data
        for tag in fcnvp:
            if tag.find('Bitmask') is not None:
                bmdata = tag[0]
	
        # Now get the Feature Control register names and make the list
        fcdict = {}
        for fcregval in bmdata:
            key = fcregval.attrib['offset']
            val = fcregval.attrib['name']
            fcdict[key] = val

        i = len(fcdict)
        while i < 16:
            nkey = str(i)
            nval = 'Rsvd'
            fcdict[nkey] = nval
            i += 1
    
        fclist = []
        for i in range(len(fcdict)):
            key = str(i)
            fclist.append(fcdict[key])
            
    except WindowsError:
        errmsg = 'No directory or XML file'
        #filename = 'Error!'

    except IOError:
        errmsg = 'No directory or XML file'

    #print fclist
    if errmsg is not None:
        return errmsg
    else: return fclist

# Method to convert list of zigbee channels to hex value
# Enter args as list or singleton, like 22 or 14,22,10
def zigbeeChToHexVal(args):
    # Make channel bits list
    chBits = []
    for i in range(32):
        chBits.append(0)
    
    try:
        len(args)
    except TypeError:
        argsv = [args]
    else: argsv = args
    for i in range(len(argsv)):
        #revCh = 31 - args[i]
        if argsv[i] != 0:
            revCh = 31 - argsv[i]
            chBits[revCh] = 1
        else: print 'Channel 0 not allowed'
    
    # Make a string out of channel list
    chBitsStr = ''
    for i in range(len(chBits)):
        chBitsStr = chBitsStr + str(chBits[i])
    
    # Use binStrToHexStr method
    chBitsHex = binStrToHexStr(chBitsStr, 32)
    
    return chBitsHex
    
# Method to convert channel list hex value to zigbee channel numbers
# chBitsHex should be a string like '0x02108000', or similar
def chlistHexToZigbeeChNum(chBitsHex):
    # Strip off '0x' or '0X'
    if chBitsHex[1] == 'x' or chBitsHex[1] == 'X':
        chBitsHex = chBitsHex[2:]
    # Pad hex string to 8 digits
    padLen = 8 - len(chBitsHex)
    for i in range(padLen):
        chBitsHex = '0' + chBitsHex
    
    # Use hexStrToBinStr method
    chBin = hexStrToBinStr(chBitsHex, 32)
    chList = []
    for i in range(len(chBin)):
        if chBin[i] != '0':
            #ch = 31 - i
            ch = i
            chList.append(ch)
            
    return chList

# Method to read in time stamp from a pcap Packet and convert to hr:min:sec.msec
# The timeStampS and timeStampUs values need to come from the testPacket[x].pcap.hdr.timeStampS
# and testPacket[x].pcap.hdr.timeStampUs values when using parsePcapFile() method
def timeConvert(timeStampS,timeStampUs):
    tsecStruct = time.localtime(timeStampS)
    # Make the hr:min:sec.msec string
    t1_hour = tsecStruct.tm_hour
    t1_min = tsecStruct.tm_min
    t1_sec = tsecStruct.tm_sec
    t1_usec = timeStampUs
    timeStr = '%s' % str(t1_hour) + ':' + '%s' % str(t1_min) + ':' + '%s' % str(t1_sec) + '.' + '%s' % str(t1_usec)
    return timeStr

# Method to convert epoch seconds to readable time-of-day
def timeString(timeStampS):
    tsecStruct = time.localtime(timeStampS)
    monthDict = {
        1   : "Jan",
        2   : "Feb",
        3   : "Mar",
        4   : "Apr",
        5   : "May",
        6   : "June",
        7   : "July",
        8   : "Aug",
        9   : "Sep",
        10  : "Oct",
        11  : "Nov",
        12  : "Dec"
    }
    
    # Make the day - month, hr:min:sec year string
    t1_mon = tsecStruct.tm_mon
    t1_month = monthDict[t1_mon]
    t1_day = tsecStruct.tm_mday
    t1_hour = tsecStruct.tm_hour
    t1_hourstr = str(t1_hour)
    if (len(t1_hourstr) != 2):
        t1_hourstr = '0' + t1_hourstr
    t1_min = tsecStruct.tm_min
    t1_minstr = str(t1_min)
    if (len(t1_minstr) != 2):
        t1_minstr = '0' + t1_minstr
    t1_sec = tsecStruct.tm_sec
    t1_secstr = str(t1_sec)
    if (len(t1_secstr) != 2):
        t1_secstr = '0' + t1_secstr
    t1_year = tsecStruct.tm_year
    timeStr = '%s' % str(t1_day) + ' ' + '%s' % str(t1_month) + ' ' + '%s' % t1_hourstr + ':' + \
    '%s' % t1_minstr + ':' + '%s' % t1_secstr + ' ' + '%s' % str(t1_year)
    return timeStr

# Method to get local time-of-day from PC or Linux machine and create
# BLE Tag OID 0x093F - time-of-day - value to send in Configure Message
def tagTime():
    tt = time.gmtime()
    year = hex(tt.tm_year)
    y = year[2:]
    if len(y) == 3:
        y = '0' + y
    # Create year MSB and year LSB
    yearMsb = int(y[0:2],16)
    yearLsb = int(y[2:4],16)
    month = tt.tm_mon
    day = tt.tm_mday
    hour = tt.tm_hour
    mins = tt.tm_min
    secs = tt.tm_sec
    # pack it all up into a 7-byte value
    timeVal = ((yearLsb << 48) + (yearMsb << 40) + (month << 32) + (day << 24) \
        + (hour << 16) + (mins << 8) + secs)
    #timeVal = ((secs << 48) + (mins << 40) + (hour << 32) + (day << 24) + (month << 16) \
    #    + (yearMsb << 8) + yearLsb)
    return hex(timeVal)

# Method to convert hex byte string to 2's complement (such as RSSI values)
# Ex: ans = auto_Utils.binConv('0x99') --> '-103'
def binConv( rbyte ):
    # Covert hex string to 2's complement
    base = 16
    bits = 8
    binVal = bin(int(rbyte, base))[2:].zfill(bits)
    binStr = str(binVal)
    xx = int(binStr, 2)
    if binStr[0] == '1':
        xx -= 2**len(binStr)
    twosStr = str(xx)
    
    return twosStr
    
# Method to find an IP address on the test machine
# Address interface for regular ethernet is 'Gigabit'
# Address interface for USB ethernet is 'Fast Ethernet'
def ipAddrFind(ipaddrintfc='Gigabit'):
        lresult = subprocess.Popen(["ipconfig","/allcompartments","/all"],stdout=subprocess.PIPE)
        ipRes = lresult.communicate()[0]
        #print ipRes
        # split string and search for IP Address on interface
        x = 0
        ipConfDataArr = ipRes.split('. :')
        for i in xrange(len(ipConfDataArr)):
            if(ipConfDataArr[i].find(ipaddrintfc) != -1):
                x = i
        for y in range(11):
            if(ipConfDataArr[x+y].find('IPv4') != -1):
                ipStr1 = ipConfDataArr[x+y+1]
                ipStr1 = ipStr1.rstrip()
                break
        try:
            ipStr1 = ipStr1.replace('(Preferred)','')
        except:
            pass
        try:
            indx = ipStr1.find('\r')
            ipStr = ipStr1[:(indx-1)]
            ipStr = ipStr.replace(' ','')
        except UnboundLocalError:
            return None
        
        return ipStr
    
# Method using pcapFile and pcapPacket to parse thru a tcpdump file and
# collect all DCP or LIP messages of any specified Command ID
# The tcpdump file should be captured using the STAFWrapper methods, or
# by commandline.
# Any tcpdump or windump file may be specified, if msgType='LIP' is
# specified then only commandId's from LIP Headers are allowed, similarly
# if msgType='DCP' is specified only DCP commandId's can be used, or if
# msgType='ICMP' is specified all ICMP messages are returned, or if
# msgType='80211' is specified then all ieee802.11 messages are returned.
# One can also specify a MAC address to filter on if more than one device is in
# the PCAP file capture, example - for 80211 wifiMac='00:14:eb:ff:ff:d'(:0d), leave
# off leading zeroes except for '00':14:eb...
# for DCP - dcpMac='0x0014ebfffe22'
# List of commandId's: 0 = Ack, 1 = Config Req, 2 = Config, 10 = Ack-With-Query-Reply,
#    0x1b = FW Avail, 0x1c = Certs Avail, 0x1d = WLAN Params Msg, 0x0d = Temp Sample
# List of blinkId's: 0 = Beacon Report, 1 = Button Press, 2 = Attach/Detach, 3 = Health,
#    4 = Power Off, 5 = Temp Sample
def parsePcapFile(filename='dumptest', msgType='DCP', commandId=None, blinkId=None, \
                  numpackets=False, dcpMac=None, wifiMac=None, wifi=True):
    dumpDir = "C:/temp/tcpdump/"
    dumpFile = dumpDir + filename
    # Open tcpdump file
    fhandle = open(dumpFile, 'rb')
    # make PcapFile instance
    pcapPFile = pcapFile.PcapFile(fhandle)
    # Loop thru file and collect messages of specified commandId and
    # return the list of messages
    messageList = []
    messageList2 = []
    messageCnt = 0
    numpackets = False
    numPackets = pcapPFile.getNumPackets()
    #print numPackets
    if wifi == False:
        try:
            for i in range(numPackets):
                testPacket = pcapPFile.getPacket(i)
                if msgType == 'DCP':
                    #print ("Got DCP msg")
                    #messageList2.append(testPacket)
                    if (testPacket.tcp.sdu.hdr.cmdId != None):
                        #print ("Got awpDCP msg")
                        if commandId != None:
                            if (testPacket.tcp.sdu.hdr.cmdId == commandId):
                                if dcpMac == None:
                                    messageList.append(testPacket)
                                    messageCnt += 1
                                    numPackets = True
                                elif dcpMac != None:
                                    dcpAddr = sim_Utils.wifiAddrFromStr(dcpMac)
                                    #print("found mac: %d, looking for: %d" % (testPacket.tcp.sdu.hdr.wifiAddr, dcpAddr))
                                    if testPacket.tcp.sdu.hdr.wifiAddr == dcpAddr:
                                        #print("Got Match!")
                                        messageList.append(testPacket)
                                        messageCnt += 1
                                        numPackets = True
                        elif commandId == None:
                            if dcpMac == None:
                                    messageList.append(testPacket)
                                    messageCnt += 1
                                    numPackets = True
                            elif dcpMac != None:
                                dcpAddr = sim_Utils.wifiAddrFromStr(dcpMac)
                                if testPacket.tcp.sdu.hdr.wifiAddr == dcpAddr:
                                    messageList.append(testPacket)
                                    messageCnt += 1
                                    numPackets = True
                elif msgType == 'ICMP':
                    if testPacket.icmp != None:
                        messageList.append(testPacket)
                        messageCnt += 1
                elif msgType == 'UDPB':
                    if testPacket.awpUdpBlink != None:
                        messageList.append(testPacket)
                        messageCnt += 1
                        numPackets = True
        except AttributeError:
            retMsg = 'Error - No messages of correct type found!'
            fhandle.close()
            return retMsg
            #return messageList
        fhandle.close()
        if numpackets == True:
            print 'Messages found: %d' % messageCnt
            return messageList
        return messageList
    elif wifi == True:
        try:
            for i in range(numPackets):
                testPacket = pcapPFile.getPacket(i)
                if msgType == '80211':
                    if testPacket.ieee80211 != None:
                        if testPacket.ieee80211.sdu.frameControl == 0x803:
                            #print ("Got FC match")
                            if hex(testPacket.ieee80211.sdu.llc) == '0x40106':
                                #print ("Got LLC match")
                                if wifiMac == None:
                                    if (testPacket.ieee80211.sdu.sdu.hdr.blinkType == blinkId):
                                        #print("Blink: %d" % testPacket.ieee80211.sdu.sdu.hdr.blinkType)
                                        messageList.append(testPacket)
                                        x = testPacket.pcap.hdr.timeStampS
                                        y = testPacket.pcap.hdr.timeStampUs
                                        timestr = timeConvert(x,y)
                                        #print timestr
                                        messageCnt += 1
                                        numpackets = True
                                    elif blinkId == None:
                                        messageList.append(testPacket)
                                        messageCnt += 1
                                        numpackets = True
                                elif wifiMac != None:
                                    if testPacket.ieee80211.sdu.trnsmtrAddr == wifiMac:
                                        if (testPacket.ieee80211.sdu.sdu.hdr.blinkType == blinkId):
                                            #print("Blink: %d" % testPacket.ieee80211.sdu.sdu.hdr.blinkType)
                                            messageList.append(testPacket)
                                            x = testPacket.pcap.hdr.timeStampS
                                            y = testPacket.pcap.hdr.timeStampUs
                                            timestr = timeConvert(x,y)
                                            #print timestr
                                            messageCnt += 1
                                            numpackets = True
                                        elif blinkId == None:
                                            messageList.append(testPacket)
                                            messageCnt += 1
                                            numpackets = True
        except AttributeError:
            retMsg = 'Error - No messages of correct type found!'
            fhandle.close()
            return retMsg
        fhandle.close()
        if numpackets == True:
            print 'Messages found: %d' % messageCnt
            return messageList
        else:
            return messageList

# Method similar to parsePcapFile, but with 2 commandId's to allow for parsing
# 2 types of messages (for the getAppConfig.py tool)
# Default is setup to pick out CONFIGURATION and ACKNOWLEDGE_WITH_QUERY_REPLY
# messages from the tcpdump or windump file. The return is a list of those
# message objects
def parseACPcapFile(filename='appconfiginfo', msgType='DCP', commandId1=10, commandId2=2):
    fileName = 'C:\\temp\\tcpdump\\%s' % filename
    # Open tcpdump file
    fhandle = open(fileName, 'rb')
    # make PcapFile instance
    pcapPFile = pcapFile.PcapFile(fhandle)
    # Loop thru file and collect messages of specified commandId's and
    # return the list of messages
    messageList = []
    numPackets = pcapPFile.getNumPackets()
    #print numPackets
    try:
        for i in range(numPackets):
            testPacket = pcapPFile.getPacket(i)
            if msgType == 'LIP':
                if testPacket.awpLip != None:
                    if testPacket.awpLip.hdr.cmdId == commandId1 or testPacket.awpLip.hdr.cmdId == commandId2:
                        messageList.append(testPacket)
            elif msgType == 'DCP':
                if testPacket.awpDcp != None:
                    if testPacket.awpDcp.hdr.cmdId == commandId2 or testPacket.awpDcp.hdr.cmdId == commandId1:
                        messageList.append(testPacket)
        #fhandle.close()
        #return messageList
    except AttributeError:
        retMsg = 'Error - No messages of correct type found!'
        fhandle.close()
        return retMsg
    fhandle.close()
    return messageList

# Method to parse all DCP and LIP messages from a pcap file and print the message count
# values
def getMsgStats(filename='', writetofile=False):
    fileName = 'C:\\temp\\tcpdump\\%s' % filename
    strfn = 'Bridge file data from: %s' % filename + '\n'
    wfileName = 'C:\\AwarepointEng\\Automation\\temp\\%s' % filename + '.txt'
    CRmsgcnt = 0
    Cmsgcnt = 0
    QRmsgcnt = 0
    PSSmsgcnt = 0
    DBRmsgcnt = 0
    PZRSImsgcnt = 0
    TSmsgcnt = 0
    AWQRmsgcnt = 0
    BRmsgcnt = 0
    STATmsgcnt = 0
    CRcmdId = 0x01
    CcmdId = 0x02
    QRcmdId = 0x03
    PSScmdId = 0x12
    TScmdId = 0xd
    AWQRcmdId = 0x0a
    BRcmdId = 0x04
    DBRcmdId = 0x05
    PZRSIcmdId = 0x09
    STATcmdId = 0x04
    
    # Parse file for messages
    fhandle = open(fileName, 'rb')
    pcapPFile = pcapFile.PcapFile(fhandle)
    numPackets = pcapPFile.getNumPackets()
    
    try:
        for i in range(numPackets):
            testPacket = pcapPFile.getPacket(i)
            if testPacket.awpLip != None:
                if testPacket.awpLip.hdr.cmdId == DBRcmdId:
                    DBRmsgcnt += 1
                elif testPacket.awpLip.hdr.cmdId == BRcmdId:
                    BRmsgcnt += 1
                elif testPacket.awpLip.hdr.cmdId == PZRSIcmdId:
                    PZRSImsgcnt += 1
            elif testPacket.awpDcp != None:
                if testPacket.awpDcp.hdr.cmdId == CRcmdId:
                    CRmsgcnt += 1
                elif testPacket.awpDcp.hdr.cmdId == PSScmdId:
                    PSSmsgcnt += 1
                elif testPacket.awpDcp.hdr.cmdId == TScmdId:
                    TSmsgcnt += 1
                elif testPacket.awpDcp.hdr.cmdId == QRcmdId:
                    QRmsgcnt += 1
                elif testPacket.awpDcp.hdr.cmdId == CcmdId:
                    Cmsgcnt += 1
                elif testPacket.awpDcp.hdr.cmdId == AWQRcmdId:
                    AWQRmsgcnt += 1
                elif testPacket.awpDcp.hdr.cmdId == STATcmdId:
                    STATmsgcnt += 1
    except AttributeError:
        print 'Error - No messages of correct type found!'
        fhandle.close()
        #exit()
        return 1
    fhandle.close()
    totalmsgs = CRmsgcnt + Cmsgcnt + AWQRmsgcnt + PSSmsgcnt + TSmsgcnt \
                + BRmsgcnt + DBRmsgcnt + PZRSImsgcnt + QRmsgcnt + STATmsgcnt
    print 'Number of CONFIG_REQ messages: %d' % CRmsgcnt
    str1 = 'Number of CONFIG_REQ messages: %d' % CRmsgcnt + '\n'
    print 'Number of CONFIGURE messages: %d' % Cmsgcnt
    str2 = 'Number of CONFIGURE messages: %d' % Cmsgcnt + '\n'
    print 'Number of ACK_WITH_QUERY_REPLY messages: %d' % AWQRmsgcnt
    str3 = 'Number of ACK_WITH_QUERY_REPLY messages: %d' % AWQRmsgcnt + '\n'
    print 'Number of SYNC_STATUS messages: %d' % PSSmsgcnt
    str4 = 'Number of SYNC_STATUS messages: %d' % PSSmsgcnt + '\n'
    print 'Number of TEMP_SAMPLE_IND messages: %d' % TSmsgcnt
    str5 = 'Number of TEMP_SAMPLE_IND messages: %d' % TSmsgcnt + '\n'
    print 'Number of BLINK_REP messages: %d' % BRmsgcnt
    str6 = 'Number of BLINK_REP messages: %d' % BRmsgcnt + '\n'
    print 'Number of DUAL_BLINK_REP messages: %d' % DBRmsgcnt
    str7 = 'Number of DUAL_BLINK_REP messages: %d' % DBRmsgcnt + '\n'
    print 'Number of PROX_REPORT_IEEE messages: %d' % PZRSImsgcnt
    str8 = 'Number of PROX_REPORT_IEEE messages: %d' % PZRSImsgcnt + '\n'
    print 'Number of QUERY_REPLY messages: %d' % QRmsgcnt
    str9 = 'Number of QUERY_REPLY messages: %d' % QRmsgcnt + '\n'
    print 'Number of STATUS messages: %d' % STATmsgcnt
    str10 = 'Number of STATUS messages: %d' % STATmsgcnt + '\n'
    print 'Total number of messages is: %d' % totalmsgs
    str11 = 'Total number of messages is: %d' % totalmsgs + '\n'
    print '\n'
    
    if writetofile == True:
        fhandle = open(wfileName, 'w')
        fhandle.write(strfn)
        fhandle.write(str1)
        fhandle.write(str2)
        fhandle.write(str3)
        fhandle.write(str4)
        fhandle.write(str5)
        fhandle.write(str6)
        fhandle.write(str7)
        fhandle.write(str8)
        fhandle.write(str9)
        fhandle.write(str10)
        fhandle.write(str11)
        fhandle.close()
        
def rangeCheck(value1=0.0,value2=0.0,percentage=20,tdiff=1.0):
    # Function to check if 2 time values are within a percentage
    # difference of each other, with a delta in between
    # Calculate delta
    tDelt = (value2 - value1)
    tDiff1 = (tdiff - (1.0 * (percentage / 100.0)))
    tDiff2 = (tdiff + (1.0 * (percentage / 100.0)))
    if( (tDelt >= tDiff1) and (tDelt <= tDiff2) ):
        return True
    else:
        return False
    
def macConvert(macaddr):
    # Code to convert macAddress '0014ebfff804' to WiFi format '00:14:eb:ff:f8:04'
    macPart1 = macaddr[0:2]
    macPart2 = macaddr[2:4]
    macPart3 = macaddr[4:6]
    macPart4 = macaddr[6:8]
    macPart5 = macaddr[8:10]
    macPart6 = macaddr[10:12]
    
    if( macPart4[:1] == '0'):
        macPart4 = macaddr[7:8]
    if( macPart5[:1] == '0'):
        macPart5 = macaddr[9:10]
    if( macPart6[:1] == '0'):
        macPart6 = macaddr[11:12]
    macStr = macPart1 + ':' + macPart2 + ':' + macPart3 + ':' + macPart4 + ':' + \
             macPart5 + ':' + macPart6
    return macStr

def quickPoll(macAdd, polltime, beactype, beacint):
    # MSE polling function
    # beactype = Beac, Butt, Stat, Attach, Temp
    # polltime in seconds
    # beacon interval in seconds
    # MAC like 0014eb07d7bc
    print("starting MSE poll")
    macAddr = macAdd[:2] + ':' + macAdd[2:4] + ':' + macAdd[4:6] + ':' + macAdd[6:8] + ':' + macAdd[8:10] + ':' + macAdd[10:12]
    lastSeq = 0
    res = -1
    filename = "C:/AwarepointEng/MSEpolling/junk.txt"
    jhandle = open(filename, 'w')
    curDir = os.getcwd()
    curDir = curDir.replace("\\","/")
    #tArray = []
    for i in range(polltime):
        tagStr = "https://apitester:A6it3ster@10.6.20.61/api/contextaware/v1/location/tags/" + macAddr
        subprocStrArr = ["C:/Program Files (x86)/Curl/curl","-k","-H","Accept:application/json",tagStr]
        tagSession = subprocess.Popen(subprocStrArr,stdout=subprocess.PIPE,stderr=jhandle)
        resStr = tagSession.communicate()[0]
        #lrtm = re.search('.+lastLocatedTime(\S{26})', resStr)
        lrtm = re.search('.+lastReceivedTime(\S{26})', resStr)
        lrt = lrtm.group(1)[3:]
        lrt = lrt.replace("T"," ")
        #tArray.append(lrt)
        ddata = json.loads(resStr)
        vdata = ddata['TagLocation']['VendorData']['data']
        vdDecode = binascii.a2b_base64(vdata)
        beacCmdId, = struct.unpack_from('B', vdDecode, 0)
        if( (beacCmdId == 0) and (beactype == 'Beac')):
            beacSeq, beacCnt, beacFlags, = struct.unpack_from('BBB', vdDecode, 1)
            curSeq = beacSeq
            #print("Got Beacon Report!")
            #print("Seq Num: %d" % beacSeq)
        elif( (beacCmdId == 1) and (beactype == 'Butt')):
            beacSeq, pressVal = struct.unpack_from('BB', vdDecode, 1)
            print("Got Button Press!")
            print("Seq: %d, Val: %d" % (beacSeq,pressVal))
        elif( (beacCmdId == 2) and (beactype == 'Attach')):
            beacSeq, detach = struct.unpack_from('BB', vdDecode, 1)
            print("Got Attach/Detach!")
            print("Seq: %d, Val: %d" % (beacSeq,detach))
        elif( (beacCmdId == 3) and (beactype == 'Stat')):
            beacSeq, health = struct.unpack_from('BB', vdDecode, 1)
            print("Got Status! - %d" % health)
        elif( (beacCmdId == 5) and (beactype == 'Temp')):
            print("Got Temp Sample")
        #print "Last Received: %s" % lrt
        if (curSeq - lastSeq) == beacint:
            print("Yay")
            res = 1
            break
        else:
            #print("Booo")
            res = -1
        time.sleep(0.9)
        lastSeq = curSeq
    
    jhandle.close()
    resul = os.remove(filename)
    return res
