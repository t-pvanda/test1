#!/usr/bin/python3
## Script to automatically run remote commands for collecting system
## hardware and software config information from a Vantage1.1 IFX system
## Notes: may not work on AWS or Azure systems
##        need root password(s) for DB and analytic nodes
## Usage:
#     - python3 get_system_info.py -sys vantage10 -dbh <dbhostname> -aah <aahostname> -dbp <dbhostpwd> 
#                    -aap <aahostpwd> -sth <stackihost> | <-stp stackipwd>
#     replace vantage10 with system under test name (no spaces please), if Stacki password same
#     as DB host password then it is optional

import argparse
try:
    import pexpect
except:
    print("No pexpect module found! Use pip install pexpect to fix this issue!")
    exit(1)
import paramiko
import sys
import os
import re
import time

# Parse input arguments
parser = argparse.ArgumentParser()
parser.add_argument('-sys','--system-name',type=str, dest='system_name', help='Supply system name',required=True)
parser.add_argument('-dbh','--db-host-name',type=str, dest='remote_db_host', help='Supply DB hostname',required=True)
parser.add_argument('-aah','--aa-host-name',type=str, dest='remote_aa_host', help='Supply AA hostname',required=True)
parser.add_argument('-dbp','--dbpassword',type=str, dest='remote_db_pass', help='Supply dbhost password',required=True)
parser.add_argument('-aap','--aapassword',type=str, dest='remote_aa_pass', help='Supply aahost password',required=True)
parser.add_argument('-sth','--stackihost',type=str, dest='remote_stacki_host', help='Supply stacki hostname',required=True)
parser.add_argument('-stp','--stackipwd',type=str, dest='remote_stacki_pass', help='Supply stacki password',required=False)
args = parser.parse_args()
system_name, remote_db_host, remote_aa_host, remote_db_pass, remote_aa_pass, remote_stacki_host, remote_stacki_pass = args.system_name, \
args.remote_db_host,args.remote_aa_host, args.remote_db_pass, args.remote_aa_pass, args.remote_stacki_host, args.remote_stacki_pass 
if remote_stacki_pass == None:
    remote_stacki_pass = remote_db_pass
print("Getting sytem info for %s and %s" % (remote_db_host,remote_aa_host))

cwd = os.getcwd()

# Make local sbom directories to copy sbom files from DB, AA, STACKI nodes to
sbompath = cwd + "/sbom" + system_name
dbsbom = sbompath + "/db_sbom"
aasbom = sbompath + "/aa_sbom"
stkbom = sbompath + "/stk_sbom"
if (os.path.exists(sbompath)) == False:
    os.mkdir(sbompath)
    os.mkdir(dbsbom)
    os.mkdir(aasbom)
    os.mkdir(stkbom)

# Create local system_info output file
outfile = cwd + "/" + system_name + "_sys_info.out"
fh = open(outfile, 'w')

# Make sure remote hosts are known or not in ~.ssh/known_hosts file
try:
    child = pexpect.spawn('ssh %s@%s' % ('root',remote_db_host))
    i = child.expect(['.*Password:', '.* continue connecting (yes/no)?'])
    if i == 1:
        print("sending yes...")
        child.sendline('yes')
    elif i == 0:
        print("sending pwd...")
        child.sendline(remote_db_pass)
    else:
        print("sending nothing...")
    print("exiting...")
    child.sendline('\x03')
except Exception as err:
    print(err)
try:
    child = pexpect.spawn('ssh %s@%s' % ('root',remote_aa_host))
    i = child.expect(['.*Password:', '.* continue connecting (yes/no)?'])
    if i == 1:
        print("sending yes...")
        child.sendline('yes')
    elif i == 0:
        print("sending pwd...")
        child.sendline(remote_aa_pass)
    else:
        print("sending nothing...")
    print("exiting...")
    child.sendline('\x03')
except Exception as err:
    print(err)
try:
    child = pexpect.spawn('ssh %s@%s' % ('root',remote_stacki_host))
    i = child.expect(['.*Password:', '.* continue connecting (yes/no)?'])
    if i == 1:
        print("sending yes...")
        child.sendline('yes')
    elif i == 0:
        print("sending pwd...")
        child.sendline(remote_aa_pass)
    else:
        print("sending nothing...")
    print("exiting...")
    child.sendline('\x03')

except Exception as err:
    print(err)

# HARDWARE section
# Gather hardware related info from TD DB and Analytic nodes
# Make SSH clients
sshdbh = paramiko.SSHClient()
sshaah = paramiko.SSHClient()
sshsth = paramiko.SSHClient()
sshdbh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
sshaah.set_missing_host_key_policy(paramiko.AutoAddPolicy())
sshsth.set_missing_host_key_policy(paramiko.AutoAddPolicy())

## Not Needed
# Check if /root/bom directory exists in DB node - if not create it
#sshdbh.connect(hostname=remote_db_host,username='root',password=remote_db_pass)
#fh_stdin,fh_stdout,fh_stderr = sshdbh.exec_command("ls /root/bom")
#danswr = fh_stderr.readlines()
#errstr = "No such file or directory"
#try:
#    if errstr in danswr[0]:
#        # create directory /root/bom
#        try:
#            print("Creating /root/bom directory.")
#            fh_stdin,fh_stdout,fh_stderr = sshdbh.exec_command("mkdir /root/bom")
#            fh_stdin,fh_stdout,fh_stderr = sshdbh.exec_command("chmod 755 /root/bom")
#        except Exception as err:
#            print(err)
#except IndexError:
#    print("Found /root/bom dir!")
 
## Not Needed
# Check if /root/bom directory exists in AA node - if not create it
#sshaah.connect(hostname=remote_aa_host,username='root',password=remote_aa_pass)
#fh_stdin,fh_stdout,fh_stderr = sshaah.exec_command("ls /root/bom")
#danswr = fh_stderr.readlines()
#errstr = "No such file or directory"
#try:
#    if errstr in danswr[0]:
#        # create directory /root/bom
#        try:
#            print("Creating /root/bom directory.")
#            fh_stdin,fh_stdout,fh_stderr = sshaah.exec_command("mkdir /root/bom")
#            fh_stdin,fh_stdout,fh_stderr = sshdbh.exec_command("chmod 755 /root/bom")
#        except Exception as err:
#            print(err)
#except IndexError:
#    print("Found /root/bom dir!")
 
# Gather DB master node BIOS info
fh_stdin,fh_stdout,fh_stderr = sshdbh.exec_command("machinetype | grep BIOS")
answr = fh_stdout.readlines()
if len(answr) != 0:
    print("DB node BIOS: %s" % (answr[0]))
    fh.write("DB node BIOS:\t %s" % (answr[0]))
else:
    print("No DB node BIOS found!!")
    fh.write("No BIOS info for DB node %s" % (remote_db_host))

# Gather AA master node BIOS info
fh_stdin,fh_stdout,fh_stderr = sshaah.exec_command("machinetype | grep BIOS")
answr = fh_stdout.readlines()
if len(answr) != 0:
    print("AA node BIOS: %s" % (answr[0]))
    fh.write("AA node BIOS:\t %s" % (answr[0]))
else:
    print("No AA node BIOS found!!")
    fh.write("No BIOS info for AA node %s" % (remote_aa_host))

# Get file system information from nodes
sshsth.connect(hostname=remote_stacki_host,username='root',password=remote_stacki_pass)
fh_stdin,fh_stdout,fh_stderr = sshsth.exec_command("stack iterate host remote_db_host command='df -k'")
arr = fh_stderr.readlines()
arrx = fh_stdout.readlines()
errstr = "command not found"
if errstr in arr[0]:
    print("No stack command on server!")
else:
    fh.write("File System - DB Node: \n")
    for item in arrx:
        fh.write(" filesytem: %s\n" % (item))
    fh_stdin,fh_stdout,fh_stderr = sshsth.exec_command("stack iterate host remote_aa_host command='df -k'")
    arr1 = fh_stdout.readlines()
    fh.write("File System - AA Node: \n") 
    for item in arr1:
        fh.write(" filesytem: %s\n" % (item))
    print("Fetched file system info...")

# Get OS kernel info
fh_stdin,fh_stdout,fh_stderr = sshdbh.exec_command("rpm -qa | grep kernel-default")
answr = fh_stdout.readlines()
if len(answr) != 0:
    print("DB node kernel: %s" % (answr))
    for i in range(len(answr)):
        fh.write("DB node kernel %d:\t %s" % (i, answr[i]))
else:
    print("No DB node kernel found!!")
    fh.write("No kernel info for DB node %s" % (remote_db_host))

fh_stdin,fh_stdout,fh_stderr = sshaah.exec_command("rpm -qa | grep kernel-default")
answr = fh_stdout.readlines()
if len(answr) != 0:
    print("AA node kernel: %s" % (answr))
    for i in range(len(answr)):
        fh.write("AA node kernel %d:\t %s" % (i, answr[i]))
else:
    print("No AA node kernel found!!")
    fh.write("No kernel info for AA node %s" % (remote_db_host))

# Get CPU related info
# DB Node first
procdict = { 'model name':'','cpu speed':'','cache size':'','cpu cores':'' }
cpudict = {}
fh_stdin,fh_stdout,fh_stderr = sshdbh.exec_command("cat /proc/cpuinfo")
answ = fh_stdout.readlines()
ss = fh_stderr.readlines()
errstr = "No such file or directory"
if len(ss) != 0:
    if errstr in ss[0]:
        print("No CPU Info file!!")
        fh.write("No CPU Info file for DB node!")
    else:
        print("Error occured trying to read /proc/cpuinfo file!")
else:
    x = 0
    while x < len(answ):
        resstr = answ[x].rstrip()
        if 'processor' in resstr:
            mat = re.match('.*: (\d+)', resstr)
            proc = mat.group(1)
            cpudict[proc] = procdict
        if "model name" in resstr:
            mat = re.match('.*: (.*)$', resstr)
            modname = mat.group(1)
            cpudict[proc]['model name'] = modname
        if "cpu MHz" in resstr:
            mat = re.match('.*: ([0-9]+\.[0-9]+)$', resstr)
            cpuspeed = mat.group(1)
            cpudict[proc]['cpu speed'] = cpuspeed
        if "cache size" in resstr:
            mat = re.match('.*: ([0-9]+\sKB)$', resstr)
            cachesize = mat.group(1)
            cpudict[proc]['cache size'] = cachesize
        if "cpu cores" in resstr:
            mat = re.match('.*: ([0-9]+)$', resstr)
            cpucores = mat.group(1)
            cpudict[proc]['cpu cores'] = cpucores
        x = x + 1
    print("Number of processors for DB node is: %d" % (int(proc) + 1))
    fh.write("Number of processors for DB node is: %d" % (int(proc) + 1))
    #for key in cpudict:
    fh.write("processor: 1, data: %s\n" % (cpudict['1']))

# AA Node 
procdict = { 'model name':'','cpu speed':'','cache size':'','cpu cores':'' }
cpudict = {}
fh_stdin,fh_stdout,fh_stderr = sshaah.exec_command("cat /proc/cpuinfo")
answ = fh_stdout.readlines()
ss = fh_stderr.readlines()
errstr = "No such file or directory"
if len(ss) != 0:
    if errstr in ss[0]:
        print("No AA CPU Info file!!")
        fh.write("No CPU Info file for AA node!")
    else:
        print("Error occured trying to read AA /proc/cpuinfo file!")
else:
    x = 0
    while x < len(answ):
        resstr = answ[x].rstrip()
        if 'processor' in resstr:
            mat = re.match('.*: (\d+)', resstr)
            proc = mat.group(1)
            cpudict[proc] = procdict
        if "model name" in resstr:
            mat = re.match('.*: (.*)$', resstr)
            modname = mat.group(1)
            cpudict[proc]['model name'] = modname
        if "cpu MHz" in resstr:
            mat = re.match('.*: ([0-9]+\.[0-9]+)$', resstr)
            cpuspeed = mat.group(1)
            cpudict[proc]['cpu speed'] = cpuspeed
        if "cache size" in resstr:
            mat = re.match('.*: ([0-9]+\sKB)$', resstr)
            cachesize = mat.group(1)
            cpudict[proc]['cache size'] = cachesize
        if "cpu cores" in resstr:
            mat = re.match('.*: ([0-9]+)$', resstr)
            cpucores = mat.group(1)
            cpudict[proc]['cpu cores'] = cpucores
        x = x + 1
    print("Number of processors for AA node is: %d" % (int(proc) + 1))
    fh.write("Number of processors for AA node is: %d" % (int(proc) + 1))
    #for key in cpudict:
    fh.write("processor: 1, AA data: %s\n" % (cpudict['1']))

# Get memory info
# DB Node --
fh_stdin,fh_stdout,fh_stderr = sshdbh.exec_command("free")
ss = fh_stderr.readlines()
sss = fh_stdout.readlines()
if len(ss) != 0:
    print("Error getting free memory space from DB node!")
    fh.write("No memory info for DB node!")
else:
    for i in range(len(sss)):
        wrstr = sss[i].replace('\n','')
        wrstr = wrstr.replace('-/+','')
        fh.write("DB: %s\n" % (wrstr))

# AA Node --
fh_stdin,fh_stdout,fh_stderr = sshaah.exec_command("free")
ss = fh_stderr.readlines()
sss = fh_stdout.readlines()
if len(ss) != 0:
    print("Error getting free memory space from AA node!")
    fh.write("No memory info for AA node!")
else:
    for i in range(len(sss)):
        wrstr = sss[i].replace('\n','')
        wrstr = wrstr.replace('-/+','')
        fh.write("AA: %s\n" % (wrstr))

# SOFTWARE BOM section

# Figure out name of sbom file
# May have to ssh into nodes to verify UTC time is set
# Presume server time is set to UTC time for now
date = time.gmtime()
fh_stdin,fh_stdout,fh_stderr = sshdbh.exec_command("date")
rem_date = fh_stdout.readlines()
db_date = rem_date[0]
mat = re.match('^(\S+)\s(\S+)\s(\d+)\s(\d+):(\d+).*', db_date)
rday = mat.group(3)
rhour = mat.group(4)
rmin = mat.group(5)
#day = date.tm_mday
mon = date.tm_mon
#year = date.tm_year
#sbom_date = str(mon) + str(day) + str(year)
sbom_date = str(mon) + rday
print("SBOM date: %s" % (sbom_date))

# Get SBOM and profile.cfg
# DB Node
dbsbom_file1 = dbsbom + "/profile.cfg"
dbsbom_file2 = dbsbom + "/DB_sbom.txt"
try:
    fh_stdin,fh_stdout,fh_stderr = sshdbh.exec_command("/opt/stack/bin/getbom")
    serr = fh_stderr.readlines()
    db_ftp = sshdbh.open_sftp()
    if len(serr) != 0:
        print("Error running getbom -- %s" % (serr[0]))
        fh.write("No SBOM scripts for DB node!!\n")
    # Get list of sbom directory on server
    sbomlist = db_ftp.listdir('/root/bom')
    if len(sbomlist) != 0:
        for i in range(len(sbomlist)):
            if sbom_date in sbomlist[i]:
                remote_sbom = '/root/bom/' + sbomlist[i]
                print("SBOM file is: %s" % (remote_sbom))
                db_ftp.get(remote_sbom,dbsbom_file2)
    time.sleep(0.5)
    db_ftp.get('/root/bom/profile.cfg',dbsbom_file1)
    time.sleep(1)
    db_ftp.close()
    fh.write("\nDB sbom files are in %s\n\n" % (dbsbom))

    # Analyze profile.cfg and sbom files for SW information
    pfileh = open(dbsbom_file1, 'r')
    for line in pfileh:
        if "pallets =" in line:
            resstr = line.replace("pallets = ", '')
            resarr = eval(resstr)
            fh.write("DB Pallet Versions:\n")
            fh.write("OS: %s\n" % (resarr[0]))
            for i in range(5):
                fh.write("%s\n" % (resarr[i+1]))
    pfileh.close()

    # Analyze sbom file
    fh.write("\nDB SBOM SW version info:\n")
    sbfileh = open(dbsbom_file2, 'r')
    for line in sbfileh:
        if "Date:" in line:
            try:
                mat = re.match('^Date: (\d+)', line)
                sbdate = mat.group(1)
                fh.write("Date: %s\n" % (sbdate))
            except AttributeError:
                pass
        if "TDput:" in line:
            mat = re.match('TDput:(\S+)-(\S+):.*', line)
            tdput1 = mat.group(1)
            tdput2 = mat.group(2)
            fh.write("TD PUT ver: %s-%s\n" % (tdput1,tdput2))
        if "bteq:" in line:
            mat = re.match('bteq:(\S+)-(\S+):.*', line)
            tdput1 = mat.group(1)
            tdput2 = mat.group(2)
            fh.write("BTEQ ver: %s-%s\n" % (tdput1,tdput2))
        if "bynet:" in line: 
            mat = re.match('bynet:(\S+)-(\S+):.*', line)
            bynet1 = mat.group(1)
            bynet2 = mat.group(2)
            fh.write("Bynet ver: %s-%s\n" % (bynet1,bynet2))
        if "ppde:" in line:
            mat = re.match('ppde:(\S+)-(\S+):.*', line)
            ppdever1 = mat.group(1)
            ppdever2 = mat.group(2)
            fh.write("PPDE ver: %s-%s\n" % (ppdever1,ppdever2))
        if "ppdegpl:" in line:
            mat = re.match('ppdegpl:(\S+)-(\S+):.*', line)
            ppdegplver1 = mat.group(1)
            ppdegplver2 = mat.group(2)
            fh.write("PPDE GPL ver: %s-%s\n" % (ppdegplver1,ppdegplver2))
        if (("pde:" in line) and ("ppde:" not in line) and ("ppdegpl:" not in line)):
            mat = re.match('pde:(\S+)-(\S+):.*', line)
            pdever1 = mat.group(1)
            pdever2 = mat.group(2)
            fh.write("PDE Base ver: %s-%s\n" % (pdever1,pdever2))
        if "ptdbms:" in line:
            mat = re.match('ptdbms:(\S+)-(\S+):.*', line)
            ptdbms1 = mat.group(1)
            ptdbms2 = mat.group(2)
            fh.write("PDE SQLE ver: %s-%s\n" % (ptdbms1,ptdbms2))
        if "teradata-gsctools:" in line:
            mat = re.match('teradata-gsctools:(\S+)-(\S+):.*', line)
            gsctools1 = mat.group(1)
            gsctools2 = mat.group(2)
            fh.write("GSC Tools ver: %s-%s\n\n" % (gsctools1,gsctools2))
except Exception as err:
    print("Error! %s" % (err))
    fh.write("No SBOM scripts for DB node!!\n")
    try:
        db_ftp.close()
    except:
        pass

# AA Node
aasbom_file1 = aasbom + "/profile.cfg"
aasbom_file2 = aasbom + "/AA_sbom.txt"
try:
    fh_stdin,fh_stdout,fh_stderr = sshaah.exec_command("/opt/stack/bin/getbom")
    serr = fh_stderr.readlines()
    aa_ftp = sshaah.open_sftp()
    if len(serr) != 0:
        print("Error running getbom -- %s" % (serr[0]))
        fh.write("No SBOM scripts for AA node!!\n")
    # Get list of sbom directory on server
    sbomlist = aa_ftp.listdir('/root/bom')
    if len(sbomlist) != 0:
        for i in range(len(sbomlist)):
            if sbom_date in sbomlist[i]:
                remote_sbom = '/root/bom/' + sbomlist[i]
                aa_ftp.get(remote_sbom,aasbom_file2)
    time.sleep(0.5)
    aa_ftp.get('/root/bom/profile.cfg',aasbom_file1)
    time.sleep(1)
    aa_ftp.close()
    fh.write("AA sbom files are in %s\n\n" % (aasbom))

    # Analyze profile.cfg and sbom files for SW information
    pfileh = open(aasbom_file1, 'r')
    for line in pfileh:
        if "pallets =" in line:
            resstr = line.replace("pallets = ", '')
            resarr = eval(resstr)
            fh.write("AP Pallet Versions:\n")
            fh.write("OS: %s\n" % (resarr[0]))
            for i in range(4):
                fh.write("%s\n" % (resarr[i+1]))
    pfileh.close()

    # Analyze sbom file
    fh.write("\nAA SBOM SW version info:\n")
    sbfileh = open(aasbom_file2, 'r')
    for line in sbfileh:
        if "Date:" in line:
            try:
                mat = re.match('^Date: (\d+)', line)
                sbdate = mat.group(1)
                fh.write("Date: %s\n" % (sbdate))
            except AttributeError:
                pass
        if "TDput:" in line:
            mat = re.match('TDput:(\S+)-(\S+):.*', line)
            tdput1 = mat.group(1)
            tdput2 = mat.group(2)
            fh.write("TD PUT ver: %s-%s\n" % (tdput1,tdput2))
        if "bynet:" in line: 
            mat = re.match('bynet:(\S+)-(\S+):.*', line)
            bynet1 = mat.group(1)
            bynet2 = mat.group(2)
            fh.write("Bynet ver: %s-%s\n" % (bynet1,bynet2))
        if "kubekit:" in line:
            mat = re.match('kubekit:(\S+)-(\S+):.*', line)
            kubek1 = mat.group(1)
            kubek2 = mat.group(2)
            fh.write("Kubekit ver: %s-%s\n" % (kubek1,kubek2))
        if "sles-release-DVD:" in line:
            mat = re.match('.*release-DVD:(\S+)-(\S+):.*', line)
            slesdvd1 = mat.group(1)
            slesdvd2 = mat.group(2)
            fh.write("SLES12 DVD ver: %s-%s\n" % (slesdvd1,slesdvd2))
        if "teradata-gsctools:" in line:
            mat = re.match('teradata-gsctools:(\S+)-(\S+):.*', line)
            gsctools1 = mat.group(1)
            gsctools2 = mat.group(2)
            fh.write("GSC Tools ver: %s-%s\n\n" % (gsctools1,gsctools2))
except Exception as err:
    print("Error! %s" % (err))
    fh.write("No SBOM scripts for AA node!!\n\n")
    try:
        aa_ftp.close()
    except:
        pass
# STACKI Node
#stkbom_file1 = stkbom + "/profile.cfg"
#stkbom_file2 = stkbom + "/STACKI_sbom.txt"
#try:
#    fh_stdin,fh_stdout,fh_stderr = sshsth.exec_command("/opt/stack/bin/getbom")
#    serr = fh_stderr.readlines()
#    if len(serr) != 0:
#        print("Error running getbom -- %s" % (serr[0]))
#        fh.write("No SBOM scripts for STACKI node!!\n")
#    else:
#        st_ftp = sshsth.open_sftp()
#        # Get list of sbom directory on server
#        sbomlist = st_ftp.listdir('/root/bom')
#        if len(sbomlist) != 0:
#            for i in range(len(sbomlist)):
#                if sbom_date in sbomlist[i]:
#                    remote_sbom = '/root/bom/' + sbomlist[i]
#                    st_ftp.get(remote_sbom,stkbom_file2)
#        time.sleep(0.5)
#        st_ftp.get('/root/bom/profile.cfg',stkbom_file1)
#        time.sleep(1)
#        st_ftp.close()
#        fh.write("STACKI sbom files are in %s\n\n" % (stkbom))
#except Exception as err:
#    print("Error! %s" % (err))
#    fh.write("No SBOM scripts for STACKI node!!\n\n")
#    try:
#        st_ftp.close()
#    except:
#        pass

# Docker image info for AP Node 
try:
    fh_stdin,fh_stdout,fh_stderr = sshaah.exec_command("docker image ls")
    errarr = fh_stderr.readlines()
    resarr = fh_stdout.readlines()
    if  len(errarr) != 0:
        print("Error getting docker images for AA Node: %s" % (errarr[0]))
    else:
        x = 0
        while x < len(resarr):
            resstr = resarr[x].rstrip()
            if "appcenter/app-service" in resstr:
                mat = re.match('.*app-service\s+(\S+).*', resstr)
                ACver = mat.group(1)
            if "mle/drops/dockerimages" in resstr:
                try:
                    mat = re.match('.*mle/drops.*/mleinit\s+(\S+).*', resstr)
                    MLEver = mat.group(1)
                except AttributeError:
                    pass
            if "tdqg-node" in resstr:
                mat = re.match('.*tdqg-node\s+(\S+).*', resstr)
                TDQGver = mat.group(1)
            if "platform/elasticsearch" in resstr:
                try:
                    mat = re.match('.*elasticsearch\s+(\S+).*', resstr)
                    ElSever = mat.group(1)
                except AttributeError:
                    pass
            x = x + 1
    fh.write("Docker Image Info from AP Node:\n")
    fh.write("AppCenter - %s\n" % (ACver))
    fh.write("MLE - %s\n" % (MLEver))
    fh.write("TDQG node - %s\n" % (TDQGver))
    fh.write("Elasticsearch - %s\n\n" % (ElSever))
except Exception as err:
    print("Error running docker image ls! %s" % (err))

# SQLEngine version info for DB Node
## Doesn't work due to 'ctl -nw' puts you in interactive shell on host
#try:
#    child = pexpect.spawn('ssh %s@%s' % ('root',remote_db_host))
#    i = child.expect(['.*Password:', '.* continue connecting (yes/no)?'])
#    if i == 0:
#        print("sending pwd...")
#        child.sendline(remote_db_pass)
#        child.expect('.*~ #')
#        child.sendline('ctl -nw')
#        child.expect('>')
#        child.sendline('scr')
        
#    else:
#        print("Error in expect ...")
#        print("exiting...")
#        child.sendline('\x03')

# PDE Info for DB Nodes
try:
    fh_stdin,fh_stdout,fh_stderr = sshdbh.exec_command("/usr/pde/bin/tdinfo")
    errarr = fh_stderr.readlines()
    resarr = fh_stdout.readlines()
    if len(errarr) != 0:
        print("Error getting PDE status: %s" % (errarr[0]))
        fh.write("No PDE status for DB Nodes!\n")
    else:
        x = 0
        while x < len(resarr):
            #resstr = resarr[x].rstrip()
            resstr = resarr[x]
            if "NodeName" in resstr:
                fh.write("DB bynet info:\n")
                fh.write(resstr)
                #fh.write("\n")
            if "byn" in resstr:
                print(resstr)
                fh.write(resstr)
                #fh.write("\n") 
            if "PDE state" in resstr:
                print(resstr)
                fh.write(resstr)
                #fh.write("\n")
            if "DBS state" in resstr:
                print(resstr)
                fh.write(resstr)
                #fh.write("\n")
            if x == len(resarr):
                print(resstr)
                fh.write("%s\n" % (resstr))
                #fh.write("\n")
            x = x + 1
except Exception as err:
    print("Error running tdinfo! - %s" % (err))

# Bynet BLM Info for DB Nodes
try:
    fh_stdin,fh_stdout,fh_stderr = sshdbh.exec_command("/opt/teradata/bynet/bin/bam -s")
    errarr = fh_stderr.readlines()
    resarr = fh_stdout.readlines()
    if len(errarr) != 0:
        print("Error getting BLM version: %s" % (errarr[0]))
        fh.write("No BLM version for DB Nodes!\n")
    else:
        x = 0
        while x < len(resarr):
            resstr = resarr[x]
            if "Version information" in resstr:
                print("Getting BLM versions...")
                fh.write("BLM %s" % (resstr))
            if "commands" in resstr:
                mat = re.match('^(\d+\.\d+\.\d+\.\d+).*', resstr)
                BLMcomver = mat.group(1)
                fh.write("BLM command ver: %s\n" % (BLMcomver))
            if "driver" in resstr:
                mat = re.match('^(\d+\.\d+\.\d+\.\d+).*', resstr)
                BLMdriver = mat.group(1)
                fh.write("BLM driver ver: %s\n" % (BLMdriver))
            if "protocol" in resstr:
                try:
                    mat = re.match('^(\d+\.\d+\.\d+\.\d+).*', resstr)
                    BLMprotocol = mat.group(1)
                    fh.write("BLM protocol ver: %s\n" % (BLMprotocol))
                except:
                    pass
            x = x + 1
except Exception as err:
    print("Error running bam -s! - %s" % (err))

# Elastic tcore version info for DB Nodes
try:
    fh_stdin,fh_stdout,fh_stderr = sshdbh.exec_command("rpm -qa | grep elastic")
    errarr = fh_stderr.readlines()
    resarr = fh_stdout.readlines()
    if len(errarr) != 0:
        print("Error getting elastic tcore version: %s" % (errarr[0]))
        fh.write("No ElasticTcore version for DB Nodes!\n")
    else:
        resstr = resarr[0]
        try:
            mat = re.match('^tvs-elastic-tcore-(\S+)$', resstr)
            ETver = mat.group(1)
            fh.write("Elastic Tcore ver: %s\n" % (ETver))
        except Exception as err:
            print("Error getting ETcore version! - %s" % (err))
            fh.write("No Elastic Tcore version for DB Nodes!")
except Exception as err:
    print("Error getting ETcore: %s" % (err))
    fh.write("No Elastic Tcore version for DB Nodes!")

# CMIC Version Info
try:
    fh_stdin,fh_stdout,fh_stderr = sshaah.exec_command("/opt/teradata/gsctools/bin/get_cmic_version")
    errarr = fh_stderr.readlines()
    resarr = fh_stdout.readlines()
    if len(errarr) != 0:
        print("Error getting CMIC version: %s" % (errarr[0]))
        fh.write("No CMIC version for AA Nodes!\n")
    else:
        try:
            resstr = resarr[0]
            print("CMIC Version: %s" % (resstr))
            fh.write("CMIC version: %s\n" % (resstr))
        except Exception as err:
            print("Error getting CMIC version: %s" % (err))
            fh.write("No CMIC version for AA Nodes!\n")
except Exception as err:
    print("Error getting CMIC: %s" % (err))
    fh.write("No CMIC version for AA Nodes!\n")

sshdbh.close()
sshaah.close()
sshsth.close()
fh.close()
