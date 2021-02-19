import os, sys, subprocess, signal
import re

sys.path.insert(0, './python-utils/')
sys.path.insert(1, './library-debloating/')

import container
import graph
import util
import syscall
import seccomp
import bisect
import time
from datetime import datetime
import forkstat
import sysdig
import constants as C
import binaryAnalysis

import piecewise

class ContainerProfiler():
    """
    This class can be used to create a seccomp profile for a container through static anlyasis of the useful binaries
    """
    def __init__(self, name, imagePath, options, imageBinaryFiles, dockerStartArgs, dockerPath, dockerEntryPoint, dockerEntryPointModify, dockerTemplateEntryPoint, glibccfgpath, muslcfgpath, glibcfunclist, muslfunclist, strictmode, gofolderpath, cfgfolderpath, fineGrain, extractAllBinaries, logger, isDependent=False):
        self.logger = logger
        self.name = name
        self.imagePath = imagePath
        self.imageBinaryFiles = imageBinaryFiles
        self.dockerStartArgs = dockerStartArgs
        self.dockerPath = dockerPath
        self.dockerEntryPoint = dockerEntryPoint
        self.dockerEntryPointModify = True if dockerEntryPointModify == 'true' else False
        self.dockerTemplateEntryPoint = dockerTemplateEntryPoint
        #self.name = name
        #if ( "/" in self.name ):
        #    self.name = self.name.replace("/","-")
        #if ( ":" in self.name ):
        #    self.name = self.name[:self.name.find(":")]
        self.options = options
        self.glibcCfgpath = glibccfgpath
        self.muslCfgpath = muslcfgpath
        self.glibcFuncList = glibcfunclist
        self.muslFuncList = muslfunclist
        self.strictMode = strictmode
        self.goFolderPath = gofolderpath
        self.cfgFolderPath = cfgfolderpath
        self.status = False
        self.runnable = False
        self.installStatus = False
        self.debloatStatus = False
        self.restrictedDebloatStatus = False
        self.errorMessage = ""
        self.denySyscallsOriginal = None
        self.denySyscallOriginalCount = 0
        self.denySyscallsFineGrain = None
        self.denySyscallFineGrainCount = 0
        self.denySyscallsRestrictive = None
        self.denySyscallRestrictiveCount = 0
        self.directSyscallCount = 0
        self.libcSyscallCount = 0
        self.languageSet = set()
        self.fineGrain = fineGrain
        self.extractAllBinaries = extractAllBinaries
        self.isDependent = isDependent
        self.containerName = None

    #TODO List
    '''
    1. Create required list of functions required by the container
        1.1. Run container
        1.2. Take snapshot of processes
        1.3. Copy binaries required and dependent libraries to host
        1.4. Extract imported libraries with objdump
    2. Map those functions to the required system calls
        2.1. Use libc callgraph to map imported libc functions to system calls
    3. Generate seccomp profile
    4. Test if the profile works with the container
    '''

    #New TODO
    '''
    1. Fix bug in tracking executed processes (SOLVED)
    2. Prevent single-time useable containers from stopping (hello-world, ubuntu, centos) (The true,false ones) (SOLVED in some cases)
    '''

    def extractDirectSyscalls(self, folder):
        #exceptList = ["lib", "grep", "sed", "bash", "sh"]
        exceptList = ["ld.so", "libc.so", "libdl.so", "libcrypt.so", "libnss_compat.so", "libnsl.so", "libnss_files.so", "libnss_nis.so", "libpthread.so", "libm.so", "libresolv.so", "librt.so", "libutil.so", "libnss_dns.so", "gosu"]
        lib = ".so"

        fileList = list()
        filesAdded = set()
        finalSyscallSet = set()
        for fileName in os.listdir(folder):
            if ( util.isElf(folder + "/" + fileName) ):
                if ( lib in fileName ):
                    tmpFileName = re.sub("-.*so",".so",fileName)
                    tmpFileName = tmpFileName[:tmpFileName.index(".so")]
                    tmpFileName = tmpFileName + ".so"
                else:
                    tmpFileName = fileName
                if ( tmpFileName not in exceptList and tmpFileName not in filesAdded ):
                    fileList.append(folder + "/" + fileName)
                    filesAdded.add(tmpFileName)

                #libWoVersionName = fileName
                #if ( fileName.startswith("lib") ):
                #    libWoVersionName = fileName[:fileName.index(".so")]
                #    libWoVersionName = libWoVersionName + ".so"
                #if ( libWoVersionName not in libWoVersion ):
                #    libWoVersion.add(libWoVersionName)
                #    fileList.append(folder + "/" + fileName)
                #    for exceptItem in exceptList:
                #        #if ( lib in fileName or fileName.startswith(exceptItem) or util.isGo(folder + "/" + fileName, self.logger) ):
                #        if ( fileName.startswith(exceptItem) or util.isGo(folder + "/" + fileName, self.logger) ):
                #            removeList.append(folder + "/" + fileName)
                #            break
        finalSet = set(fileList)# - set(removeList)
        for filePath in finalSet:
            self.logger.debug("extraction direct syscall for %s", filePath)
            #temp = util.extractDirectSyscalls(filePath, self.logger)
            #self.directSyscallCount += temp
            #self.logger.debug("directSyscall for %s is %d", filePath, temp)
            #temp = util.extractLibcSyscalls(filePath, self.logger)
            #self.libcSyscallCount += temp
            #self.logger.debug("libcSyscall for %s is %d", filePath, temp)
            binAnalysis = binaryAnalysis.BinaryAnalysis(filePath, self.logger)
            syscallSet, successCount, failCount = binAnalysis.extractDirectSyscalls()
            self.logger.debug("Successfull direct syscalls: %d list: %s, Failed direct syscalls: %d", successCount, str(syscallSet), failCount)
            #self.logger.warning("Failed syscalls: %d", failCount)
            if ( syscallSet ):
                finalSyscallSet.update(syscallSet)
        return finalSyscallSet

    def extractAllImportedFunctions(self, folder, fileName):
        outputFilePath = folder + "/" + fileName
        outputFile = open(outputFilePath, 'a+')
        for fileName in os.listdir(folder):
            functionList = util.extractImportedFunctions(folder + "/" + fileName, self.logger)
            if ( not functionList ):
                self.logger.debug("Function extraction for file: %s failed (probably not an ELF file).", fileName)
            else:
                for function in functionList:
                    outputFile.write(function + "\n")
                    outputFile.flush()
        outputFile.close()
        return outputFilePath

    def extractAllImportedFunctionsFromBinary(self, folder, fileName):
        funcSet = set()
        functionList = util.extractImportedFunctions(folder + fileName, self.logger)
        if ( not functionList ):
            self.logger.debug("Function extraction for file: %s failed (probably not an ELF file).", fileName)
        else:
            for function in functionList:
                funcSet.add(function)
        return funcSet

    def usesMusl(self, folder):
        #return True
        for fileName in os.listdir(folder):
            if ( "musl" in fileName ):
                return True
        return False

    def extractBinaryType(self, folder):
        for fileName in os.listdir(folder):
            if ( fileName == "gosu" ):
                continue
            if ( fileName == "java" ):
                self.languageSet.add("Java")
            if ( fileName == "python" ):
                self.languageSet.add("Python")
            if ( fileName == "perl" ):
                self.languageSet.add("Perl")
            headerSection = util.extractHeaderSection(folder + "/" + fileName, self.logger)
            if ( headerSection.strip() != "" ):
                for lang in util.BinaryLang:
                    if ( lang.value in headerSection ):
                        self.languageSet.add(lang.name)
                if ( len(self.languageSet) == 0 ):
                    self.languageSet.add(util.BinaryLang.CCPP.name)
        return

    def getStatus(self):
        return self.status

    def getRunnableStatus(self):
        return self.runnable

    def getInstallStatus(self):
        return self.installStatus

    def getDenylistedSyscallCount(self):
        if ( self.fineGrain ):
            return self.denySyscallFineGrainCount
        else:
            return self.denySyscallOriginalCount

    def getDenylistedSyscallOriginalCount(self):
        return self.denySyscallOriginalCount

    def getDenylistedSyscallFineGrainCount(self):
        return self.denySyscallFineGrainCount

    def getDenylistedSyscallRestrictiveCount(self):
        return self.denySyscallRestrictiveCount

    def getDebloatStatus(self):
        return self.debloatStatus

    def getRestrictedDebloatStatus(self):
        return self.restrictedDebloatStatus

    def getErrorMessage(self):
        return self.errorMessage

    def getDenylistedSyscalls(self):
        if ( self.fineGrain ):
            return self.denySyscallsFineGrain
        else:
            return self.denySyscallsOriginal

    def getDenylistedSyscallsOriginal(self):
        return self.denySyscallsOriginal

    def getDenylistedSyscallsFineGrain(self):
        return self.denySyscallsFineGrain

    def getDenylistedSyscallsRestrictive(self):
        return self.denySyscallsRestrictive

    def getDirectSyscallCount(self):
        return self.directSyscallCount

    def getLibcSyscallCount(self):
        return self.libcSyscallCount

    def getLanguageSet(self):
        return self.languageSet

    def getContainerName(self):
        return self.containerName

    def createSeccompProfile(self, tempOutputFolder, resultsFolder):
        returnCode = 0
        if os.geteuid() != 0:
            self.logger.error("This script must be run as ROOT only!")
            exit("This script must be run as ROOT only. Exiting.")
        self.logger.debug("tempOutputFolder: %s", tempOutputFolder)

        allSyscalls = set()

        muslSyscallList = list()
        glibcSyscallList = list()

        i = 0
        while i < 400:
            muslSyscallList.append("syscall(" + str(i) + ")")
            glibcSyscallList.append("syscall(" + str(i) + ")")
            glibcSyscallList.append("syscall ( " + str(i) + " )")
            glibcSyscallList.append("syscall( " + str(i) + " )")
            i += 1

        fineGrainCfgs = dict()

        glibcGraph = graph.Graph(self.logger)
        glibcGraph.createGraphFromInput(self.glibcCfgpath, ":")

        glibcWrapperListTemp = []
        if ( self.strictMode ):
            for func in self.glibcFuncList:
                glibcWrapperListTemp.extend(glibcGraph.getSyscallFromStartNode(func))
        else:
            i = 0
            while i < 400:
                glibcWrapperListTemp.append(i)
                i += 1
        glibcWrapperList = set(glibcWrapperListTemp)
        muslGraph = graph.Graph(self.logger)
        muslGraph.createGraphFromInput(self.muslCfgpath, "->")
        muslWrapperListTemp = []
        if ( self.strictMode ):
            for func in self.muslFuncList:
                muslWrapperListTemp.extend(muslGraph.getSyscallFromStartNode(func))
        else:
            i = 0
            while i < 400:
                muslWrapperListTemp.append(i)
                i += 1
        muslWrapperList = set(muslWrapperListTemp)

#        self.logger.debug("glibcWrapperList: %s", str(glibcWrapperList))
#        self.logger.debug("muslWrapperList: %s", str(muslWrapperList))


        #TODO Separate libaio-like CFGs from fine-grained CFGs
        #Go through extra CFGs such as libaio to extract lib->syscall mapping
        #for fileName in os.listdir(self.cfgFolderPath):
        #    self.logger.debug("Adding cfg: %s", fileName)
        #    glibcGraph.createGraphFromInput(self.cfgFolderPath + "/" + fileName, "->")
        #    muslGraph.createGraphFromInput(self.cfgFolderPath + "/" + fileName, "->")

        #time.sleep(10)

        exceptList = ["access","arch_prctl","brk","close","execve","exit_group","fcntl","fstat","geteuid","lseek","mmap","mprotect","munmap","openat","prlimit64","read","rt_sigaction","rt_sigprocmask","set_robust_list","set_tid_address","stat","statfs","write","setns","capget","capset","chdir","fchown","futex","getdents64","getpid","getppid","lstat","openat","prctl","setgid","setgroups","setuid","stat","io_setup","getdents","clone","readlinkat","newfstatat","getrandom","sigaltstack","getresgid","getresuid","setresgid","setresuid","alarm","getsid","getpgrp", "epoll_pwait", "vfork", "fstatfs"]
        
        binExceptList = ["execve", "exit group", "brk", "mmap", "munmap", "prctl", "write", "fstat"]

        javaExceptList = ["open", "getcwd", "openat", "close", "fopen", "fclose", "link", "unlink", "unlinkat", "mknod", "rename", "renameat", "mkdir", "rmdir", "readlink", "realpath", "symlink", "stat", "lstat", "fstat", "fstatat", "chown", "lchown", "fchown", "chmod", "fchmod", "utimes", "futimes", "lutimes", "readdir", "read", "write", "access", "getpwuid", "getgrgid", "statvfs", "clock_getres", "get_mempolicy", "gettid", "getcpu", "fallocate", "memfd_create", "fstatat64", "newfstatat"]
        
        binaryReady = False
        libFileReady = False
        languageReady = False
        try:
            self.logger.debug("Checking cache in %s", tempOutputFolder)
            myFile = open(tempOutputFolder + "/" + C.BINTOLIBCACHE, 'r')    #We need to have the mapping between binaries and their libraries to analyze them
            myFile = open(tempOutputFolder + "/" + C.CACHE, 'r')
            binaryReady = True
            myFile = open(tempOutputFolder + "/" + C.LIBFILENAME, 'r')
            libFileReady = True
        #    myFile = open(tempOutputFolder + "/" + C.LANGFILENAME, 'r')
        #    languageReady = True
        except OSError as e:
            self.logger.info("Cache doesn't exist, must extract binaries and libraries")

        self.logger.debug("binaryReady: %s libFileReady: %s", str(binaryReady), str(libFileReady))


        myContainer = container.Container(self.imagePath, self.options, self.logger)
        self.containerName = myContainer.getContainerName()

        if ( not myContainer.pruneVolumes() ):
            self.logger.warning("Pruning volumes failed, storage may run out of space\n")
        returncode, out, err = util.runCommand("mkdir -p " + tempOutputFolder)
        if ( returncode != 0 ):
            self.logger.error("Failed to create directory: %s with error: %s", tempOutputFolder, err)
        else:
            self.logger.debug("Successfully created directory: %s", tempOutputFolder)

        ttr = 10
        logSleepTime = 60
        sysdigTotalRunCount = 3
        if ( binaryReady ):
            sysdigTotalRunCount = 1
        sysdigRunCount = 1

        if ( self.name == "softwareag-apigateway" ):
            logSleepTime = 60

        if ( self.name == "cirros" ):
            logSleepTime = 120
        
        binaryToLibraryDict = dict()
        psListAll = set()
        #myForkStat = forkstat.ForkStat(self.logger)
        mySysdig = sysdig.Sysdig(self.logger)
        #forkStatResult = myForkStat.runForkStatWithDuration("exec", ttr)

        self.logger.info("--->Starting MONITOR phase:")
        while ( sysdigRunCount <= sysdigTotalRunCount ):
            self.logger.debug("Trying to kill and delete container which might not be running in loop... Not a problem if returns error")
            str(myContainer.kill())
            str(myContainer.delete())
            self.logger.info("Running sysdig multiple times. Run count: %d from total: %d", sysdigRunCount, sysdigTotalRunCount)
            sysdigRunCount += 1
            #sysdigResult = mySysdig.runSysdigWithDurationWithContainer("execve", logSleepTime, myContainer.getContainerName())
            sysdigResult = mySysdig.runSysdigWithDuration("execve", logSleepTime)
            if ( not sysdigResult ):
                self.logger.error("Running sysdig with execve failed, not continuing for container: %s", self.name)
                self.logger.error("Please make sure sysdig is installed and you are running the script with root privileges. If problem consists please contact our support team.")
                self.errorMessage = "Running sysdig with execve failed"

            nowTime = datetime.now()
            if ( sysdigResult and myContainer.runWithoutSeccomp() ):#myContainer.run() ):
                self.status = True
                self.logger.info("Ran container sleeping for %d seconds to generate logs and extract execve system calls", logSleepTime)
                time.sleep(logSleepTime)
                originalLogs = myContainer.checkLogs()
                self.logger.debug("originalLog: %s", originalLogs)
                time.sleep(10)
                if ( not myContainer.checkStatus() ):
                    self.logger.warning("Container exited after running, trying to run in attached mode!")
                    self.logger.debug(str(myContainer.delete()))
                    if ( not myContainer.runInAttachedMode() ):
                        self.errorMessage = "Container didn't run in attached mode either, forfeiting!"
                        self.logger.error("Container didn't run in attached mode either, forfeiting!")
                        self.logger.error("There is a problem launching a container for %s. Please validate you can run the container without Confine. If so, contact our support team.", self.name)
                        self.logger.debug(str(myContainer.delete()))
                        return C.NOATTACH
                    else:
                        time.sleep(10)
                        if ( not myContainer.checkStatus() ):
                            self.errorMessage = "Container got killed after running in attached mode as well!"
                            self.logger.error("Container got killed after running in attached mode as well, forfeiting!")
                            self.logger.error("There is a problem launching a container for %s. Please validate you can run the container without Confine. If so, contact our support team.", self.name)
                            self.logger.debug(str(myContainer.kill()))
                            self.logger.debug(str(myContainer.delete()))
                            return C.CONSTOP
                self.runnable = True
                self.logger.debug("Ran container %s successfully, sleeping for %d seconds", self.name, ttr)
                time.sleep(ttr)
                self.logger.debug("Finished sleeping, extracting psNames for %s", self.name)
                self.logger.debug("Starting to identify running processes and required binaries and libraries through dynamic analysis.")

                if ( not binaryReady ):
                    psList = mySysdig.extractPsNames()

                    if ( not psList ):
                        self.logger.error("PS List is None from extractPsNames(). Retrying this container: %s", self.name)
                        self.logger.debug(str(myContainer.kill()))
                        self.logger.debug(str(myContainer.delete()))
                        self.errorMessage = "PS List is None from extractPsNames(), error in sysdig, retrying this container"
                        return C.SYSDIGERR
                    if ( len(psList) == 0 ):
                        self.logger.error("PS List is None from extractPsNames(). Retrying this container: %s", self.name)
                        self.logger.debug(str(myContainer.kill()))
                        self.logger.debug(str(myContainer.delete()))
                        self.errorMessage = "PS List is None from extractPsNames(), error in sysdig, retrying this container"
                        return C.NOPROCESS
                    self.logger.info("len(psList) from sysdig: %d", len(psList))
                    currPsList, binaryToLibraryDict = myContainer.extractLibsFromProc()
                    psList = psList.union(currPsList)
                    self.logger.debug("len(psList) after extracting proc list: %d", len(psList))
                    self.logger.debug("Container: %s PS List: %s", self.name, str(psList))
                    self.logger.debug("Container: %s extracted psList with %d elements", self.name, len(psList))
                    self.logger.debug("Entering not binaryReady")
                    if ( not util.deleteAllFilesInFolder(tempOutputFolder, self.logger) ):
                        self.logger.error("Failed to delete files in temporary output folder, exiting...")
                        self.errorMessage = "Failed to delete files in temporary output folder"
                        sys.exit(-1)

                    psListAll.update(psList)
                    self.logger.info("Container: %s extracted psList with %d elements", self.name, len(psListAll))
                    util.writeDictToFile(binaryToLibraryDict, tempOutputFolder + "/" + C.BINTOLIBCACHE)

        if ( self.status ):
            if ( not binaryReady ):
                self.logger.info("Container: %s PS List: %s", self.name, str(psListAll))
                self.logger.info("Starting to copy identified binaries and libraries (This can take some time...)")#Will try to copy from different paths. Some might not exist. Errors are normal.")
                if ( self.extractAllBinaries ):
                    psListAll.update(myContainer.extractAllBinaries())


                for binaryPath in psListAll:
                    if ( binaryPath.strip() != "" ):
                        myContainer.copyFromContainerWithLibs(binaryPath, tempOutputFolder)

                        if ( binaryToLibraryDict.get(binaryPath, None) ):
                            librarySet = binaryToLibraryDict[binaryPath]
                            self.logger.debug("binary: %s library set: %s", binaryPath, str(librarySet))
                            for libraryPath in librarySet:
                                myContainer.copyFromContainerWithLibs(libraryPath, tempOutputFolder)
                        else:
                            self.logger.debug("Binary: %s doesn't exist in binaryToLibraryDict", binaryPath)
                        #if ( not myContainer.copyFromContainerWithLibs(binaryPath, tempOutputFolder) ):
                        #    self.logger.error("Problem copying files from container!")
                binaryReady = True
                myFile = open(tempOutputFolder + "/" + C.CACHE, 'w')
                myFile.write("complete")
                myFile.flush()
                myFile.close()
                self.logger.info("Finished copying identified binaries and libraries")
                self.logger.info("<---Finished MONITOR phase\n")

            self.logger.debug(str(myContainer.kill()))
            self.logger.debug(str(myContainer.delete()))

            if ( binaryReady ):
                self.logger.info("--->Starting Direct Syscall Extraction")
                self.logger.info("Extracting direct system call invocations")
                directSyscallSet = self.extractDirectSyscalls(tempOutputFolder)
                self.logger.info("<---Finished Direct Syscall Extraction\n")
                if ( not libFileReady ):
                    self.logger.info("--->Starting ANALYZE phase")
                    self.logger.info("Extracting imported functions and storing in libs.out")
                    self.extractAllImportedFunctions(tempOutputFolder, C.LIBFILENAME)
                    self.logger.info("<---Finished ANALYZE phase\n")
                #if ( not languageReady ):
                self.extractBinaryType(tempOutputFolder)
                isMusl = self.usesMusl(tempOutputFolder)
                funcFilePath = tempOutputFolder + "/" + C.LIBFILENAME
                funcFile = open(funcFilePath, 'r')
                funcLine = funcFile.readline()
                if ( not funcLine and not os.path.isfile(os.path.join(self.goFolderPath, self.name + ".syscalls")) and len(directSyscallSet) == 0 ):
                    self.logger.info("%s container can't be hardened because no functions can be extracted from binaries and no direct syscalls found", self.name)
                    self.errorMessage = "container can't be hardened because no functions can be extracted from binaries and no direct syscalls found"
                    return C.NOFUNCS


                self.logger.info("--->Starting INTEGRATE phase, extracting the list required system calls")
                functionStartsOriginal = set()
                functionStartsOriginal.update(piecewise.Piecewise.libcStartNodes)
                # functionStartsFineGrain = set()

                funcFile.seek(0)
                funcLine = funcFile.readline()
                while ( funcLine ):
                    funcLine = funcLine.strip()
                    functionStartsOriginal.add(funcLine)
                    funcLine = funcFile.readline()

                funcFile.close()

                binaryToLibraryDict = util.readDictFromFile(tempOutputFolder + "/" + C.BINTOLIBCACHE)

                allSyscallsFineGrain = set()
                binaryOnlySyscalls = set()

                if ( self.fineGrain ):
                    #TODO Fix fine grained analysis
                    #1. Create CFG for each library
                    #2. Extract leaves from all imported functions in libs.out 
                    #3. Create a list of required functions for each library
                    #4. Use fine grained version or all imported for libraries without CFG
                    self.logger.info("--->Starting Fine Grain Syscall Extraction")
                    binaryPaths = os.listdir(tempOutputFolder)
                    self.logger.info("self.name: %s", self.name)

                    existSet = set()
                    missingSet = set()

                    for binary in binaryPaths:
                        self.logger.info("binary/library: %s", binary)
                        if binary.strip() != "" and binary[0:3] != "lib" and ".so" not in binary:
                            self.logger.info("Binary: %s", binary)
                            binaryPath = tempOutputFolder + binary
                            startFunctions = self.extractAllImportedFunctionsFromBinary(tempOutputFolder, binary)
                            startFunctions.update(piecewise.Piecewise.libcStartNodes)
                            if ( isMusl ):
                                piecewiseObj = piecewise.Piecewise(binaryPath, "", self.muslCfgpath, self.cfgFolderPath, self.logger, cfginputseparator="->")
                            else:
                                piecewiseObj = piecewise.Piecewise(binaryPath, "", self.glibcCfgpath, self.cfgFolderPath, self.logger)
                            procLibrarySet = binaryToLibraryDict.get(binary, set())
                            procLibraryDict = util.convertLibrarySetToDict(procLibrarySet)
                            binarySyscalls= piecewiseObj.extractAccessibleSystemCallsFromBinary(startFunctions, altLibPath=os.path.abspath(tempOutputFolder), procLibraryDict=procLibraryDict)

                            binaryProfiler = binaryAnalysis.BinaryAnalysis(binaryPath, self.logger)
                            binaryDirectSyscallSet, successCount, failedCount  = binaryProfiler.extractDirectSyscalls()
                            if ( binaryDirectSyscallSet and len(binaryDirectSyscallSet) > 0 ):
                                binarySyscalls.update(binaryDirectSyscallSet)

                            allSyscallsFineGrain.update(binarySyscalls)
                            if binary in self.imageBinaryFiles:
                                binaryOnlySyscalls.update(binarySyscalls)
                        else:
                            self.logger.info("Skipped library: %s", binary)

                    self.logger.info("Extracted fine grain syscalls: %s", str(allSyscallsFineGrain))
                    self.logger.info("<---Finished Direct Syscall Extraction\n")

                    # libsWithCfg = set()
                    # libsInLibc = set()
                    # for fileName in os.listdir(self.cfgFolderPath):
                    #     libsWithCfg.add(fileName)

                    # libsInLibc.add("libcrypt.callgraph.out")
                    # libsInLibc.add("libdl.callgraph.out")
                    # libsInLibc.add("libnsl.callgraph.out")
                    # libsInLibc.add("libnss_compat.callgraph.out")
                    # libsInLibc.add("libnss_files.callgraph.out")
                    # libsInLibc.add("libnss_nis.callgraph.out")
                    # libsInLibc.add("libpthread.callgraph.out")
                    # libsInLibc.add("libm.callgraph.out")
                    # libsInLibc.add("libresolv.callgraph.out")
                    # libsInLibc.add("librt.callgraph.out")
                    # libsInLibc.add("libutil.callgraph.out")
                    # libsInLibc.add("libnss_dns.callgraph.out")

                    # cfgAvailable = False
                    # for fileName in os.listdir(tempOutputFolder):
                    #     self.logger.debug("fileName: %s", fileName)
                    #     tmpFileName = fileName
                    #     functionList = set()
                    #     if ( fileName.startswith("lib") and fileName != "libs.out"):
                    #         cfgAvailable = True
                    #         tmpFileName = re.sub("-.*so",".so",fileName)
                    #         tmpFileName = tmpFileName[:tmpFileName.index(".so")]
                    #         tmpFileName = tmpFileName + ".callgraph.out"
                    #         self.logger.debug("tmpFileName: %s", tmpFileName)
                    #     if ( tmpFileName in libsWithCfg ):
                    #         tmpGraph = graph.Graph(self.logger)
                    #         tmpGraph.createGraphFromInput(self.cfgFolderPath + "/" + tmpFileName, "->")
                    #         funcFile.seek(0)
                    #         funcLine = funcFile.readline()
                    #         while ( funcLine ):
                    #             funcName = funcLine.strip()
                    #             leaves = tmpGraph.getLeavesFromStartNode(funcName, list(), list())
                    #             if ( len(leaves) != 0 and funcName not in leaves ):
                    #                 #self.logger.debug("funcName: %s leaves: %s", funcName, str(leaves))
                    #                 functionList.update(set(leaves))
                    #             funcLine = funcFile.readline()
                    #     elif ( tmpFileName in libsInLibc ):
                    #         continue
                    #     else:
                    #         self.logger.info("Adding function starts for %s", fileName)
                    #         functionList = util.extractImportedFunctions(tempOutputFolder + "/" + fileName, self.logger)
                    #         if ( not functionList ):
                    #             self.logger.warning("Function extraction for file: %s failed!", fileName)
                    #     functionStartsFineGrain.update(set(functionList))

                self.logger.info("Traversing libc call graph to identify required system calls")
                tmpSet = set()
                allSyscallsOriginal = set()
                for function in functionStartsOriginal:
                    if ( isMusl ):
                        leaves = muslGraph.getLeavesFromStartNode(function, muslSyscallList, list())
                    else:
                        leaves = glibcGraph.getLeavesFromStartNode(function, glibcSyscallList, list())
                    if ( "syscall( 318 )" in leaves ):
                        self.logger.debug("function: %s, leaves: %s", function, leaves)
                    tmpSet = tmpSet.union(leaves)
                for syscallStr in tmpSet:
                    syscallStr = syscallStr.replace("syscall( ", "syscall(")
                    syscallStr = syscallStr.replace("syscall ( ", "syscall(")
                    syscallStr = syscallStr.replace(" )", ")")
                    syscallNum = int(syscallStr[8:-1])
                    allSyscallsOriginal.add(syscallNum)


                self.logger.debug("allSyscallsOriginal: %s", str(allSyscallsOriginal))
                # allSyscallsFineGrain = set()
                # if ( self.fineGrain ):
                #     tmpSet = set()
                #     for function in functionStartsFineGrain:
                #         #if ( function == "fork" ):
                #         #    self.logger.debug("/////////////////////////////////////////FORK has been found///////////////////////////////////")
                #         if ( isMusl ):
                #             leaves = muslGraph.getLeavesFromStartNode(function, muslSyscallList, list())
                #         else:
                #             leaves = glibcGraph.getLeavesFromStartNode(function, glibcSyscallList, list())
                #         tmpSet = tmpSet.union(leaves)
                #     for syscallStr in tmpSet:
                #         syscallStr = syscallStr.replace("syscall( ", "syscall(")
                #         syscallStr = syscallStr.replace("syscall ( ", "syscall(")
                #         syscallStr = syscallStr.replace(" )", ")")
                #         syscallNum = int(syscallStr[8:-1])
                #         allSyscallsFineGrain.add(syscallNum)


                #Check if we have go syscalls
                staticSyscallList = []
                try:
                    staticSyscallListFile = open(os.path.join(self.goFolderPath, self.name + ".syscalls"), 'r')
                    syscallLine = staticSyscallListFile.readline()
                    while ( syscallLine ):
                        staticSyscallList.append(int(syscallLine.strip()))
                        syscallLine = staticSyscallListFile.readline()
                    allSyscallsFineGrain.update(staticSyscallList)
                    binaryOnlySyscalls.update(staticSyscallList)
                except Exception as e:
                    self.logger.debug("Can't extract syscalls from: %s", os.path.join(self.goFolderPath, self.name + ".syscalls (probably not a golang developed application)"))
                self.logger.debug("After reading file: %s len(staticSyscallList): %d", os.path.join(self.goFolderPath, self.name + ".syscalls"), len(staticSyscallList))

                syscallMapper = syscall.Syscall(self.logger)
                syscallMap = syscallMapper.createMap()

                self.logger.info("Generating final system call filter list")
                denyListOriginal = []

                i = 1
                while i < 400:
                    if ( (self.directSyscallCount == 0 and self.libcSyscallCount == 0) or (isMusl and i in muslWrapperList) or (i in glibcWrapperList) ):
                        if ( i not in directSyscallSet and i not in staticSyscallList and i not in allSyscallsOriginal and syscallMap.get(i, None) and syscallMap[i] not in exceptList):
                            if ( ("Java" in self.languageSet and syscallMap[i] not in javaExceptList) or ("Java" not in self.languageSet) ):
                                self.logger.debug("syscallMap[%d]: %s", i, syscallMap[i])
                                denyListOriginal.append(syscallMap[i])
                    i += 1

                denyListFineGrain = []
                if ( self.fineGrain ):
                    i = 1
                    while i < 400:
                        if ( (self.directSyscallCount == 0 and self.libcSyscallCount == 0) or (isMusl and i in muslWrapperList) or (i in glibcWrapperList) ):
                            if ( i not in directSyscallSet and i not in staticSyscallList and i not in allSyscallsFineGrain and syscallMap.get(i, None) and syscallMap[i] not in exceptList):
                                if ( ("Java" in self.languageSet and syscallMap[i] not in javaExceptList) or ("Java" not in self.languageSet) ):
                                    denyListFineGrain.append(syscallMap[i])
                        i += 1

                self.logger.info("************************************************************************************")
                self.logger.info("Container Name: %s Num of filtered syscalls (original): %s", self.name, str(len(denyListOriginal)))

                # allSyscallsOriginalMapped = set()
                # for syscall_num in allSyscallsOriginal:
                #     allSyscallsOriginalMapped.add(syscallMap[syscall_num])
                # all_syscalls = set(syscallMap.values())

                # self.logger.info("All syscalls original: %s", str(all_syscalls.difference(set(denyListOriginal))))
                self.logger.info("************************************************************************************")
                self.logger.info("<---Finished INTEGRATE phase\n")

                self.denySyscallsOriginal = denyListOriginal
                self.denySyscallOriginalCount = len(denyListOriginal)

                seccompProfile = seccomp.Seccomp(self.logger)
                seccompCProgramPath = None
                dockerStartArgsStr = None

                if ( self.fineGrain ):
                    self.logger.info("Container Name: %s Num of filtered syscalls (fine grained): %s", self.name, str(len(denyListFineGrain)))
                    # self.logger.info("denylistFineGrain - denyListOriginal: %s", str(set(denyListFineGrain).difference(set(denyListOriginal))))
                    # self.logger.info("Fine Grain filtered syscalls: %s", str(set(denyListFineGrain)))
                    binaryOnlySyscallNames = set()
                    for syscall_num in binaryOnlySyscalls:
                        self.logger.debug("binaryOnlySyscall: %d", syscall_num)
                        if ( syscallMap.get(syscall_num, None) ):
                            binaryOnlySyscallNames.add(str(syscallMap[syscall_num]))
                        else:
                            self.logger.error("fine-grained syscall extraction: non-valid system call number is being extracted. this should not happen! %d", syscall_num)
                    # self.logger.info("%s syscalls: %s", self.name, str(binaryOnlySyscallNames))
                    # self.logger.info(self.imageBinaryFiles)

                    # generate denylist and seccomp profile for more restrictive filter
                    denyListBinaryFineGrain = []
                    i = 1
                    while i < 400:
                        if i not in binaryOnlySyscalls and syscallMap.get(i, None) and syscallMap[i] not in binExceptList:# and syscallMap[i] not in exceptList:       #exceptList was used only for the Docker initialization, it shouldn't be needed for the serving phase
                            if ( ("Java" in self.languageSet and syscallMap[i] not in javaExceptList) or ("Java" not in self.languageSet) ):
                                denyListBinaryFineGrain.append(syscallMap[i])
                        i += 1
                    self.logger.info("%s binary profile denylist: %s", self.name, str(len(denyListBinaryFineGrain)))

                    self.denySyscallsRestrictive = denyListBinaryFineGrain
                    self.denySyscallRestrictiveCount = len(denyListBinaryFineGrain)

                    denyListBinaryProfile = seccompProfile.createProfile(denyListBinaryFineGrain)
                    if ( "/" in self.name ):
                        outputPath = resultsFolder + "/" + self.name.replace("/", "-") + ".restrictive.seccomp.json"
                    else:
                        outputPath = resultsFolder + "/" + self.name + ".restrictive.seccomp.json"
                    outputFile = open(outputPath, 'w')
                    outputFile.write(denyListBinaryProfile)
                    outputFile.flush()
                    outputFile.close()

                    # generate C program that installs the more restrictive seccomp filter
                    if ( "/" in self.name ):
                        outputPath = resultsFolder + "/" + self.name.replace("/", "-") + "-seccomp.c"
                    else:
                        outputPath = resultsFolder + "/" + self.name + "-seccomp.c"
                    seccompCProgramPath = outputPath
                    outputFile = open(outputPath, 'w')
                    seccompTemplate = open("./seccomp-program/seccomp-deny-1.txt", 'r')
                    for line in seccompTemplate:
                        outputFile.write(line)
                    seccompTemplate.close()

                    # add allowed syscalls
                    for syscall_name in denyListBinaryFineGrain:#binaryOnlySyscallNames:
                        outputFile.write(f"Kill({syscall_name}),\n\t")
                        #outputFile.write(f"Allow({syscall_name}),\n\t")

                    seccompTemplate = open("./seccomp-program/seccomp-deny-2.txt", 'r')
                    for line in seccompTemplate:
                        outputFile.write(line)
                    seccompTemplate.close()

                    dockerStartArgsStr = ""
                    for arg in self.dockerStartArgs:
                        outputFile.write(f"\"{arg}\", ")
                        dockerStartArgsStr += arg + " "
                    outputFile.write(f" NULL}};\n\texecv(\"{self.dockerPath}\", args);\n}}\n")

                    outputFile.flush()
                    outputFile.close()

                    self.denySyscallsFineGrain = denyListFineGrain
                    self.denySyscallFineGrainCount = len(denyListFineGrain)

                if ( self.fineGrain ):
                    denyListFineGrainProfile = seccompProfile.createProfile(denyListFineGrain)
                denyListProfile = seccompProfile.createProfile(denyListOriginal)
                if ( "/" in self.name ):
                    outputFineGrainPath = resultsFolder + "/" + self.name.replace("/", "-") + ".finegrain.seccomp.json"
                    outputPath = resultsFolder + "/" + self.name.replace("/", "-") + ".seccomp.json"
                else:
                    outputFineGrainPath = resultsFolder + "/" + self.name + ".finegrain.seccomp.json"
                    outputPath = resultsFolder + "/" + self.name + ".seccomp.json"
                outputFile = open(outputPath, 'w')
                outputFile.write(denyListProfile)
                outputFile.flush()
                outputFile.close()
                seccompPath = outputPath
                if ( self.fineGrain ):
                    seccompPath = outputFineGrainPath
                    outputFineGrainFile = open(outputFineGrainPath, 'w')
                    outputFineGrainFile.write(denyListFineGrainProfile)
                    outputFineGrainFile.flush()
                    outputFineGrainFile.close()
                self.logger.info("--->Validating generated Seccomp profile: %s", seccompPath)
                myRestrictedContainer = None
                if ( myContainer.runWithSeccompProfile(seccompPath) ):
                    time.sleep(logSleepTime)
                    debloatedLogs = myContainer.checkLogs()
                    #if ( len(originalLogs) == len(debloatedLogs) ):
                    if ( len(originalLogs) == len(debloatedLogs) or ( len(originalLogs) > len(debloatedLogs) and len(debloatedLogs) >= (0.99*len(originalLogs)) ) or ( len(debloatedLogs) > len(originalLogs) and len(originalLogs) >= (0.99*len(originalLogs)) ) ):
                        time.sleep(3)
                        if ( myContainer.checkStatus() ):
                            self.logger.info("************************************************************************************")
                            self.logger.info("Finished validation. Container for image: %s was hardened SUCCESSFULLY!", self.name)
                            self.logger.info("************************************************************************************")
                            self.debloatStatus = True
                            self.restrictedDebloatStatus = False
                            returnCode = 0

                            # TODO validate the more restrictive filter here
                            # create a new container object (with args)
                            # modify docker-entrypoint.sh (automatically?)
                            # create seccomp binary (automatically?)
                            # launch container

                            if ( seccompCProgramPath ):
                                cProgramStatus = False
                                entrypointStatus = False
                                if ( not os.path.isfile(os.path.join(tempOutputFolder, C.SECCOMPCPROG)) ):
                                    cProgramStatus = self.compileSeccompCProgram(seccompCProgramPath, os.path.join(tempOutputFolder, C.SECCOMPCPROG))
                                else:
                                    cProgramStatus = True
    
                                if ( cProgramStatus ):
                                    entrypointStatus = False
                                    if ( self.dockerEntryPointModify and not os.path.isfile(os.path.join(tempOutputFolder, C.DOCKERENTRYSCRIPTMODIFIED) ) ):
                                        if ( self.dockerEntryPoint == "" ):
                                            self.createDockerEntryPointFromTemplate(tempOutputFolder, C.DOCKERENTRYSCRIPT)
                                        if ( os.path.isfile(os.path.join(tempOutputFolder, self.dockerEntryPoint)) ):
                                            entrypointStatus = self.generateModifiedEntrypointScript(tempOutputFolder + self.dockerEntryPoint, tempOutputFolder + C.DOCKERENTRYSCRIPTMODIFIED, C.SECCOMPCPROG)
                                        else:
                                            self.logger.warning("Docker image does not seem to have entrypoint.sh")
                                            entrypointStatus = False
                                    else:
                                        entrypointStatus = True

                                    dockerEntryPointPath = ""
                                    if ( self.dockerEntryPointModify ):
                                        dockerEntryPointFileName = C.DOCKERENTRYSCRIPTMODIFIED
                                    else:
                                        dockerEntryPointFileName = self.dockerEntryPoint
                            
                                    if ( entrypointStatus ):
                                        restrictiveOptions = self.generateRestrictiveOptions(tempOutputFolder, dockerEntryPointFileName)
                                        myRestrictedContainer = container.Container(self.imagePath, restrictiveOptions, self.logger, remote=None, args=dockerStartArgsStr)
                                        self.logger.info("--->Validating more restrictive Seccomp profile: %s", seccompCProgramPath)
                                        self.logger.info("Killing and deleting fine-grained hardened container")
                                        myContainer.kill()
                                        myContainer.delete()
                                        if ( myRestrictedContainer.runWithSeccompProfile(seccompPath) ):
                                            time.sleep(logSleepTime)
                                            restrictedLogs = myRestrictedContainer.checkLogs()
                                            restrictedLogs = restrictedLogs.replace("/home/confine/docker-entrypoint.wseccomp.sh", "/docker-entrypoint.sh")
                                            if ( len(originalLogs) == len(restrictedLogs) or ( len(originalLogs) > len(restrictedLogs) and len(restrictedLogs) >= (0.99*len(originalLogs)) ) or ( len(restrictedLogs) > len(originalLogs) and len(originalLogs) >= (0.99*len(originalLogs)) ) ):
                                                time.sleep(3)
                                                if ( myRestrictedContainer.checkStatus() ):
                                                    self.logger.info("************************************************************************************")
                                                    self.logger.info("Finished more restricted validation. Container for image: %s was hardened SUCCESSFULLY!", self.name)
                                                    self.logger.info("************************************************************************************")
                                                    self.restrictedDebloatStatus = True
                                                    returnCode = 0
                                                else:
                                                    self.logger.warning("Container for image: %s was hardened with problems. Dies after running!", self.name)
                                                    self.errorMessage= "Container was hardened with problems. Dies after running!"
                                                    self.restrictedDebloatStatus = False
                                                    returnCode = C.HSTOPS
                                            else:
                                                self.logger.warning("Container for image: %s was hardened (more restrictively) with problems: len(original): %d len(seccomp): %d original: %s seccomp: %s", self.name, len(originalLogs), len(restrictedLogs), originalLogs, restrictedLogs)
                                                self.errorMessage = "Unknown problem in hardening (more restrictive) container!"
                                                self.restrictedDebloatStatus = False
                                                returnCode = C.HLOGLEN
                                        else:
                                            self.errorMessage = "Unknown problem in hardening container!"
                                            self.logger.warning(self.errorMessage)
                                            self.restrictedDebloatStatus = False
                                            returnCode = C.HNORUN
                                    else:
                                        self.logger.warning("docker-entrypoint.wseccomp.sh has not been created, skipping the validation check of the more restrictive filters")
                                else:
                                    self.logger.warning("seccomp C program has not been created, skipping the validation check of the more restrictive filters")
                            else:
                                self.logger.warning("seccomp C program path not set, supposing not enabled, skipping more restrictive validation")
                        else:
                            self.logger.warning("Container for image: %s was hardened with problems. Dies after running!", self.name)
                            self.errorMessage= "Container was hardened with problems. Dies after running!"
                            returnCode = C.HSTOPS
                    else:
                        self.logger.warning("Container for image: %s was hardened with problems: len(original): %d len(seccomp): %d original: %s seccomp: %s", self.name, len(originalLogs), len(debloatedLogs), originalLogs, debloatedLogs)
                        self.errorMessage = "Unknown problem in hardening container!"
                        returnCode = C.HLOGLEN
                    if ( self.isDependent ):
                        self.logger.info("Not killing container: %s because it is a dependent for hardening another container", self.name)
                    elif ( myRestrictedContainer ):
                        if ( not myRestrictedContainer.kill() and self.restrictedDebloatStatus ):
                            self.logger.warning("Restricted container can't be killed even though successfully hardened! Hardening has been unsuccessfull!")
                            self.errorMessage = "Restricted container can't be killed even though successfully hardened! Hardening has been unsuccessfull!"
                            self.restrictedDebloatStatus = False
                            returnCode = C.HNOKILL
                    else:
                        if ( not myContainer.kill() and self.debloatStatus ):
                            self.logger.warning("Container can't be killed even though successfully hardened! Hardening has been unsuccessfull!")
                            self.errorMessage = "Container can't be killed even though successfully hardened! Hardening has been unsuccessfull!"
                            self.debloatStatus = False
                            returnCode = C.HNOKILL
                else:
                    self.errorMessage = "Unknown problem in hardening container!"
                    returnCode = C.HNORUN
                if ( not self.isDependent ):
                    if ( myRestrictedContainer ):
                        self.logger.debug(str(myRestrictedContainer.delete()))
                    else:
                        self.logger.debug(str(myContainer.delete()))
        return returnCode

    def createDockerEntryPointFromTemplate(self, outputPath, fileName):
        cmd = "cp {} {}"
        cmd = cmd.format(self.dockerTemplateEntryPoint, outputPath + "/" + fileName)
        self.logger.debug("generating Docker entrypoint from template: %s", cmd)
        returncode, out, err = util.runCommand(cmd)
        if ( returncode != 0 ):
            self.logger.error("Error generating docker entrypoint: %s", err)
            return False
        self.dockerEntryPoint = fileName
        return True

    def compileSeccompCProgram(self, inputPath, outputPath):
        cmd = "gcc -static -o {} {}"
        cmd = cmd.format(outputPath, inputPath)
        self.logger.debug("generating Seccomp C program using command: %s", cmd)
        returncode, out, err = util.runCommand(cmd)
        if ( returncode != 0 ):
            self.logger.error("Error generating seccomp C program: %s", err)
            return False
        return True

    def generateModifiedEntrypointScript(self, inputPath, outputPath, cProgramFileName):
        pathInContainer = "/home/confine"
        cProgramPath = pathInContainer + "/" + cProgramFileName
        cProgramPath = cProgramPath.replace("/", "\/")
        cmd = "sed 's/exec \"$@\"/" + cProgramPath + "/g' " + inputPath + " >> " + outputPath
        self.logger.debug("modifying entrypoint using command: %s", cmd)
        returncode, out, err = util.runCommand(cmd)
        if ( returncode != 0 ):
            self.logger.error("Error modifying the docker-entrypoint.sh script: %s", err)
            return False

        cmd = "sudo chmod +x {}"
        cmd = cmd.format(outputPath)
        returncode, out, err = util.runCommand(cmd)
        if ( returncode != 0 ):
            self.logger.error("Error modifying the docker-entrypoint.wseccomp.sh permission: %s", err)
            return False
        return True

    def generateRestrictiveOptions(self, tempOutputFolder, entrypointScriptFileName):
        #sudo docker run -v /library/path/in/local/:/home/test -td --entrypoint /home/test/docker-entrypoint.sh nginx
        pathInContainer = "/home/confine"
        entrypointScriptPath = pathInContainer + "/" + entrypointScriptFileName
        tempOutputFolder = os.getcwd() + "/" + tempOutputFolder
        options = self.options
        options = options + " -v {}:{} " + " --entrypoint {}"
        options = options.format(tempOutputFolder, pathInContainer, entrypointScriptPath)
        self.logger.debug("using restrictive options to run container: %s", options)
        return options

    def createFineGrainedSeccompProfile(self, tempOutputFolder, resultsFolder):
        self.logger.debug("tempOutputFolder: %s", tempOutputFolder)

        allSyscalls = set()

        muslSyscallList = list()
        glibcSyscallList = list()

        i = 0
        while i < 400:
            muslSyscallList.append("syscall(" + str(i) + ")")
            glibcSyscallList.append("syscall(" + str(i) + ")")
            glibcSyscallList.append("syscall ( " + str(i) + " )")
            glibcSyscallList.append("syscall( " + str(i) + " )")
            i += 1

        glibcGraph = graph.Graph(self.logger)
        glibcGraph.createGraphFromInput(self.glibcCfgpath, ":")
        glibcWrapperListTemp = []
        if ( self.strictMode ):
            for func in self.glibcFuncList:
                glibcWrapperListTemp.extend(glibcGraph.getSyscallFromStartNode(func))
        else:
            i = 0
            while i < 400:
                glibcWrapperListTemp.append(i)
                i += 1
        glibcWrapperList = set(glibcWrapperListTemp)
        muslGraph = graph.Graph(self.logger)
        muslGraph.createGraphFromInput(self.muslCfgpath, "->")
        muslWrapperListTemp = []
        if ( self.strictMode ):
            for func in self.muslFuncList:
                muslWrapperListTemp.extend(muslGraph.getSyscallFromStartNode(func))
        else:
            i = 0
            while i < 400:
                muslWrapperListTemp.append(i)
                i += 1
        muslWrapperList = set(muslWrapperListTemp)

#        self.logger.debug("glibcWrapperList: %s", str(glibcWrapperList))
#        self.logger.debug("muslWrapperList: %s", str(muslWrapperList))

        #Go through extra CFGs such as libaio to extract lib->syscall mapping
        for fileName in os.listdir(self.cfgFolderPath):
            self.logger.debug("Adding cfg: %s", fileName)
            glibcGraph.createGraphFromInput(self.cfgFolderPath + "/" + fileName, "->")
            muslGraph.createGraphFromInput(self.cfgFolderPath + "/" + fileName, "->")

        exceptList = ["access","arch_prctl","brk","close","execve","exit_group","fcntl","fstat","geteuid","lseek","mmap","mprotect","munmap","openat","prlimit64","read","rt_sigaction","rt_sigprocmask","set_robust_list","set_tid_address","stat","statfs","write","setns","capget","capset","chdir","fchown","futex","getdents64","getpid","getppid","lstat","openat","prctl","setgid","setgroups","setuid","stat","io_setup","getdents","clone","readlinkat","newfstatat","getrandom","sigaltstack","getresgid","getresuid","setresgid","setresuid","alarm","getsid","getpgrp", "epoll_pwait", "vfork"]

        javaExceptList = ["open", "getcwd", "openat", "close", "fopen", "fclose", "link", "unlink", "unlinkat", "mknod", "rename", "renameat", "mkdir", "rmdir", "readlink", "realpath", "symlink", "stat", "lstat", "fstat", "fstatat", "chown", "lchown", "fchown", "chmod", "fchmod", "utimes", "futimes", "lutimes", "readdir", "read", "write", "access", "getpwuid", "getgrgid", "statvfs", "clock_getres", "get_mempolicy", "gettid", "getcpu", "fallocate", "memfd_create", "fstatat64", "newfstatat"]


        libsWithCfg = set()
        libsInLibc = set()
        functionStarts = set()
        for fileName in os.listdir(self.cfgFolderPath):
            libsWithCfg.add(fileName)

        libsInLibc.add("libcrypt.callgraph.out")
        libsInLibc.add("libdl.callgraph.out")
        libsInLibc.add("libnsl.callgraph.out")
        libsInLibc.add("libnss_compat.callgraph.out")
        libsInLibc.add("libnss_files.callgraph.out")
        libsInLibc.add("libnss_nis.callgraph.out")
        libsInLibc.add("libpthread.callgraph.out")
        libsInLibc.add("libm.callgraph.out")
        libsInLibc.add("libresolv.callgraph.out")
        libsInLibc.add("librt.callgraph.out")

        #iterate over ELF files
        #IF library which has CFG add to graph
        #ELIF binary or library without CFG add to starting nodes
        cfgAvailable = False
        for fileName in os.listdir(tempOutputFolder):
            self.logger.debug("fileName: %s", fileName)
            if ( fileName.startswith("lib") and fileName != "libs.out"):
                cfgAvailable = True
                tmpFileName = re.sub("-.*so",".so",fileName)
                tmpFileName = tmpFileName[:tmpFileName.index(".so")]
                tmpFileName = tmpFileName + ".callgraph.out"
                self.logger.debug("tmpFileName: %s", tmpFileName)
                if ( tmpFileName in libsWithCfg ):
                    glibcGraph.createGraphFromInput(self.cfgFolderPath + "/" + tmpFileName, "->")
                elif ( tmpFileName in libsInLibc ):
                    cfgAvailable = True
                else:
                    cfgAvailable = False
            if ( not fileName.startswith("lib") or not cfgAvailable ):
                self.logger.info("Adding function starts for %s", fileName)
                functionList = util.extractImportedFunctions(tempOutputFolder + "/" + fileName, self.logger)
                if ( not functionList ):
                    self.logger.warning("Function extraction for file: %s failed!", fileName)
                functionStarts.update(set(functionList))

        tmpSet = set()
        allSyscalls = set()
        for function in functionStarts:
            leaves = glibcGraph.getLeavesFromStartNode(function, glibcSyscallList, list())
            tmpSet = tmpSet.union(leaves)
        syscallList = list()
        for syscallStr in tmpSet:
            syscallStr = syscallStr.replace("syscall( ", "syscall(")
            syscallStr = syscallStr.replace("syscall ( ", "syscall(")
            syscallStr = syscallStr.replace(" )", ")")
            syscallNum = int(syscallStr[8:-1])
            allSyscalls.add(syscallNum)

        syscallMapper = syscall.Syscall(self.logger)
        syscallMap = syscallMapper.createMap()
        denyList = set()
        i = 0
        while i < 400:
            if ( i not in allSyscalls and syscallMap.get(i, None) and syscallMap[i] not in exceptList):
                denyList.add(syscallMap[i])
            i += 1


        self.logger.info("Results for %s:///////////////////////////////////", self.name)
        self.logger.info("%s: len(denylist): %d", self.name, len(denyList))
        self.logger.info("%s: denylist: %s", self.name, str(denyList))
        self.logger.info("//////////////////////////////////////////////////////////////////")
