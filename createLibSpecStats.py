import os, sys, subprocess, signal
import logging
import optparse
import re
import constants as C

sys.path.insert(0, './python-utils/')

import util

def isValidOpts(opts):
    if ( not opts.binaryfolder or not opts.callgraphpath ):
        parser.error("All options --binaryfolder, --callgraphpath should be provided.")
        return False

    return True

def cleanLib(libName, logger):
    if ( ".so" in libName ):
        libName = re.sub("-.*so",".so",libName)
        libName = libName[:libName.index(".so")]
        #libName = libName + ".so"
    return libName


def setLogPath(logPath):
    """
    Set the property of the logger: path, config, and format
    :param logPath:
    :return:
    """
    if os.path.exists(logPath):
        os.remove(logPath)

    rootLogger = logging.getLogger("coverage")
    if options.debug:
        logging.basicConfig(filename=logPath, level=logging.DEBUG)
        rootLogger.setLevel(logging.DEBUG)
    else:
        logging.basicConfig(filename=logPath, level=logging.INFO)
        rootLogger.setLevel(logging.INFO)

#    ch = logging.StreamHandler(sys.stdout)
    consoleHandler = logging.StreamHandler()
    rootLogger.addHandler(consoleHandler)
    return rootLogger
#    rootLogger.addHandler(ch)

if __name__ == '__main__':
    """
    Find system calls for function
    """
    usage = "Usage: %prog --binarypath <Binary Path> --binarycfgpath <Binary call graph> --libccfgpath <Libc call graph path> --otherlibcfgpath <Path to folder containing other libraries' cfg>"

    parser = optparse.OptionParser(usage=usage, version="1")

    parser.add_option("", "--binaryfolder", dest="binaryfolder", default=None, nargs=1,
                      help="Path to folder which holds binaries and libraries for containers")

    parser.add_option("", "--callgraphpath", dest="callgraphpath", default="libs.uniq.cdf", nargs=1,
                      help="Path to callgraph files")

    parser.add_option("-d", "--debug", dest="debug", action="store_true", default=False,
                      help="Debug enabled/disabled")

    (options, args) = parser.parse_args()
    if isValidOpts(options):
        rootLogger = setLogPath("createlibspecstats.log")

        libcRelatedList = ["ld", "libc", "libdl", "libcrypt", "libnss_compat", "libnsl", "libnss_files", "libnss_nis", "libpthread", "libm", "libresolv", "librt", "libutil", "libnss_dns"]
        libaprRelatedList = ["libapr", "libaprutil"]

        folderToMainBin = dict()
        folderToMainBin["httpd"] = "httpd"
        folderToMainBin["ghost"] = "node"
        folderToMainBin["logstash"] = "java"
        folderToMainBin["mariadb"] = "mariadbd"
        folderToMainBin["memcached"] = "memcached"
        folderToMainBin["mongo"] = "mongod"
        folderToMainBin["mysql"] = "mysqld"
        folderToMainBin["nextcloud"] = "apache2"
        folderToMainBin["nginx"] = "nginx"
        folderToMainBin["node"] = "node"
        folderToMainBin["postgres"] = "postgres"
        folderToMainBin["redis"] = "redis-server"
        folderToMainBin["registry"] = "registry"
        folderToMainBin["telegraf"] = "telegraf"
        folderToMainBin["traefik"] = "traefik"

        hasCallgraph = 0
        noCallgraph = 0
        librarySet = set()

        folderList = os.listdir(options.binaryfolder)
        for folder in folderList:
            libraryList = os.listdir(options.binaryfolder + "/" + folder)
            for library in libraryList:
                #if ( library.startswith("lib") and "so" in library ):
                if ( ".so." in library or library.endswith(".so") ):
                    libraryName = cleanLib(library, rootLogger)
                    if ( libraryName not in librarySet and libraryName not in libcRelatedList and libraryName not in libaprRelatedList ):
                        librarySet.add(libraryName)
                        if ( os.path.isfile(options.callgraphpath + "/" + libraryName + ".callgraph.out") ):
                            hasCallgraph += 1
                        else:
                            rootLogger.debug("doesn't have callgraph: %s", libraryName)
                            noCallgraph += 1
        rootLogger.info("total: %d has callgraph: %d doesn't have callgraph: %d", len(librarySet), hasCallgraph, noCallgraph)

        rootLogger.info("imageName;binaryCount;allLibraryCount;mainLibraryCount")
        folderList = os.listdir(options.binaryfolder)
        for folder in folderList:
            getBinariesCommand = util.getCmdRetrieveAllBinaries(options.binaryfolder + "/" + folder)
            returncode, out, err = util.runCommand(getBinariesCommand)
            if ( returncode != 0 ):
                rootLogger.error("command: %s returned error: %s", getBinariesCommand, err)
            else:
                libraryList = os.listdir(options.binaryfolder + "/" + folder)
                librarySet = set()
                for library in libraryList:
                    #if ( (library.startswith("lib") and "so" in library) or (library.startswith("mod") and "so" in library) ):
                    if ( ".so." in library or library.endswith(".so") ):
                        libraryName = cleanLib(library, rootLogger)
                        if ( libraryName not in librarySet ):
                            librarySet.add(libraryName)
                rootLogger.debug("list of libraries: %s", str(librarySet))
                binariesAndLibraries = out.split("\n")
                binaries = set()
                for binOrLib in binariesAndLibraries:
                    binOrLib = binOrLib.split(":")[0]
                    if ( "/" in binOrLib ):
                        binOrLib = binOrLib[binOrLib.rindex("/")+1:]
                    binOrLibName = cleanLib(binOrLib, rootLogger)
                    if ( binOrLibName != "" and binOrLibName != "seccomp" and binOrLibName != "dumpe2fs" and binOrLibName not in librarySet ):
                        binaries.add(binOrLibName)
                        if ( binOrLibName == "sh" ):
                            librarySet.add("libc")
                            librarySet.add("linux-vdso")
                rootLogger.debug("list of binaries: %s", str(binaries))
                totalBinaries = len(binaries)
                mainBinLibs = set()
                if ( os.path.isfile(options.binaryfolder + "/" + folder + "/" + C.BINTOLIBCACHE) ):
                    binaryToLibraryDict = util.readDictFromFile(options.binaryfolder + "/" + folder + "/" + C.BINTOLIBCACHE)
                    mainBinaryLibraries = binaryToLibraryDict.get(folderToMainBin[folder], set())
                    rootLogger.debug("mainBinaryLibraries: %s", str(mainBinaryLibraries))
                    for mainBinaryLibrary in mainBinaryLibraries:
                        libName = mainBinaryLibrary
                        if ( "/" in libName ):
                            libName = libName[libName.rindex("/")+1:]
                        libName = cleanLib(libName, rootLogger)
                        if ( "[" not in libName ):
                            mainBinLibs.add(libName)
                        elif ( "libName" == "[vdso]" ):
                            mainBinLibs.add("linux-vdso")
                fixup = 0
                for library in librarySet:
                    if ( library not in mainBinLibs ):
                        fixup += 1
                rootLogger.debug(str(mainBinLibs))
                rootLogger.info(folder + ";" + str(len(binaries)) + ";" + str(len(librarySet)) + ";" + str(len(librarySet)-fixup))
