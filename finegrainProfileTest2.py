import os, sys, subprocess, signal
import logging
import optparse
import containerProfiler
import time
import json

sys.path.insert(0, './python-utils/')

import constants as C
import util

def isValidOpts(opts):
    """
    Check if the required options are sane to be accepted
        - Check if the provided files exist
        - Check if two sections (additional data) exist
        - Read all target libraries to be debloated from the provided list
    :param opts:
    :return:
    """
    if not options.input or not options.outputfolder or not options.reportfolder or not options.defaultprofile or not options.libccfginput or not options.muslcfginput or not options.gofolderpath or not options.cfgfolderpath:
        parser.error("All options -c, -i, -p, -r, -l, -f, -m, -n, -g, -c and -o should be provided.")
        return False

    return True


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
    Main function for finding physical memory usage of process
    """
    usage = "Usage: %prog -c <CFG input from libc> -i <Input containing list of docker images to run and debloat> -o <A temporary output folder to store intermediate results in>"

    parser = optparse.OptionParser(usage=usage, version="1")

    parser.add_option("-l", "--libccfginput", dest="libccfginput", default=None, nargs=1,
                      help="libc call function graph input")

    parser.add_option("-f", "--libcfuncpath", dest="libcfuncpath", default=None, nargs=1,
                      help="libc exported function list")

    parser.add_option("-m", "--muslcfginput", dest="muslcfginput", default=None, nargs=1,
                      help="musl call function graph input")

    parser.add_option("-n", "--muslfuncpath", dest="muslfuncpath", default=None, nargs=1,
                      help="musl exported function list")

    parser.add_option("-i", "--input", dest="input", default=None, nargs=1,
                      help="Input file containing list of image names to be debloated.")

    parser.add_option("-o", "--outputfolder", dest="outputfolder", default=None, nargs=1,
                      help="Output folder path")

    parser.add_option("-r", "--reportfolder", dest="reportfolder", default=None, nargs=1,
                      help="Report file path")

    parser.add_option("-p", "--defaultprofile", dest="defaultprofile", default=None, nargs=1,
                      help="Report file path")

    parser.add_option("-s", "--strictmode", dest="strictmode", default=False,
                      help="Enable strict mode")

    parser.add_option("-g", "--gofolder", dest="gofolderpath", default=None, nargs=1,
                      help="Golang system call folder path")

    parser.add_option("-c", "--cfgfolder", dest="cfgfolderpath", default=None, nargs=1,
                      help="Path to other cfg files")

    parser.add_option("-d", "--debug", dest="debug", action="store_true", default=False,
                      help="Debug enabled/disabled")

    (options, args) = parser.parse_args()
    if isValidOpts(options):
        rootLogger = setLogPath("finegrainedcontainerprofiler.log")

        glibcFuncList = None
        muslFuncList = None
        if ( options.strictmode ):
            #Read list of libc and musl functions
            glibcFuncList = util.extractAllFunctions(options.libcfuncpath, rootLogger)
            if ( not glibcFuncList ):
                rootLogger.error("Problem extracting list of functions from glibc")
                sys.exit(-1)
            muslFuncList = util.extractAllFunctions(options.muslfuncpath, rootLogger)
            if ( not muslFuncList ):
                rootLogger.error("Problem extracting list of functions from musl")
                sys.exit(-1)

        #Initialize results and output folder
        accessRights = 0o755
        reportFolder = options.reportfolder
        while ( reportFolder.endswith("/") ):
            reportFolder = reportFolder[:-1]
        if ( not os.path.exists(reportFolder) ):
            try:
                os.mkdir(reportFolder, accessRights)
            except OSError:
                rootLogger.error("There was a problem creating the results (-r) folder")
                sys.exit(-1)
        elif ( os.path.isfile(reportFolder) ):
            rootLogger.error("The folder specified for the results (-r) already exists and is a file. Please change the path or delete the file and re-run the script.")
            sys.exit(-1)

        outputFolder = options.outputfolder
        while ( outputFolder.endswith("/") ):
            outputFolder = outputFolder[:-1]
        if ( not os.path.exists(outputFolder) ):
            try:
                os.mkdir(outputFolder, accessRights)
            except OSError:
                rootLogger.error("There was a problem creating the output (-o) folder")
                sys.exit(-1)
        elif ( os.path.isfile(outputFolder) ):
            rootLogger.error("The folder specified for the output (-o) already exists and is a file. Please change the path or delete the file and re-run the script.")
            sys.exit(-1)

        # inputFile = open(options.input, 'r')
        # inputLine = inputFile.readline()
        try:
            inputFile = open(options.input, 'r')
            imageToPropertyStr = inputFile.read()
            imageToPropertyMap = json.loads(imageToPropertyStr)
        except Exception as e:
            rootLogger.error("Trying to load image list map json from: %s, but doesn't exist: %s", options.input, str(e))
            rootLogger.error("Exiting...")
            sys.exit(-1)

        retry = False
        finegrain = True
        allbinaries = True
        for imageKey, imageVals in imageToPropertyMap.items():
            imageName = imageVals.get("image-name", imageKey)
            imageNameFullPath = imageVals.get("image-url", None)
            imageOptions = imageVals.get("options", "")
            imageRank = imageVals.get("id", -1)
            imageCategoryList = imageVals.get("category", ["Other"])
            imageArgs = imageVals.get("args", "")
            imagePullCount = imageVals.get("pull-count", 0)
            imageOfficial = imageVals.get("official", False)
            imageBinaryCfgPath = imageVals.get("binary-cfg-path", "")
            

            start = time.time()
            newProfile = containerProfiler.ContainerProfiler(imageName, imageNameFullPath, imageOptions, options.libccfginput, options.muslcfginput, glibcFuncList, muslFuncList, options.strictmode, options.gofolderpath, options.cfgfolderpath, finegrain, allbinaries, imageBinaryCfgPath, rootLogger)
#                returncode = newProfile.createSeccompProfile(options.outputfolder + "/" + imageName + "/", options.reportfolder)
            returncode = newProfile.createFineGrainedSeccompProfile(options.outputfolder + "/" + imageName + "/", options.reportfolder)
            end = time.time()

            if ( returncode == C.SYSDIGERR and not retry ):
                retry = True
            else:
                retry = False

            if ( not retry ):
                inputLine = inputFile.readline()

        inputFile.close()