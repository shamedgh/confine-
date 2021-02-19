import os, sys, subprocess, signal
import logging
import optparse
import re

def isValidOpts(opts):
    if ( not opts.binaryfolder or not opts.imagelist or not opts.outputpath ):
        parser.error("All options --binaryfolder, --imagelist and --outputpath should be provided.")
        return False

    return True

def cleanLib(libName, logger):
    logger.debug("cleanLib libName input: %s", libName)
    if ( ".so" in libName ):
        libName = re.sub("-.*so",".so",libName)
        libName = libName[:libName.index(".so")]
        #libName = libName + ".so"
    logger.debug("cleanLib libName output: %s", libName)
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

    parser.add_option("", "--imagelist", dest="imagelist", default=None, nargs=1,
                      help="File with sorted list of images")

    parser.add_option("", "--outputpath", dest="outputpath", default="libs.uniq.cdf", nargs=1,
                      help="Path to store unique library CDF")

    parser.add_option("-d", "--debug", dest="debug", action="store_true", default=False,
                      help="Debug enabled/disabled")

    (options, args) = parser.parse_args()
    if isValidOpts(options):
        rootLogger = setLogPath("generatelibcdf.log")

        librarySet = set()
        outputFile = open(options.outputpath, 'w')
        imageListFile = open(options.imagelist, 'r')
        imageListLine = imageListFile.readline()

        while ( imageListLine ):
            splittedLine = imageListLine.split(";")
            imageName = splittedLine[1]
            imageFolder = options.binaryfolder + "/" + imageName + "/"
            if ( os.path.isdir(imageFolder) ):
                fileList = os.listdir(imageFolder)
                for fileName in fileList:
                    if ( fileName.startswith("lib") and "so" in fileName ):
                        rootLogger.debug("fileName before: %s", fileName)
                        fileName = cleanLib(fileName, rootLogger)
                        rootLogger.debug("fileName after: %s", fileName)
                        librarySet.add(fileName)
                outputFile.write(str(len(librarySet)) + "\n")
                outputFile.flush()

            imageListLine = imageListFile.readline()

        outputFile.close()
