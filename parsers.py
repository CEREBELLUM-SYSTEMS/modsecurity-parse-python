import re
import time

#   Part letter	    Description
#   A               Audit log header (mandatory)
#   B	            Request headers
#   C	            Request body
#   D	            Reserved
#   E	            Response body
#   F	            Response headers
#   G	            Reserved
#   H	            Audit log trailer, which contains additional data
#   I	            Compact request body alternative (to part C), which excludes files
#   J	            Information on uploaded files (available as of version 2.6.0)
#   K	            Contains a list of all rules that matched for the transaction
#   Z	            Final boundary (mandatory)

def parseA(list):
    ADict = {}
    reg = re.compile(r'[0-9]{2}/[A-Z]{1}[a-z]{2}/[0-9]{4}:[0-9]{2}:[0-9]{2}:[0-9]{2}\s[+-]{1}[0-9]{4}')
    foundtime = reg.search(list[0])
    timestring = foundtime.group(0)
    ADict['Timestamp'] = time.strptime(timestring, "%d/%b/%Y:%H:%M:%S %z")
    AList = list[0].split(' ')
    ADict['Unique-Transanction-ID'] = AList[2]
    ADict['Source-IP'] = AList[3]
    ADict['Source-Port'] = AList[4]
    ADict['Destination-IP'] = AList[5]
    ADict['Destination-Port'] = AList[6]

    return ADict

def parseB(list):
    BDict = {}
    BDict['Request'] = list[0]

    for each in list:
        if re.match(r'^Host:\s', each):
            tmplist = each.split(' ', 1)
            BDict['Host'] = tmplist[1]
        elif re.match(r'^Connection:\s', each):
            tmplist = each.split(' ', 1)
            BDict['Connection'] = tmplist[1]
        elif re.match(r'^Accept:\s', each):
            tmplist = each.split(' ', 1)
            BDict['Accept'] = tmplist[1]
        elif re.match(r'^Upgrade-Insecure-Requests:\s', each):
            tmplist = each.split(' ', 1)
            BDict['Upgrade-Insecure-Requests'] = tmplist[1]
        elif re.match(r'^User-Agent:\s', each):
            tmplist = each.split(' ', 1)
            BDict['User-Agent'] = tmplist[1]
        elif re.match(r'^Accept-Encoding:\s', each):
            tmplist = each.split(' ', 1)
            BDict['Accept-Encoding'] = tmplist[1]
        elif re.match(r'^Accept-Language:\s', each):
            tmplist = each.split(' ', 1)
            BDict['Accept-Language'] = tmplist[1]
        else:
            pass #i dont know what it is, so im skipping for today

    return BDict

def parseF(list):
    FDict = {}
    FDict['Response'] = list[0]

    for each in list:
        if re.match(r'^Last-Modified:\s', each):
            tmplist = each.split(' ', 1)
            FDict['Last-Modified'] = tmplist[1]
        elif re.match(r'^ETag:\s', each):
            tmplist = each.split(' ', 1)
            FDict['ETag'] = tmplist[1]
        elif re.match(r'^Accept-Ranges:\s', each):
            tmplist = each.split(' ', 1)
            FDict['Accept-Ranges'] = tmplist[1]
        elif re.match(r'^Vary:\s', each):
            tmplist = each.split(' ', 1)
            FDict['Vary'] = tmplist[1]
        elif re.match(r'^Content-Encoding:\s', each):
            tmplist = each.split(' ', 1)
            FDict['Content-Encoding'] = tmplist[1]
        elif re.match(r'^Content-Length:\s', each):
            tmplist = each.split(' ', 1)
            FDict['Content-Length'] = tmplist[1]
        elif re.match(r'^Keep-Alive:\s', each):
            tmplist = each.split(' ', 1)
            FDict['Keep-Alive'] = tmplist[1]
        elif re.match(r'^Connection:\s', each):
            tmplist = each.split(' ', 1)
            FDict['Connection'] = tmplist[1]
        elif re.match(r'^Content-Type:\s', each):
            tmplist = each.split(' ', 1)
            FDict['Content-Type'] = tmplist[1]
        else:
            pass #i dont know what it is, so im skipping for today

    return FDict

def parseH(list):
    HDict = {}
    messageList = []

    for each in list:
        if re.match(r'^Message', each):
            messageList.append(re.sub('^Message:\s', '', each))
        elif re.match(r'^Engine-Mode', each):
            tmplist = each.split(' ')
            HDict['Engine-Mode'] = re.sub('"', '', tmplist[1])
        elif re.match(r'^Server:\s', each):
            tmplist = each.split(' ', 1)
            HDict['Server'] = tmplist[1]
        elif re.match(r'^Producer:\s', each):
            tmplist = each.split(' ', 1)
            HDict['Producer'] = tmplist[1]
        elif re.match(r'^Response-Body-Transformed:\s', each):
            tmplist = each.split(' ', 1)
            HDict['Response-Body-Transformed'] = tmplist[1]
        else:
            pass #i dont know what it is and i dont care right now

    HDict['Message'] = messageList
    return HDict