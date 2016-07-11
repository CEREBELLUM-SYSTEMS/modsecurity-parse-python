#!/usr/local/bin/python3
# imports
import re
import parsers

#get the log data file
log = open('data/modsec_audit.log').readlines()

entry = {}

#given each file create dict key for each header and insert each line of each header as list items, we'll pass these
#to parsers for each section in parsers.py

for index, line in enumerate(log):
    if re.match(r'^--[a-fA-F0-9]{8}-Z--\n$', line):
        break #Z is the bottom bounday, if we hit, let's not waste any more time
    elif re.match(r'^--[a-fA-F0-9]{8}-[A-Z]{1}--\n$', line):
        entry[line.rstrip()] = []
        currentHeader = line.rstrip()
    else:
        list = entry[currentHeader]
        list.append(line.rstrip())

for header in entry:
    if header[11] == 'A':
        ADict = parsers.parseA(entry[header])
    elif header[11] == 'B':
        BDict = parsers.parseB(entry[header])
    elif header[11] == 'C':
        pass
    elif header[11] == 'D':
        pass
    elif header[11] == 'E':
        pass
    elif header[11] == 'F':
        FDict = parsers.parseF(entry[header])
    elif header[11] == 'G':
        pass
    elif header[11] == 'H':
        HDict = parsers.parseH(entry[header])
    elif header[11] == 'I':
        pass
    elif header[11] == 'J':
        pass
    elif header[11] == 'K':
        pass

print (ADict)