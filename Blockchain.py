# *-* coding: utf-8 *-*
import sys, os
import typing
import struct
import time
from collections import namedtuple
from datetime import datetime, timedelta, timezone
from hashlib import sha1
from typing import BinaryIO, List, Callable
from uuid import UUID, uuid4
import PySimpleGUI as sg

# export
#file_path = os.getenv('BCHOC_FILE_PATH')
file_path = 'chain'

#Evidence States
State = {
    "INITIAL": b"INITIAL\0\0\0\0",
    "CHECKEDIN": b"CHECKEDIN\0\0",
    "CHECKEDOUT": b"CHECKEDOUT\0",
    "DISPOSED": b"DISPOSED\0\0\0",
    "DESTROYED": b"DESTROYED\0\0",
    "RELEASED": b"RELEASED\0\0\0",
}

#Packing format, length, and structure
block_head_fmt = "20s d 16s I 11s I"
block_head_len = struct.calcsize(block_head_fmt)
block_head_struct = struct.Struct(block_head_fmt)

#Blockchain object class
class Blockchain(object):
    #INIT
    def __init__(self):
        #Blockchain is a list of Block dicts
        self.chain = []

    def setFilePath(self, text):
        global file_path
        file_path = text

    #ADD: Creates a new Block, packs/unpacks for byte alignment
    def new_block(self, data: str = b'Initial block\0', data_length: int = 14, previous_hash: bytes = bytes(20), timestamp=time.time(), case_ID: UUID = UUID(int=0), evidence_ID: int = 0, state: State = State['INITIAL']):

        #Each Block is a dict
        block = {
            'previous_hash': previous_hash, #20 bytes
            'timestamp': timestamp, #08 bytes
            'case_ID': case_ID, #16 bytes
            'evidence_ID': evidence_ID, #04 bytes
            'state': state, #11 bytes
            'data_length': data_length, #04 bytes
            'data': data, #no limit
        }

        #data may be empty
        blockData = block['data']

        #may want to do block['case_ID'].bytes_le?
        packed = block_head_struct.pack(block['previous_hash'], block['timestamp'], block['case_ID'].bytes, int(block['evidence_ID']), block['state'], len(block['data']))

        keys = ["previous_hash", "timestamp", "case_ID", "evidence_ID", "state", "data_length", "data"]
        values = block_head_struct.unpack(packed)

        #Struct.unpack saves variables into a tuple
        #Below code takes those attributes and puts them into dict structure
        #This is like this because initially it had no problem unpacking into a dict
        #And then it did halfway through the project...
        block = dict(zip(keys, values))
        block['data'] = blockData
        block['previous_hash'] = block['previous_hash']
        block['case_ID'] = UUID(bytes=block['case_ID'])
        block['state'] = State[str(block['state']).replace("\\x00", "")[2:-1]]

        try:
            if str(blockData)[0] == 'b' and str(blockData)[1] == '\'':
                block['data'] = str(blockData).replace("\\x00", "")[2:-1]
            else:
                block['data'] = blockData
        except IndexError:
            block['data'] = blockData

        #Appends the newly made Block to end of list
        self.chain.append(block)

        return block

    @staticmethod
    def hash(block):
        #SHA1 hash of entire packed block
        # We must make sure that the Dictionary is Ordered, or we'll have inconsistent hashes
        data_length = len(block['data'])
        block_string = struct.pack(f'20s d 16s I 11s I {data_length}s', block['previous_hash'], block['timestamp'], block['case_ID'].bytes, int(block['evidence_ID']), block['state'], len(block['data']), bytes(block['data'], 'ascii'))
        return sha1(block_string).digest()

    #Stores the chain into the out_file
    def saveChain(self):
        i = 0
        #Open and flush out_file contents
        open(file_path, 'wb').close()

        #Write each packed Block int out_file
        for i in range(len(self.chain)):
            st = self.chain[i]['case_ID'].bytes
            cid = bytearray.fromhex(st.hex())
            cid.reverse()

            if self.chain[i]['data']:
                self.chain[i]['data'] = self.chain[i]['data'].rstrip('\0')
                data_len = len(self.chain[i]['data']) + 1 # need null terminator?
            else:
                data_len = 0

            packed = block_head_struct.pack(self.chain[i]['previous_hash'], self.chain[i]['timestamp'], cid, int(self.chain[i]['evidence_ID']), self.chain[i]['state'], data_len)

            #Data length is variable, so written separately
            blockData = struct.pack(f'{data_len}s', bytes(self.chain[i]['data'], 'ascii'))

            #Write to out_file
            with open(file_path, "ab") as out_file:
                out_file.write(packed)
                out_file.write(blockData)
                out_file.close()
        return

    @property
    def last_block(self):
        #Returns the last Block in Blockchain
        return self.chain[-1]

    #----------- Bunch of LOG functions below --------------
    #LOG [-r]
    def printChain(self, lValues):
        out = ""
        if lValues[1]:
            for i in reversed(range(len(self.chain))):
                out += ("Case: " + str(self.chain[i]['case_ID']) + "\n"
                    +  "Item: " + str(self.chain[i]['evidence_ID']) + "\n"
                    +  "Action: " + str(self.chain[i]['state'])[2:-1].rstrip('\\x00') + "\n"
                    +  "Time: " + str(datetime.fromtimestamp(self.chain[i]['timestamp']).isoformat() + 'Z') + "\n\n")
        else:
            for i in range(len(self.chain)):
                #ALSO, init is only used for getting the initial block from a file?
                out += ("Case: " + str(self.chain[i]['case_ID']) + "\n"
                    +  "Item: " + str(self.chain[i]['evidence_ID']) + "\n"
                    +  "Action: " + str(self.chain[i]['state'])[2:-1].rstrip('\\x00') + "\n"
                    +  "Time: " + str(datetime.fromtimestamp(self.chain[i]['timestamp']).isoformat()+ 'Z') + "\n\n")
        if out != "":
            return out.rstrip()

    #LOG [-r] -i
    def printChainItem(self, lValues):
        out = ""
        if lValues[1]:
            for i in reversed(range(len(self.chain))):
                if int(self.chain[i]['evidence_ID']) == int(lValues['-IN2-']):
                    out += ("Case: " + str(self.chain[i]['case_ID']) + "\n" +
                           "Item: " + str(self.chain[i]['evidence_ID']) + "\n" +
                           "Action: " + str(self.chain[i]['state'])[2:-1].rstrip('\\x00') + "\n" +
                           "Time: " + str(datetime.fromtimestamp(self.chain[i]['timestamp']).isoformat() + 'Z') + "\n\n")
        else:
            for i in range(len(self.chain)):
                #ALSO, init is only used for getting the initial block from a file?
                if int(self.chain[i]['evidence_ID']) == int(lValues['-IN2-']):
                    out += ("Case: " + str(self.chain[i]['case_ID']) + "\n"
                        +  "Item: " + str(self.chain[i]['evidence_ID']) + "\n"
                        +  "Action: " + str(self.chain[i]['state'])[2:-1].rstrip('\\x00') + "\n"
                        +  "Time: " + str(datetime.fromtimestamp(self.chain[i]['timestamp']).isoformat() + 'Z') + "\n\n")
        if out != "":
            return out.rstrip()

    #LOG [-r] -c
    def printChainCase(self, lValues):
        out = ""
        if lValues[1]:
            for i in reversed(range(len(self.chain))):
                if str(self.chain[i]['case_ID']) == str(lValues[2]):
                    out += ("Case: " + str(self.chain[i]['case_ID']) + "\n" +
                           "Item: " + str(self.chain[i]['evidence_ID']) + "\n" +
                           "Action: " + str(self.chain[i]['state'])[2:-1].rstrip('\\x00') + "\n" +
                           "Time: " + str(datetime.fromtimestamp(self.chain[i]['timestamp']).isoformat() + 'Z') + "\n\n")
        else:
            for i in range(len(self.chain)):
                #ALSO, init is only used for getting the initial block from a file?
                if str(self.chain[i]['case_ID']) == str(lValues[2]):
                    out += ("Case: " + str(self.chain[i]['case_ID']) + "\n"
                        +  "Item: " + str(self.chain[i]['evidence_ID']) + "\n"
                        +  "Action: " + str(self.chain[i]['state'])[2:-1].rstrip('\\x00') + "\n"
                        +  "Time: " + str(datetime.fromtimestamp(self.chain[i]['timestamp']).isoformat() + 'Z') + "\n\n")
        if out != "":
            return out.rstrip()

    #LOG [-r] -n
    def printChainLimited(self, lValues):
        out = ""
        if lValues[1]:
            lim = self.chain[-int(lValues['-IN1-']):]
            for i in reversed(range(len(lim))):
                out += ("Case: " + str(lim[i]['case_ID']) + "\n" +
                       "Item: " + str(lim[i]['evidence_ID']) + "\n" +
                       "Action: " + str(lim[i]['state'].decode()) + "\n" +
                       "Time: " + str(datetime.fromtimestamp(lim[i]['timestamp']).isoformat()) + "\n\n")
        else:
            for i in range(int(lValues['-IN1-'])):
                #ALSO, init is only used for getting the initial block from a file?
                if i >= len(self.chain):
                    break
                out += ("Case: " + str(self.chain[i]['case_ID']) + "\n"
                    +  "Item: " + str(self.chain[i]['evidence_ID']) + "\n"
                    +  "Action: " + str(self.chain[i]['state'])[2:-1].rstrip('\\x00') + "\n"
                    +  "Time: " + str(datetime.fromtimestamp(self.chain[i]['timestamp']).isoformat() + 'Z') + "\n\n")

        if out != "":
            return out.rstrip()

    #LOG [-r] -c -i
    def printChainCaseAndItem(self, lValues):
        out = ""
        if lValues[1]:
            for i in reversed(range(len(self.chain))):
                if str(self.chain[i]['case_ID']) == str(lValues[2]) and int(self.chain[i]['evidence_ID']) == int(lValues['-IN2-']):
                    out += ("Case: " + str(self.chain[i]['case_ID']) + "\n" +
                           "Item: " + str(self.chain[i]['evidence_ID']) + "\n" +
                           "Action: " + str(self.chain[i]['state'])[2:-1].rstrip('\\x00') + "\n" +
                           "Time: " + str(datetime.fromtimestamp(self.chain[i]['timestamp']).isoformat() + 'Z') + "\n\n")
        else:
            for i in range(len(self.chain)):
                if str(self.chain[i]['case_ID']) == str(lValues[2]) and int(self.chain[i]['evidence_ID']) == int(lValues['-IN2-']):
                #ALSO, init is only used for getting the initial block from a file?
                    out += ("Case: " + str(self.chain[i]['case_ID']) + "\n"
                        +  "Item: " + str(self.chain[i]['evidence_ID']) + "\n"
                        +  "Action: " + str(self.chain[i]['state'])[2:-1].rstrip('\\x00') + "\n"
                        +  "Time: " + str(datetime.fromtimestamp(self.chain[i]['timestamp']).isoformat() + 'Z') + "\n\n")
        if out != "":
            return out.rstrip()

    #LOG [-r] -n -i
    def printChainLimitedItem(self, lValues):
        out = ""
        n = 0
        if lValues[1]:
            for i in reversed(range(len(self.chain))):
                if int(self.chain[i]['evidence_ID']) == int(lValues['-IN2-']):
                    out += ("Case: " + str(self.chain[i]['case_ID']) + "\n" +
                            "Item: " + str(self.chain[i]['evidence_ID']) + "\n" +
                            "Action: " + str(self.chain[i]['state'])[2:-1].rstrip('\\x00') + "\n" +
                            "Time: " + str(datetime.fromtimestamp(self.chain[i]['timestamp']).isoformat() + 'Z') + "\n\n")
                    n += 1
                if n == int(lValues['-IN1-']):
                    break
        else:
            for i in range(len(self.chain)):
                if int(self.chain[i]['evidence_ID']) == int(lValues['-IN2-']):
                    #ALSO, init is only used for getting the initial block from a file?
                    out += ("Case: " + str(self.chain[i]['case_ID']) + "\n"
                         +  "Item: " + str(self.chain[i]['evidence_ID']) + "\n"
                         +  "Action: " + str(self.chain[i]['state'])[2:-1].rstrip('\\x00') + "\n"
                         +  "Time: " + str(datetime.fromtimestamp(self.chain[i]['timestamp']).isoformat() + 'Z') + "\n\n")
                    n += 1
                if n == int(lValues['-IN1-']):
                    break

        if out != "":
            return out.rstrip()

    #LOG [-r] -n -c
    def printChainLimitedCase(self, lValues):
        out = ""
        n = 0
        if lValues[1]:
            for i in reversed(range(len(self.chain))):
                if str(self.chain[i]['case_ID']) == str(lValues[2]):
                    out += ("Case: " + str(self.chain[i]['case_ID']) + "\n" +
                            "Item: " + str(self.chain[i]['evidence_ID']) + "\n" +
                            "Action: " + str(self.chain[i]['state'])[2:-1].rstrip('\\x00') + "\n" +
                            "Time: " + str(datetime.fromtimestamp(self.chain[i]['timestamp']).isoformat() + 'Z') + "\n\n")
                    n += 1
                if n == int(lValues['-IN1-']):
                    break
        else:
            for i in range(len(self.chain)):
                if str(self.chain[i]['case_ID']) == str(lValues[2]):
                    #ALSO, init is only used for getting the initial block from a file?
                    out += ("Case: " + str(self.chain[i]['case_ID']) + "\n"
                         +  "Item: " + str(self.chain[i]['evidence_ID']) + "\n"
                         +  "Action: " + str(self.chain[i]['state'])[2:-1].rstrip('\\x00') + "\n"
                         +  "Time: " + str(datetime.fromtimestamp(self.chain[i]['timestamp']).isoformat() + 'Z') + "\n\n")
                    n += 1
                if n == int(lValues['-IN1-']):
                    break

        if out != "":
            return out.rstrip()

    #LOG [-r] -n -c -i
    def printChainLimitedCaseAndItem(self, lValues):
        out = ""
        n = 0
        if lValues[1]:
            for i in reversed(range(len(self.chain))):
                if str(self.chain[i]['case_ID']) == str(lValues[2]):
                    if int(self.chain[i]['evidence_ID']) == int(lValues['-IN2-']):
                        out += ("Case: " + str(self.chain[i]['case_ID']) + "\n" +
                                "Item: " + str(self.chain[i]['evidence_ID']) + "\n" +
                                "Action: " + str(self.chain[i]['state'])[2:-1].rstrip('\\x00') + "\n" +
                                "Time: " + str(datetime.fromtimestamp(self.chain[i]['timestamp']).isoformat() + 'Z') + "\n\n")
                        n += 1
                if n == int(lValues['-IN1-']):
                    break
        else:
            for i in range(len(self.chain)):
                if str(self.chain[i]['case_ID']) == str(lValues[2]):
                    if int(self.chain[i]['evidence_ID']) == int(lValues['-IN2-']):
                        out += ("Case: " + str(self.chain[i]['case_ID']) + "\n"
                             +  "Item: " + str(self.chain[i]['evidence_ID']) + "\n"
                             +  "Action: " + str(self.chain[i]['state'])[2:-1].rstrip('\\x00') + "\n"
                             +  "Time: " + str(datetime.fromtimestamp(self.chain[i]['timestamp']).isoformat() + 'Z') + "\n\n")
                        n += 1
                if n == int(lValues['-IN1-']):
                    break

        if out != "":
            return out.rstrip()

    #----------------- END LOG functions -------------------
