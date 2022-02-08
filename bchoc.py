#!/usr/bin/python3
import typing
import sys, os
import struct
import time
from Blockchain import Blockchain
from collections import namedtuple
from datetime import datetime, timedelta, timezone
from hashlib import sha1
from uuid import UUID, uuid4
import PySimpleGUI as sg

# export
#file_path = os.getenv('BCHOC_FILE_PATH')
file_path = 'chain'

#evidence actions
State = {
    "INITIAL": b"INITIAL\0\0\0\0",
    "CHECKEDIN": b"CHECKEDIN\0\0",
    "CHECKEDOUT": b"CHECKEDOUT\0",
    "DISPOSED": b"DISPOSED\0\0\0",
    "DESTROYED": b"DESTROYED\0\0",
    "RELEASED": b"RELEASED\0\0\0",
}

#format, length, and struct for packing block(s)
block_head_fmt = "20s d 16s I 11s I"
block_head_len = struct.calcsize(block_head_fmt)
block_head_struct = struct.Struct(block_head_fmt)

#Empty blockchain object
blockchain = Blockchain()

sg.theme('Light Green 2')

#window layout
layout = [[sg.Frame('Blockchain Chain-of-Custody', font=('Helvetica', 12), layout=[[sg.Button('Init'), sg.Text('Initialize Custody Chain')],
                                                           [sg.Button('Add'), sg.Text('Add New Evidence')],
                                                           [sg.Button('Checkout'), sg.Text('Take Evidence')],
                                                           [sg.Button('Checkin'), sg.Text('Return Evidence')],
                                                           [sg.Button('Log'), sg.Text('Display Custody Chain')],
                                                           [sg.Button('Remove'), sg.Text('Remove Evidence')],
                                                           [sg.Button('Verify'), sg.Text('Ensure Chain Integrity')],
                                                           [sg.Button('Quit'), sg.Text('Close Application')]]),
           sg.MLine(size=(40, 20), disabled=True, key='-ML1-', font=('Helvetica', 12))]]

#create window
window = sg.Window('Blockchain Chain-of-Custody', layout)

#READ IN OUT_FILE
def readFile():
    try:
        #Read file_path
        with open(file_path, 'rb') as in_file:
            while True:
                #Read in standard block size
                piece = in_file.read(68)
                #End file reading if no more blocks can be read
                if piece == b'':
                    break
                else:
                    #Unpack block to save to Blockchain
                    newBlock = block_head_struct.unpack(piece)

                    #Read in additional bytes for Block data field (any length, so must rely on block data_length)
                    blockData = in_file.read(int(newBlock[5]))

                    # reverse uuid to original format
                    caseID = newBlock[2].hex()
                    cid = bytearray.fromhex(caseID)
                    cid.reverse()

                    #Add the new Block
                    blockchain.new_block(data=blockData, data_length=int(newBlock[5]), previous_hash=newBlock[0], timestamp=newBlock[1], case_ID=UUID(bytes=bytes(cid)), evidence_ID=newBlock[3], state=newBlock[4])
        return True
    except struct.error as se:
        sg.PopupError("Error: 68 bytes required for block creation")
        return False
    except KeyError as ke:
        sg.PopupError("Error: Invalid Block State.")
        return False

#INIT
def init_command(blockchain):
    #Populate the Blockchain from a file if given
    #Otherwise, create a new INITIAL Block
    try:
        #search for file
        if readFile():
            if blockchain.chain[0]['state'] == State['INITIAL']:
                sg.Popup("Init", "Blockchain file found with INITIAL block.")
                return True
            else:
                sg.PopupError("Error: Blockchain invalid.")
                return True
        else:
            return False
    except FileNotFoundError as e:
        #Create new INITIAL Block if out_file does not exist
        blockchain.new_block()
        sg.Popup("Init", "Blockchain file not found. Created INITIAL block.")
        return True
    except IndexError as ie:
        sg.PopupError("Error: File is empty.")
        return False

#ADD
def add_command(case, ids, blockchain):
    #Add a new Block to the Blockchain

    #Create INITIAL Block if none exists when calling ADD
    try:
        readFile()
    except FileNotFoundError:
        init_command(blockchain)

    #verifies evidence_ID was not previously used
    newEvidence = True

    #For each evidence_ID passed in...
    for x in range(len(ids)):
        #Check if it has been used already...
        for i in range(len(blockchain.chain)):
            if int(blockchain.chain[i]['evidence_ID']) == int(str(ids[x])):
                sg.PopupError("evidence_ID already used")
                newEvidence = False
                return
            #Otherwise, add the new evidence
        if newEvidence:
            blockchain.new_block(data="", data_length=0, previous_hash=blockchain.hash(blockchain.last_block), timestamp=time.time(), case_ID=UUID(case), evidence_ID=int(str(ids[x])), state=State['CHECKEDIN'])
            sg.Popup("Block Added", "Case: " + str(case), "Added item: " + str(blockchain.last_block['evidence_ID']), "  Status: " + str(blockchain.last_block['state'])[2:-1].rstrip('\\x00'), "  Time of action: " + str(datetime.fromtimestamp(blockchain.last_block['timestamp']).isoformat()))

#CHECKOUT
def checkout_command(idVal, blockchain):
    #Create new Block with same evidence_ID, case_ID, etc.
    #But CHECKEDOUT State and new timestamp

    readFile()

    try:
        #save input ID as int
        id = int(idVal)

        #Traverse chain backwards (probably a better way to go about this)
        i = len(blockchain.chain) - 1
        while i > -1:
            #Check if evidence with given ID has been DESTROYED, DISPOSED, RELEASED, or CHECKEDOUT
            if int(blockchain.chain[i]['evidence_ID']) == id:
                if blockchain.chain[i]['state'] == State['DISPOSED'] or blockchain.chain[i]['state'] == State['DESTROYED'] or blockchain.chain[i]['state'] == State['RELEASED']:
                    sg.PopupError("Error: evidence previously removed.")
                    return False
                elif blockchain.chain[i]['state'] == State['CHECKEDOUT']:
                    sg.PopupError("Error: evidence already checked out")
                    return False
                else:
                    #make new block for checked out evidence item
                    blockchain.new_block(data="", data_length=0, previous_hash=blockchain.hash(blockchain.last_block), timestamp=time.time(), case_ID=blockchain.chain[i]['case_ID'], evidence_ID=blockchain.chain[i]['evidence_ID'], state=State['CHECKEDOUT'])

                    # Get last block as newest block will be the check out block
                    sg.Popup("Evidence Successfully Checked Out:", "Case: " + str(blockchain.last_block['case_ID']), "Checked out item: " + str(blockchain.last_block['evidence_ID']), "  Status: " + str(blockchain.last_block['state'])[2:-1].rstrip('\\x00'), "  Time of action: " + str(datetime.fromtimestamp(blockchain.last_block['timestamp']).isoformat()) + "Z")
                    return True
            i -= 1
        #Input ID not in Blockchain
        if i == -1:
            sg.PopupError("Error: ID not found")
            return False
    except ValueError:
        #Input ID not an int
        sg.PopupError("Error: Invalid evidence ID")
        return False

#CHECKIN
def checkin_command(idVal, blockchain):
    #Create new Block with same case_ID, evidence_ID, etc
    #But CHECKEDIN State and new timestamp

    readFile()

    try:
        #Save ID  as int
        id = int(idVal)

        #Traverse Blockchain backwards to find most recent use of given ID
        i = len(blockchain.chain) - 1
        while i > -1:
            #Check if evidence was DESTROYED, DISPOSED, RELEASED, or CHECKEDIN
            #TODO refactor for VERIFY function?
            if int(blockchain.chain[i]['evidence_ID']) == id:
                if blockchain.chain[i]['state'] == State['DISPOSED'] or blockchain.chain[i]['state'] == State['DESTROYED'] or blockchain.chain[i]['state'] == State['RELEASED']:
                    sg.PopupError("Error: evidence previously removed.")
                    return False
                elif blockchain.chain[i]['state'] == State['CHECKEDIN']:
                    sg.PopupError("Error: evidence already checked in")
                    return False
                else:
                    #make new block for checked in evidence item
                    blockchain.new_block(data="", data_length=0, previous_hash=blockchain.hash(blockchain.last_block), timestamp=time.time(), case_ID=blockchain.chain[i]['case_ID'], evidence_ID=blockchain.chain[i]['evidence_ID'], state=State['CHECKEDIN'])

                    #Stdout
                    sg.Popup("Evidence Successfully Checked In:", "Case: " + str(blockchain.last_block['case_ID']), "Checked out item: " + str(blockchain.last_block['evidence_ID']), "  Status: " + str(blockchain.last_block['state'])[2:-1].rstrip('\\x00'), "  Time of action: " + str(datetime.fromtimestamp(blockchain.last_block['timestamp']).isoformat()))
                    return True
            i -= 1
        if i == -1:
            sg.PopupError("Error: ID not found")
            return False
    except ValueError:
        #Given ID not an int
        sg.PopupError("Error: Invalid item ID")
        return False

#LOG
def log_command(lValues, blockchain):
    #Print Blockchain

    readFile()

    out = ""
    #Prints log in reverse
    if lValues[1]:
        #Prints last N log entries
        if lValues['-IN1-'] != '':
            #Prints only entries relevant to case_ID C
            if lValues[2] != '':
                #Prints log entries only relevant to evidence_ID I
                if lValues['-IN2-'] != '':
                    out = blockchain.printChainLimitedCaseAndItem(lValues)
                else:
                    out = blockchain.printChainLimitedCase(lValues)
            else:
                if lValues['-IN2-'] != '':
                    out = blockchain.printChainLimitedItem(lValues)
                else:
                    out = blockchain.printChainLimited(lValues)
        else:
            if lValues[2] != '':
                if lValues['-IN2-'] != '':
                    out = blockchain.printChainCaseAndItem(lValues)
                else:
                    out = blockchain.printChainCase(lValues)
            else:
                if lValues['-IN2-'] != '':
                    out = blockchain.printChainItem(lValues)
                else:
                    out = blockchain.printChain(lValues)
    else:
        if lValues['-IN1-'] != '':
            if lValues[2] != '':
                if lValues['-IN2-'] != '':
                    out = blockchain.printChainLimitedCaseAndItem(lValues)
                    pass
                else:
                    out = blockchain.printChainLimitedCase(lValues)
                    pass
            else:
                if lValues['-IN2-'] != '':
                    out = blockchain.printChainLimitedItem(lValues)
                    pass
                else:
                    out = blockchain.printChainLimited(lValues)
        else:
            if lValues[2] != '':
                if lValues['-IN2-'] != '':
                    out = blockchain.printChainCaseAndItem(lValues)
                else:
                    out = blockchain.printChainCase(lValues)
            else:
                if lValues['-IN2-'] != '':
                    out = blockchain.printChainItem(lValues)
                else:
                    out = blockchain.printChain(lValues)
    return out

#REMOVE
def remove_command(rValues, blockchain):
    #Remove specified evidence from given ID
    #Renders that evidence uneditable

    readFile()

    #Reason for removal must be DISPOSED, DESTROYED, or RELEASED
    why = ''
    if rValues[0]:
        why = 'DISPOSED'
    elif rValues[1]:
        why = 'DESTROYED'
    elif rValues[2]:
        why = 'RELEASED'
    else:
        sg.PopupError("Error: reason invalid")
        return False

    #Traverse Blockchain backwards
    i = len(blockchain.chain) - 1
    while i > -1:
        #Check if evidence was already removed
        if blockchain.chain[i]['evidence_ID'] == int(rValues['-ID-']):
            if blockchain.chain[i]['state'] == State['DISPOSED'] or blockchain.chain[i]['state'] == State['DESTROYED'] or blockchain.chain[i]['state'] == State['RELEASED']:
                sg.PopupError("Error: evidence already removed")
                return False
            elif blockchain.chain[i]['state'] == State['CHECKEDOUT']:
                sg.PopupError("Error: evidence currently checked out")
                return False
            else:
                #If reason was RELEASED, owner information must be given
                if why == 'RELEASED':
                    if rValues['-O-'] != '':
                        blockchain.new_block(data=rValues['-O-'], data_length=len(rValues['-O-']), previous_hash=blockchain.hash(blockchain.last_block), timestamp=time.time(), case_ID=blockchain.chain[i]['case_ID'], evidence_ID=int(str(rValues['-ID-'])), state=State[why])
                    else:
                        sg.PopupError("Error: Evidence released, but no owner information was given.")
                        return False
                #Otherwise owner information is optional
                elif rValues['-O-'] != '':
                    blockchain.new_block(data=rValues['-O-'], data_length=len(rValues['-O-']), previous_hash=blockchain.hash(blockchain.last_block), timestamp=time.time(), case_ID=blockchain.chain[i]['case_ID'], evidence_ID=int(str(rValues['-ID-'])), state=State[why])
                else:
                    blockchain.new_block(data="", data_length=0, previous_hash=blockchain.hash(blockchain.last_block), timestamp=time.time(), case_ID=blockchain.chain[i]['case_ID'], evidence_ID=int(str(rValues['-ID-'])), state=State[why])
                break
        i -= 1
    if i == -1:
        #No ID given is in Blockchain
        sg.PopupError("Error: ID not found")
        return False
    else:
        #Print owner information if necessary
        if rValues['-O-'] != '':
            sg.Popup("Case: " + str(blockchain.last_block['case_ID']), "Removed item: " + str(blockchain.last_block['evidence_ID']),
                  "  Status: " + str(blockchain.last_block['state'])[2:-1].rstrip('\\x00'), "  Owner info: " + blockchain.last_block['data'], "  Time of action: " + str(datetime.fromtimestamp(blockchain.last_block['timestamp']).isoformat()))
        else:
            sg.Popup("Case: " + str(blockchain.last_block['case_ID']), "Removed item: " + str(blockchain.last_block['evidence_ID']),
                  "  Status: " + str(blockchain.last_block['state'])[2:-1].rstrip('\\x00'), "  Time of action: " + str(datetime.fromtimestamp(blockchain.last_block['timestamp']).isoformat()))
        return True

#TODO create VERIFY function
def verify_command():
    readFile()
    return verify_chain()

# verify the chain
def verify_chain():
    # set default state to clean
    blockchain_valid_state = "CLEAN"

    out = ''

    out = "Transactions in blockchain:" + str(len(blockchain.chain)) + "\n"
    # check_block_status(blockchain.chain)
    dupes = check_if_duplicates(blockchain.chain)

    if dupes != None:
        out += dupes

    # parse chain
    for i in range(len(blockchain.chain)):

        if (i != 0):
            # prev_hash != hash(prev)
            if (blockchain.chain[i]['previous_hash'] == blockchain.hash(blockchain.chain[i-1])):
                blockchain_valid_state = "CLEAN"
            else:
                out += "State of blockchain: ERROR" + "\n"
                out += "Bad block: " + str(blockchain.hash(blockchain.chain[i])) + "\n"
                out += "Block contents do not match block checksum." +"\n"
                return out
    # print if clean
    out += "State of blockchain: " + blockchain_valid_state + "\n"

    return out

# Check for duplicate hashes resulting in same parent
def check_if_duplicates(chain):
    # Storage for hashes
    mem = {}

    out = ''

    for block in chain:
        hash = block["previous_hash"]
        if hash not in mem:
            mem[hash] = block
        # Duplicate found
        else:
            out += "Bad Block:" + str(blockchain.hash(block)) + "\n"
            out += "Parent block: " + str(hash) + "\n"
            out += "Two blocks found with same parent." + "\n"
            return out

def main():
    #Main method
    initCalled = False
    global file_path

    while True:
        event, values = window.read()

        if event == sg.WIN_CLOSED or event == 'Quit':
            break
        elif event == 'Init':
            '''if sg.PopupYesNo('Please ensure your file is located at the path specified in the environment variable \'BCHOC_FILE_PATH\' before continuing.', 'Otherwise, a new blockchain file will be created.', 'Would you like to proceed?') == 'Yes':
                init_command(blockchain)
                initCalled = True
                blockchain.saveChain()
                blockchain.chain = []'''
            iLayout = [[sg.FileBrowse('Select File'), sg.InputText(disabled=True)],
                       [sg.Button('Generate New File')],
                       [sg.Button('Submit'), sg.Button('Cancel')]]
            iWindow = sg.Window('Init', iLayout)

            while True:
                iEvents, iValues = iWindow.read()
                if iEvents == 'Cancel' or iEvents == sg.WIN_CLOSED:
                    iWindow.close()
                    break
                elif iEvents == 'Submit':
                    if iValues[0] == '':
                        sg.PopupError('Please select a file.')
                    elif '.' in iValues[0]:
                        sg.PopupError('Please submit a file without an extension.')
                        iWindow[0].update('')
                    else:
                        file_path = iValues['Select File']
                        blockchain.setFilePath(file_path)
                        iWindow[0].update(str(file_path))
                        if init_command(blockchain):
                            initCalled = True
                            iWindow.close()
                            blockchain.saveChain()
                            blockchain.chain = []
                            break
                        else:
                            iWindow[0].update('')
                elif iEvents == 'Generate New File':
                    text = sg.PopupGetText('File name', 'Please enter the name of the blockchain file.')
                    if text != "":
                        file_path = text
                        blockchain.setFilePath(text)
                        init_command(blockchain)
                        initCalled = True
                        iWindow.close()
                        blockchain.saveChain()
                        blockchain.chain = []
                        break
                    else:
                        sg.PopupError("Please enter a name for the file.")
        elif event == 'Add':
            addLayout = [[sg.Text('Case ID'), sg.InputText()],
                         [sg.Text('Item ID (if multiple, separate with commas)'), sg.InputText(key='-IN-', enable_events=True)],
                         [sg.Button('Add'), sg.Button('Quit')]]
            addWindow = sg.Window('Add to Blockchain', addLayout)

            while True:
                addEvent, addValues = addWindow.read()

                if addEvent == sg.WIN_CLOSED or addEvent == 'Quit':
                    addWindow.close()
                    break
                elif addEvent == '-IN-' and addValues['-IN-'] and addValues['-IN-'][-1] not in ('0123456789, '):
                    addWindow['-IN-'].update(addValues['-IN-'][:-1])
                elif addEvent == 'Add':
                    ids = addValues['-IN-'].split(",")
                    if addValues[0] == '':
                        sg.PopupError("Error: Case ID cannot be empty")
                        blockchain.chain = []
                    elif ids == ['']:
                        sg.PopupError('Error: Item ID(s) cannot be empty')
                        blockchain.chain = []
                    else:
                        try:
                            initCalled = True
                            add_command(addValues[0], ids, blockchain)
                            blockchain.saveChain()
                            blockchain.chain = []
                            break
                        except ValueError as ve:
                            sg.PopupError('Error: please enter a valid Case ID')
                            addWindow[0].update('')
                            addWindow['-IN-'].update('')
                            blockchain.chain = []
            addWindow.close()
        elif event == 'Checkout':
            if not initCalled:
                sg.PopupError("Error", "Blockchain not initialized using \'Init\'")
            else:
                coLayout = [[sg.Text('Item ID'), sg.InputText(key='-IN-', enable_events=True)],
                            [sg.Button("Checkout"), sg.Button("Cancel")]]
                coWindow = sg.Window('Checkout Evidence', coLayout)

                while True:
                    coEvent, coValues = coWindow.read()

                    if coEvent == 'Cancel' or coEvent == sg.WIN_CLOSED:
                        coWindow.close()
                        break
                    elif coEvent == '-IN-' and coValues['-IN-'] and coValues['-IN-'][-1] not in ('0123456789'):
                        coWindow['-IN-'].update(coValues['-IN-'][:-1])
                    elif coEvent == 'Checkout':
                        if checkout_command(coValues['-IN-'], blockchain):
                            blockchain.saveChain()
                            blockchain.chain = []
                            break
                        coWindow['-IN-'].update('')
                        #blockchain.saveChain() #may not need?
                        blockchain.chain = []
                coWindow.close()
        elif event == 'Checkin':
            if not initCalled:
                sg.PopupError("Error: Blockchain not initialized using \'Init\'")
            else:
                ciLayout = [[sg.Text('Item ID'), sg.InputText(key='-IN-', enable_events=True)],
                            [sg.Button("Checkin"), sg.Button("Cancel")]]
                ciWindow = sg.Window('Checkin Evidence', ciLayout)

                while True:
                    ciEvent, ciValues = ciWindow.read()

                    if ciEvent == 'Cancel' or ciEvent == sg.WIN_CLOSED:
                        ciWindow.close()
                        break
                    elif ciEvent == '-IN-' and ciValues['-IN-'] and ciValues['-IN-'][-1] not in ('0123456789'):
                        ciWindow['-IN-'].update(ciValues['-IN-'][:-1])
                    elif ciEvent == 'Checkin':
                        if checkin_command(ciValues['-IN-'], blockchain):
                            blockchain.saveChain()
                            blockchain.chain = []
                            break
                        ciWindow['-IN-'].update('')
                        #blockchain.saveChain() #may not need?
                        blockchain.chain = []
                ciWindow.close()
        elif event == 'Log':
            if not initCalled:
                sg.PopupError("Error: Blockchain not initialized using \'Init\'")
            else:
                lLayout = [[sg.Frame(layout=[
                                            [sg.Radio('Forward Order', "RADIO1", default=True, size=(10,1)), sg.Radio('Reverse Order', "RADIO1")]], title='Reverse', relief=sg.RELIEF_RIDGE)],
                           [sg.Text('Number of Results (optional):'), sg.InputText(key='-IN1-', enable_events=True)],
                           [sg.Text('Case ID (optional):'), sg.InputText()],
                           [sg.Text('Item ID (optional):'), sg.InputText(key='-IN2-', enable_events=True)],
                           [sg.Button('Enter'), sg.Button('Cancel')]]

                lWindow = sg.Window('Log Options', lLayout)

                while True:
                    lEvent, lValues = lWindow.read()

                    if lEvent == 'Cancel' or lEvent == sg.WIN_CLOSED:
                        lWindow.close()
                        break
                    elif lEvent == '-IN1-' and lValues['-IN1-'] and lValues['-IN1-'][-1] not in ('0123456789'):
                        lWindow['-IN1-'].update(lValues['-IN1-'][:-1])
                    elif lEvent == '-IN2-' and lValues['-IN2-'] and lValues['-IN2-'][-1] not in ('0123456789'):
                        lWindow['-IN2-'].update(lValues['-IN2-'][:-1])
                    elif lEvent == 'Enter':
                        log = log_command(lValues, blockchain)
                        if log != None:
                            window['-ML1-'].update(log)
                            blockchain.saveChain()
                            blockchain.chain = []
                            break
                        else:
                            sg.PopupError("Error: No evidence found")
                            lWindow['-IN1-'].update('')
                            lWindow[2].update('')
                            lWindow['-IN2-'].update('')
                            blockchain.chain = []
                lWindow.close()
        elif event == 'Remove':
            if not initCalled:
                sg.PopupError("Error", "Blockchain not initialized using \'init\'")
            else:
                rLayout = [[sg.Frame(layout=[
                                             [sg.Radio('DISPOSED', "RADIO1", default=True, size=(10,1))],
                                             [sg.Radio('DESTROYED', "RADIO1", size=(10,1))],
                                             [sg.Radio('RELEASED', "RADIO1", size=(10,1))]], title='Reason for Removal', relief=sg.RELIEF_SUNKEN)],
                           [sg.Text('Item ID:'), sg.InputText(key='-ID-', enable_events=True)],
                           [sg.Text('Owner Information (required if RELEASED):'), sg.InputText(key='-O-', enable_events=True)],
                           [sg.Button('Remove'), sg.Button('Cancel')]]
                rWindow = sg.Window('Remove Evidence', rLayout)

                while True:
                    rEvent, rValues = rWindow.read()

                    if rEvent == 'Cancel' or rEvent == sg.WIN_CLOSED:
                        rWindow.close()
                        break
                    elif rEvent == '-ID-' and rValues['-ID-'] and rValues['-ID-'][-1] not in ('0123456789'):
                        rWindow['-ID-'].update(rValues['-ID-'][:-1])
                    elif rEvent == 'Remove':
                        if rValues['-ID-'] == '':
                            sg.PopupError("Error: Item ID cannot be empty")
                        else:
                            if remove_command(rValues, blockchain):
                                blockchain.saveChain()
                                blockchain.chain = []
                                break
                            else:
                                rWindow['-ID-'].update('')
                                rWindow['-O-'].update('')
                                blockchain.chain = []
                rWindow.close()
        elif event == 'Verify':
            if not initCalled:
                sg.PopupError("Error: Blockchain not initialized using \'Init\'")
            else:
                vLayout = [[sg.Text("Verification Complete", font=('Helvetica', 16))],
                           [sg.Text("Result:", font=('Helvetica', 14))],
                           [sg.Text(verify_command(), font=('Helvetica', 12))],
                           [sg.Button("OK")]]
                vWindow = sg.Window('Blockchain Verification', vLayout)

                vEvent, vValues = vWindow.read()

                if vEvent == 'OK' or vEvent == sg.WIN_CLOSED:
                    vWindow.close()
                blockchain.saveChain()
                blockchain.chain = []
    window.close()

#Main method
if __name__ == '__main__':
    main()
