# Chain-of-Custody
This application serves as a chain-of-custody form for logging, and tracking evidence and the corresponding transactions. The underlying data structure is a blockchain, which can be verified using each block's checksum. An update to the initial production of this program saw the addition of a Graphical User Interface using the PySimpleGUI library.

## Functionality
The following actions have been implemented into the Chain-Of-Custody form:
- Init: Creates a blockchain. A file may be selected to import a blockchain, or a new one may be created (This will initialize it with an empty block).
- Add: Adds a new block to the chain. 
- Checkout: Temporarily remove evidence from custody. Must provide Item ID upon cehcking out. Prevents removal of evidence until returned.
- Checkin: Return checked-out evidence to custody. Must provide item ID upon cehcking out. Enables removal of evidence.
- Log: Displays contents of the blockchain records. A user may:
  - Display in reverse or forward order.
  - Choose number of blocks to display.
  - Choose to only see blocks for a given case by providing Case ID.
  - Choose to only see blocks for a certain item by providing Item ID.
- Remove: Remove evidence item from the blockchain. Removal requires specification of reason, item ID, and owner information (required for evidence release). Disables any further interaction with corresponding item.
- Verify: calculates the checksum of each block in the blockchain and ensures chain integrity.
- Quit: Exits application

## Block Attributes:
Each block in the Chain-of-Custody requires:
- A case ID in UUID format
- Item ID (nonnegative integer)
- Action: automatically generated except for removal headers.
  - INITIAL: Reserved for the empty initial block when creating a new blockchain.
  - CHECKEDIN: For evidence that has been added to the blockchain.
  - CHECKEDOUT: For evidence that has been temporarily removed by a user.
  - DISPOSED: Header for permanent removal from chain.
  - DESTROYED: Header for permanent removal from chain.
  - RELEASED: Header for permanent removal from chain (must provide with evidence owner's information upon release).
- Time: automatically generated using current timestamp
