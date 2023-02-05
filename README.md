
# EVM From Scratch
 
Welcome to [0xMonsoon](https://twitter.com/0xmonsoon)'s implementation of the Ethereum Virtual Machine in python. Its based on this [template](https://github.com/w1nt3r-eth/evm-from-scratch). 

**Note:**
 - All the opcodes have been implemented.
 - Gas metering has not been implemented yet. Its a work in progress.	 
 - The code is poorly documented right now. Working on adding rationale for design choices.
 
## Credits

All the test cases in this repository are made by [w1nt3r.eth](https://twitter.com/w1nt3r_eth). This repository is part of the "EVM From Scratch" course (release date TBD).

Implementation inspired by [smol-evm](https://github.com/karmacoma-eth/smol-evm) and [jaglinux](https://github.com/jaglinux/evm-from-scratch).

## Commands to run

```
cd src
python3 evm.py
```
This will run the Ethereum Virtual Machine and test it against the test cases contained in `test/tests.json`.