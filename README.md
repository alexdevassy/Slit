# Slit
"Slit" is an interactive CLI build in node js which serves as an "Interface", "Enumeration" and "Dissecting" tool for exploiting Hyperledger Fabric (HLF). "Slit" is intended to be used as a red teaming tool at the infrastructure layer. "Slit" is designed with the primary aim to decrease the knowledge gap b/w a security researcher and a fabric domain expert.

*"Slit" had been deployed and tested against Hyperledger Fabric v 2.3.3*

### Installation
#### Prerequisites
Node v10.19.0  
npm 6.14.4
```
https://github.com/alexdevassy/Slit.git
cd Slit
npm install
```
### Options
Run `node slit.js -h` to view help menu in "Slit"
```

  ██████  ██▓     ██▓▄▄▄█████▓
▒██    ▒ ▓██▒    ▓██▒▓  ██▒ ▓▒
░ ▓██▄   ▒██░    ▒██▒▒ ▓██░ ▒░
  ▒   ██▒▒██░    ░██░░ ▓██▓ ░
▒██████▒▒░██████▒░██░  ▒██▒ ░
▒ ▒▓▒ ▒ ░░ ▒░▓  ░░▓    ▒ ░░
░ ░▒  ░ ░░ ░ ▒  ░ ▒ ░    ░
░  ░  ░    ░ ░    ▒ ░  ░
      ░      ░  ░ ░

Usage: node slit.js [OPTIONS]...

Options:
  -v, --version      Output the version number
  -d, --description  Get to know Slit
  -l, --list         List modules in Slit
  -r, --run          Run Slit
  -h, --HELP         Display HELP information
```
### Modules Library
"Slit" comes with an ever-growing library of modules which can be used to enumerate / exploit Hyperledger Fabric. Below are list of modules currently supported by "Slit". 
```
> Enumerate for exposed Hyperledger Fabric (HLF) nodes
        > Enter target IP address
> Enumerate for HLF environment variables
> Enumerate for exposed CouchDB endpoints
        > Enumerate environment variables
        > Enter target IP address
> Enumerate for Connection Profiles
        > Enter target directory path for enumeration (Default value is cwd)
> Attempt connecton to CA server
        > Enter path to Connection Profile
> Attempt enrolling default admin user to CA server
        > Enter path to Connection Profile
        > Enter MSPvalue
                > Enumerate Affiliations
                > Enumerate Identities
```
