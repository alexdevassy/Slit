var request = require("request"); //requiring request module
var fs = require('fs');
var finder = require('findit')(process.argv[2] || '.');
var path = require('path');
const colors = require('colors');
const inquirer = require('inquirer');
var walk    = require('walk');
const FabricCAServices = require('fabric-ca-client');
const yaml = require('js-yaml');
const { Wallets } = require('fabric-network');

function searchenv() {
let Senvvar = ['PEER', 'ORDERER', 'FABRIC_CFG_PATH', 'CA', 'FABRIC'];
var envvalues = [];
//Enumerating env variables
console.log('Enumerating env variables')
var env = process.env;
Object.keys(env).forEach(function(key) {
  //console.log('Value is' + key + '="' + env[key] +'"');
  const foundevar = Senvvar.find(v => key.includes(v));
      if(typeof foundevar !== "undefined")
      {
        envvalues.push(
        {
          'Environment Variable': key,
          'Value': env[key]
        });
      }
});
if (envvalues.length === 0) {
console.log("No HLF environment variables were observed".brightMagenta)
}else {
console.table(envvalues);
}
DYC();
}

function filewalk(dirpath){
  var cpvalues = [];
  let regex = new RegExp(/Connection.*\.[jy][as][mo][nl]$/, "i");
  var count = 0;
  var walker  = walk.walk(dirpath, { followLinks: false });
  walker.on('file', function(root, stat, next) {
    let val = regex.test(stat.name)
    if (val){

      cpvalues.push(
      {
          'Path to file': root,
          'File name': stat.name
      });
      //console.log('Potential Connection Profile Found at ' + root + stat.name)
      count = count + 1;
    }
    next();
  });
  walker.on("end", function () {
    if (count === 0 ){
      console.log('No potential Connection Profiles were observed at '.brightMagenta, dirpath)
    } else {
   console.table(cpvalues);
   }
    DYC();
  }); //walker end
} // func filewalk end

function caconnect(x){
  return new Promise((sucess) =>{
    try {
      let connectionProfile = yaml.safeLoad(fs.readFileSync(x, 'utf8'));
      // Create a new CA client for interacting with the CA.
      const caInfo = connectionProfile.certificateAuthorities[Object.keys(connectionProfile.certificateAuthorities)[0]];
      const caTLSCACerts = caInfo.tlsCACerts.pem;
      const ca = new FabricCAServices(caInfo.url, { trustedRoots: caTLSCACerts, verify: false }, caInfo.caName);
      sucess(ca);
    } catch (error) {
        sucess('Error');
    }
  });
}

///////////////////////////////
async function enrollAdmin(caval, mspid) {
try {

const walletPath = path.join(process.cwd(), 'wallet');
const wallet = await Wallets.newFileSystemWallet(walletPath);

const enrollment = await caval.enroll({ enrollmentID: 'admin', enrollmentSecret: 'adminpw' });
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
  .prompt([
    {
      type: 'list',
      name: 'adminOptions',
      message: 'Select an Item from below list',
      choices: ['Enumerate identities', 'Enumerate affiliations'],
    },
  ])
  .then(answers => {
        if (answers.adminOptions == "Enumerate affiliations"){
            let affiliationService = caval.newAffiliationService();
            //let registeredAffiliations = affiliationService.getAll(adminUser);
            affiliationService.getAll(adminUser)
                .then(registeredAffiliations => {
                console.dir(registeredAffiliations, { depth: null })
                });
            //console.dir(registeredAffiliations, { depth: null })
            DYC();
        } else if (answers.adminOptions == "Enumerate identities") {
            let identityService = caval.newIdentityService();
            identityService.getAll(adminUser)
                .then(registeredidentities => {
                console.dir(registeredidentities, { depth: null })
                });
            //let registeredidentities = identityService.getAll(adminUser);
            //console.dir(registeredidentities, { depth: null })
            //console.log('identities')
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
///////////////////////////////

function DYC() {
inquirer
  .prompt([
    {
      type: 'list',
      name: 'DYCOptions',
      message: 'Do you want to continue?'.brightYellow,
      choices: ['Yes', 'No'],
    },
  ])
  .then(answers => {
        if (answers.DYCOptions == "No"){
                process.exit()
        } else if (answers.DYCOptions == "Yes"){
                main();
        } else {
                console.info('Answer:', answers.DYCOptions);
        }
  });

}

function main() {
inquirer
  .prompt([
    {
      type: 'list',
      name: 'Options',
      message: 'Select an Item from below list'.brightYellow,
      choices: ['Enumerate for HLF environment variables', 'Enumerate for Connection Profiles', 'Attempt connecton to CA server', 'Attempt enrolling default admin user to CA server', 'Exit'],
    },
  ])
  .then(answers => {
        if (answers.Options == "Exit"){
                process.exit()
        } else if (answers.Options == "Enumerate for HLF environment variables"){
                searchenv();
        } else if (answers.Options == "Enumerate for Connection Profiles"){
                inquirer
                  .prompt([
                    {
                      name: 'dpath',
                      message: 'Enter target directory path for enumeration (Default value is path to current working directoty): '
                    },
                  ])
                  .then(answers => {
                    if (answers.dpath){
                      filewalk(answers.dpath);
                    } else {
                      filewalk(__dirname);
                    }
                  });
        } else if (answers.Options == "Attempt connecton to CA server"){
                //searchenv();
                inquirer
                  .prompt([
                    {
                      name: 'pathcp',
                      message: 'Enter path to Connection Profile: ',
                    },
                  ])
                  .then(answers => {
                    if (answers.pathcp){
                      caconnect(answers.pathcp)
                      .then(res => {
                        if (res == "Error"){
                          console.log("Connection attempt failed".brightMagenta)
                          DYC();
                        }else{
                          //console.log(res)
                          console.log("Sucessfully connected to CA Server".brightGreen)
                          DYC();
                        }
                      });
                    } else {
                      console.log('Invalid path received'.brightMagenta)
                      DYC();
                    }
                  });
        } else if (answers.Options == "Attempt enrolling default admin user to CA server"){
        inquirer
                .prompt([
                        {
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
                        if (answers.pathcp && answers.mspval){
                                caconnect(answers.pathcp)
                                        .then(res => {
                                                if (res == "Error"){
                                                        console.log("Connection attempt failed".brightMagenta)
                                                        DYC();
                                                }else{
                                                        //console.log(res)
                                                        console.log("Sucessfully connected to CA Server".brightGreen)
                                                        enrollAdmin(res, answers.mspval);
                                                        //console.log(answers.mspval)
                                                        //DYC();
                                                }
                                        });
                        } else {
                                console.log('Invalid CP path || mspID received'.brightMagenta)
                                DYC();
                        }
        });

        } else {
                console.info('Answer:', answers.Options);
        }
  });
}
if (require.main === module) {
  main();
}
