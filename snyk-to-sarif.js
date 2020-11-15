#!/usr/bin/env node
const fs = require('fs');
const { argv } = require('process');
const yargs = require('yargs');

//Verbosity Setting
let verbose = false

// Packages vulnerability and rule data into the main SARIF object structure
async function createSarif(vulnerabilities, rules) {
    return {
        $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        version: "2.1.0",
        runs: [
            {
                tool: {
                    driver: {
                        name: "Snyk",
                        rules: Object.keys(rules).map(function(key) {
                            // Retreiving all entries in the dictionary
                            return rules[key];
                        }),
                    }
                },
                results: vulnerabilities,
            }
        ]
    }
}

async function convertIACProj(projectData) {
    const ruleList = {};   
    const vulnList = [];
    const vulnArr = projectData.infrastructureAsCodeIssues;
    const affectedFile = projectData.targetFile;


    // Scans a Snyk IaC File
    for(let i = 0; i < vulnArr.length; i++) {
        const vulnerability = vulnArr[i]; 

        // Check if this is wanted as part of the results
        if (vulnerability.isIgnored) {
            continue;
        }

        let severity = "warning";
        let tags  = [ 
            "security",
            // OWASP Top Ten 2017 Category A6 - Security Misconfiguration
            "CWE-1032"
        ];        

        if (vulnerability.severity == "high") {
            severity = "error";
        }

        const formattedText = "## Overview\n" 
            + vulnerability.iacDescription.issue
            + "\n\n## Impact\n\n" + vulnerability.iacDescription.impact
            + "\n\n## Remediation\n\n" + vulnerability.iacDescription.resolve;
    
        ruleList[vulnerability.id] = {
            id: vulnerability.id,
            shortDescription: {
                text:  vulnerability.title
            },
            fullDescription: { 
                text: vulnerability.iacDescription.issue
            },
            help: {
                markdown: formattedText,
                text: "",
            },
            defaultConfiguration: {
                level: severity 
            },
            properties: {
                tags: tags
            },
        }
    
        vulnList.push({
            ruleId: vulnerability.id,
            message: { 
                text: vulnerability.title
            },
            locations: [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": affectedFile,  
                        },
                        "region": {
                            "startLine": vulnerability.lineNumber,
                            "startColumn": 1
                        }
                    }

                }
            ],
        });
    }

    return {
        vulnerabilities: vulnList,
        rules: ruleList,
    };

}

// Converts Snyk Project data into a set of "Rules" and "Vulnerability" objects using SARIF templates
async function convertProject(projectData) {
    // Check for IaC projects
    if (projectData.infrastructureAsCodeIssues) {
        return await convertIACProj(projectData)
    }

    const ruleList = {};   
    const vulnList = [];
    const vulnArr = projectData.vulnerabilities;
    const affectedFile = projectData.displayTargetFile;

    

    // Scans a Snyk Dependencies File
    for(let i = 0; i < vulnArr.length; i++) {
        const vulnerability = vulnArr[i]; 
        let severity = "warning";
        let tags  = [ 
            "security"
        ];        

        // Make sure the vuln does have identifiers          
        if(vulnerability.identifiers) {
            if("CWE" in vulnerability.identifiers) {
                tags = vulnerability.identifiers.CWE.concat(tags);
            }
        }

        if (vulnerability.severity == "high") {
            severity = "error";
        }
    
        ruleList[vulnerability.id] = {
            id: vulnerability.id,
            shortDescription: {
                text:  vulnerability.title + " - " + vulnerability.packageName
            },
            fullDescription: { 
                text: "The dependency " /
                    + vulnerability.packageName
                    + " introduces a "
                    + vulnerability.title
                    + " vulnerability",
            },
            help: {
                markdown: vulnerability.description,
                text: "",
            },
            defaultConfiguration: {
                level: severity 
            },
            properties: {
                tags: tags
            },
        }
    
        vulnList.push({
            ruleId: vulnerability.id,
            message: { 
                text: "This adds a vulnerable dependency "
                    + vulnerability.packageName
                    + " which introduces a "
                    + vulnerability.severity
                    + " severity security flaw",
            },
            locations: [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": affectedFile,  
                        }
                    }
                }
            ],
        });
    }

    return {
        vulnerabilities: vulnList,
        rules: ruleList,
    };
}

async function squashMultiProject(snykData) {
    let mergedRules = {};
    let vulnerabilityList = [];

    // Process the data
    for(let i = 0; i < snykData.length; i++) {
        // Grab the vulns and rules out of the project
        const { vulnerabilities, rules } = await convertProject(snykData[i]);   
        
        // Merge in the vulns into our list
        vulnerabilityList = vulnerabilityList.concat(vulnerabilities);

        // Merge the rules in, ignoring duplicates
        mergedRules = Object.assign({}, mergedRules, rules);
    }

    return await createSarif(vulnerabilityList, mergedRules);
}

function printHelp() {
    console.log(`
        Snyk to Sarif Options:
        -i, --input   | Allows an input snyk json file to be specified by the user
        -o, --output  | Allows a sarif output file path to be specified by the user
        -v, --verbose | Prints additional debug information
        -h, --help    | Prints the help prompt
    `); 
}

async function run(data, outputFile) {
    let snykJson, sarifData;
    try {
        snykJson = JSON.parse(data);
    } catch(e) { 
        if(verbose) {
            console.error(e);
        }
        console.error("The input data does not appear to be valid");
        return;
    }

    if(Array.isArray(snykJson)) {
        sarifData = await squashMultiProject(snykJson);
    } else { 
        const { vulnerabilities, rules } = await convertProject(snykJson); 
        sarifData = await createSarif(vulnerabilities, rules);
    }

    if(outputFile) {
        fs.writeFileSync(outputFile, JSON.stringify(sarifData));
    } else {    
        console.log(JSON.stringify(sarifData));
    }
}

async function processCommandLineArgs() {
    let snykFile;
    
    // Get command line args
    const argv = yargs(process.argv.slice(2)).argv;
    
    const inputFile = argv.i || argv.input; 
    const outputFile = argv.o || argv.output;

    // Print the help prompt and end the program
    if (argv.h != undefined || argv.help != undefined) {
        printHelp()
        return
    }

    // Toggle Verbosity
    if(argv.v != undefined || argv.verbose != undefined) {
        verbose = true;
    }


    // Checking if an input file is provided
    if (inputFile) {    

        if(fs.existsSync(inputFile)) {
            snykFile = fs.readFileSync(inputFile, 'utf8');
        } else { 
            console.log("Provided input file does not exist");
            return
        }

        run(snykFile, outputFile);

    } else {
        let data = ""
        process.stdin.setEncoding('utf8');

        process.stdin.on('data', function(chunk) {
            data += chunk;
            pipeData = true;
        });

        process.stdin.on('end', function() {
            run(data, outputFile);
        });

    }
}
processCommandLineArgs();