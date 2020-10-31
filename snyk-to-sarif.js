#!/usr/bin/env node
const fs = require('fs');
const { argv } = require('process');
const yargs = require('yargs');

async function createSarif(vulnerabilities, rules) {
    var squashedRules = Object.keys(rules).map(function(key) {
        return rules[key];
     });
    return {
        $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        version: "2.1.0",
        runs: [
            {
                tool: {driver: {name: "Snyk", rules: squashedRules}},
                results: vulnerabilities,
            }
        ]
    }
}

async function convertProject(projectData) {
    let ruleList = {};
    let vulnList = [];
    let vulnArr = projectData.vulnerabilities;
    let affectedFile = projectData.displayTargetFile;

    for(let i = 0; i < vulnArr.length; i++) {
        let vulnerability = vulnArr[i];
        let severity = "warning";
        let tags  = [];
        if("CWE" in vulnerability.identifiers) {
            tags = tags.concat(vulnerability.identifiers.CWE);
        }
        tags.push("security");

        if (vulnerability.severity == "high") {
            severity = "error";
        }
    
        ruleList[vulnerability.id] = {
            id: vulnerability.id,
            shortDescription: {text:  vulnerability.title + " - " + vulnerability.packageName},
            fullDescription: {text: "The dependency " + vulnerability.packageName + " introduces a " +vulnerability.title + " vulnerability"},
            help: {
                markdown: vulnerability.description,
                text: "",
            },
            defaultConfiguration: {level: severity},
            properties: {tags: tags},
        }
    
        let toolTip = "This adds a vulnerable dependency " + vulnerability.packageName + " which introduces a " + vulnerability.severity + " severity security flaw"; 

        vulnList.push({
            ruleId: vulnerability.id,
            message: {"text": toolTip},
            locations: [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": affectedFile},
                        //"region": {"startLine": line},
                    }
                }
            ],
        });
    }
    return {
        vulnerabilities: vulnList,
        rules: ruleList
    };
}

async function squashMultiProject(snykData) {
    let promises = [];
    let mergedRules = {};
    let vulnerabilityList = [];

    for(let i = 0; i < snykData.length; i++) {
        promise = convertProject(snykData[i]);
        promises.push(promise);
    }
    
    // Merge lists and resolving the promises
    for(let i = 0; i < promises.length; i++) {
        // Resolving promises
        let {vulnerabilities, rules} = await promises[i];
        // Adding all vulnerabilities to main list
        vulnerabilityList = vulnerabilityList.concat(vulnerabilities);
        // Merging rules and removing dupes
        mergedRules = Object.assign({}, mergedRules, rules);
    }
    // Return all rules and vulnerabilities
    return await createSarif(vulnerabilityList, mergedRules);
}

function printHelp() {
    console.log(`
        Snyk to Sarif Options:
        -i, --input  | Allows an input snyk json file to be specified by the user
        -o, --output | Allows a sarif output file path to be specified by the user
        -h, --help   | Prints the help prompt
    `)
}

async function run(data) {
    let argv = yargs(process.argv.slice(2)).argv;
    let snykJson, sarifData, snykFile;

    if (argv.h != undefined || argv.help != undefined) {
        printHelp()
        return
    }

    // Checking if an input file is provided
    if (argv.i != undefined || argv.input != undefined) {
        let inputFile = (typeof argv.i === 'undefined') ? argv.input : argv.i;
        if(fs.existsSync(inputFile)) {
            snykFile = fs.readFileSync(inputFile, 'utf8');
        }
        else {
            console.log("Provided input file does not exist")
            return
        }

        try {
            snykJson = JSON.parse(snykFile);
        }
        catch(e) {
            console.log("The input data does not appear to be valid")
            return;
        }
    }
    else // Using input from a pipe
    {
        if(data === "") {
            console.log("No data or input file provided");
            return;
        }
        snykJson = JSON.parse(data)
    }
    
    
    if(Array.isArray(snykJson)) {
        sarifData = await squashMultiProject(snykJson)
    }
    else {
        let {vulnerabilities, rules} = await convertProject(snykJson);
        sarifData = await createSarif(vulnerabilities, rules);
    }
    // Check if output is to file or terminal
    if(argv.o != undefined || argv.output != undefined) {
        let outputFile = (typeof argv.o === 'undefined') ? argv.output : argv.o;
        fs.writeFileSync(outputFile, JSON.stringify(sarifData))
    }
    else {
        console.log(JSON.stringify(sarifData))
    }
}
let data = "";
let pipeData = false;
process.stdin.resume();
process.stdin.setEncoding('utf8');

process.stdin.on('data', function(chunk) {
    data += chunk;
    pipeData = true;
});


process.stdin.on('end', function() {
    run(data)  
});

setTimeout(async function() {
    if (!pipeData) {
        await run(data)
        process.exit();
    }
}, 1000);


