# Snyk-To-Sarif-JS
A node module that can be used to convert Snyk projects to the SARIF format. This tool is inspired by [https://github.com/garethr/snyk-to-sarif](https://github.com/garethr/snyk-to-sarif). However, it is designed to support multi-project Snyk outputs and also is built in NodeJS to be inline with other Snyk integrations and the CLI itself.

## Setup
The following command will install the application.

```npm install -g snyk-to-sarif ```

## Quick Start
The intended method of using the tool is as follows.

```snyk test --json | snyk-to-sarif -o output.sarif```

This allows the tool to easily work with the native Snyk CLI with a clear SARIF artifact produced at the end that can be uploaded and processed by any SARIF compatible tool.

## Usage
Usage of the tool follows the following format:

`snyk test --json | snyk-to-sarif -o output.sarif`

### Optional Flags
`-o, --output <Output>`        Name of the file to output to (SARIF FORMAT), if not specified the content will be printed to screen (To allow for piping).

`-i, --input <Input>`    Path to a snyk json file to read as input, note this take precendence over piped input.

`-v, --verbose `    Prints additional debug information.

`-h, --help`     Prints the help prompt