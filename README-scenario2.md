# IT Toolshed Scenario 2

<!--
Author:   David Hisel <david.hisel@cyberark.com>
Updated:  <2023-08-03 13:12:01 david.hisel>
-->

## Demo Setup and Usage

IMPORTANT - Please read and configure the resources as specified in the [Prerequisites](README.md#prerequisites) section before proceding with the demo.

This demo can be run from linux/mac, or from an EC2 linux instance.

### Steps to run through the demo

1. git clone toolshed
2. cd toolshed
3. cd into the `cmd/provengine` directory
4. Make copies of the pasconfig-example.toml, awsconfig-example.toml, and conjurconfig-example.toml files (See the next section [Configuration Files](README.md#configuration-files) for detailed explanation of each field.)
   1. cp pasconfig-example.toml pasconfig.toml
   2. cp awsconfig-example.toml awsconfig.toml **# ONLY FILL OUT the Region**
   3. cp conjurconfig-example.toml conjurconfig.toml
5. Edit the config files and update the fields with the info from the Prerequisites
6. In order to start the toolshed web-app, type: `make run`
7. open a browser to <http://localhost:8080/>
8. In the browser fill in the toolshed intake form
9. Open AWS console to view the new EC2 instance
10. Open PAS Vault to view the new account for the new EC2 instance details