---
Title:    IT Tool Shed
Author:   David Hisel <david.hisel@cyberark.com>
Updated:  <2023-07-12 15:20:50 david.hisel>
Comment:  The toolshed is an app to simulate the intake and provisioning
          of requests from application developers to IT staff to
          provision assets, and to show how to store credentials in
          CyberArk PAS.
---

## IT Toolshed

## Summary

**NOTE: "IT Toolshed" is intended as a front-end for DEMO purposes only.**

There are 2 components, the "ITSM App" and the "Provision Engine."   The "ITSM App" provides an intake form for an application developer to make a request for a resource, send the request to the provision engine, and report back to the user the access details.

The primary purpose of IT Toolshed is to serve as a facade for use in demos.  E.g. present an intake form and simulate passing the params to a backend provision engine.

The following reference diagram illustrates a high-level process flow whereby a resource is requested, provisioned, and access details are returned to the requestor.  The details of the "CyberArk PAS Automation Goes Here" are discussed below and illustrate how to onboard credentials into CyberArk PAS.

```plantuml
@startuml ReferenceProcessFlowDiagram.png

title Reference Process Flow Diagram

actor AppDev as "App Developer"
participant ITSMApp as "ITSM App\n(Ex: ServiceNow)"
participant ProvEngine as "Provision Engine\n(Ex: in-house app)"
participant Provisioner as "Provisioner\n(Ex: Terraform)"
participant Provider as "Provider\n(Ex: AWS)"

AppDev -> ITSMApp: Intake - Request Resource
ITSMApp -> ProvEngine: Start Provision Process
ProvEngine -> Provisioner: Trigger Provision
Provisioner -> Provider: Create Resource Request
Provider -> Provider: Create Resource
Provider -> Provisioner: Send Resource Details
Provisioner -> ProvEngine: Send Resource Details
ProvEngine -> ProvEngine: CyberArk PAS\nAutomation Goes Here
ProvEngine -> ITSMApp: Report Resource Access Details
ITSMApp -> AppDev: Provide Access Details
@enduml
```

### "CyberArk PAS Automation Goes Here"

#### Toolshed Simulated Architecture

```plantuml
@startuml
title Toolshed Simulated Architecture Diagram
actor AppDev as "App Developer"

AppDev -right-> [Toolshed]
[Toolshed] -right-> [ProvEngine]: (1) Submit intake
[ProvEngine] <-up- [Provider Creds\n(Conjur)]: (2) (Alternative)\nLoad creds\nIAM Auth to Conjur
[ProvEngine] <-up- [Provider Creds\n(Local FIle)]: (2) Load creds
[ProvEngine] --> [Provider]: (3) Request\nResource
[ProvEngine] <-- [Provider]: (4) Send\nResource\nDetails
[ProvEngine] --> [PASVault]: (5) Add\nAccount


json Legend {
 "Toolshed": "ITSM App\n(Ex: ServiceNow)",
 "ProvEngine": "Provision Engine\n(Ex: in-house app)",
 "Provisioner": "Provisioner\n(Ex: Terraform)",
 "Provider": "Provider\n(Ex: AWS)",
 "PASVault": "PAS Vault"
}
@enduml
```

#### Scenario 1 -- Provide Creds in a File

```plantuml
@startuml Scenario1Diagram.png
title Scenario 1 -- Provide Creds in a File
participant ProvEngine as "Provision Engine\n(Ex: in-house app)"
participant Provisioner as "Provisioner\n(Ex: Terraform)"
participant Provider as "Provider\n(Ex: AWS)"

ProvEngine -> ProvEngine: Read Provider creds from a file
ProvEngine -> Provisioner: Pass Provider creds
Provisioner -> Provider: (Provider creds) Request resource
Provider -> Provider: Create resource
Provider -> ProvEngine: Send Resource Details
ProvEngine -> ProvEngine: Store details in PAS Vault
@enduml
```

#### Scenario 2 -- Provide Creds from Conjur

```plantuml
@startuml Scenario2Diagram.png
title Scenario 2 - Provide Creds from Conjur
participant ProvEngine as "Provision Engine\n(Ex: in-house app)"
participant Provisioner as "Provisioner\n(Ex: Terraform)"
participant Provider as "Provider\n(Ex: AWS)"

note over ProvEngine #FFAAAA: HOW TO GET CONNECTION\nCREDS FOR CONJUR?
ProvEngine -> ProvEngine: Read Provider creds from Conjur
ProvEngine -> Provisioner: Pass Provider creds
Provisioner -> Provider: (Provider creds) Request resource
Provider -> Provider: Create resource
Provider -> ProvEngine: Send Resource Details
ProvEngine -> ProvEngine: Store details in PAS Vault
@enduml
```

### IT Toolshed Request Flow

```plantuml
@startuml RequestResourceFlowDiagram.png

' Render: plantuml -tpng README.md -o images

title Request Flow

actor AppDev as "App Developer"
participant Toolshed as "IT Toolshed"
participant ProvEngine as "Provision Engine"

== Request Resource ==
AppDev -> Toolshed: Request Intake Form: GET /intake
activate Toolshed
Toolshed->AppDev: Response Intake Form
deactivate Toolshed

AppDev->AppDev: Fill-in Intake Form

AppDev -> Toolshed: Submit Intake Form: POST /provision
activate Toolshed

Toolshed -> ProvEngine: (async) Exec Provision Script
rnote over ProvEngine
Call script with Intake params
endnote
ProvEngine -> ProvEngine: Provision Resource
rnote over ProvEngine
Update status when complete
endnote
Toolshed->AppDev: Respond 202
deactivate Toolshed

== Request Details ==

AppDev -> Toolshed: Request details: GET /details
activate Toolshed
Toolshed -> AppDev: Respond 102 or 200:\n200 Response includes values\nneeded for next stage

deactivate Toolshed

rnote over Toolshed
endnote

@enduml
```

### Meta

#### Document Toolchain

* [PlantUML](https://plantuml.com/starting)
* VSCode Extensions used to produce this document
  * [PlantUML](https://marketplace.visualstudio.com/items?itemName=jebbs.plantuml)
  * [Markdown Extension Pack](https://marketplace.visualstudio.com/items?itemName=bat67.markdown-extension-pack)
  * [Markdown Plantuml Preview](https://marketplace.visualstudio.com/items?itemName=myml.vscode-markdown-plantuml-preview)
* Emacs
  * Install `markdown-it`, `markdown-it-cli` and the plugins for `plantuml-ex` and `meta-header`

    ```bash
    npm install markdown-it --save
    npm install markdown-it-cli --save
    npm install markdown-it-meta-header --save
    npm install markdown-it-plantuml-ex --save
    ```

  * Recommend to download the latest plantuml.jar and replace the jar in `plantuml-ex`

    ```bash
    # use the latest plantuml.jar
    curl -sLJO https://github.com/plantuml/plantuml/releases/download/v1.2023.9/plantuml.jar -o plantuml.jar
    mv plantuml.jar ./node_modules/markdown-it-plantuml-ex/lib/plantuml.jar
    ```

  * Add this to your `.emacs.d/init.el`

    ```elisp
    ;; https://jblevins.org/projects/markdown-mode/
    ;; Using npm "markdown-it" with "meta-header" and "plantuml-ex" plugins.
    ;; Steps to install it:
    ;;  npm install markdown-it --save
    ;;  npm install markdown-it-cli --save
    ;;  npm install markdown-it-meta-header --save
    ;;  npm install markdown-it-plantuml-ex --save
    ;;  # use the latest plantuml.jar
    ;;  curl -sLJO https://github.com/plantuml/plantuml/releases/download/v1.2023.9/plantuml.jar -o plantuml.jar
    ;;  mv plantuml.jar ./node_modules/markdown-it-plantuml-ex/lib/plantuml.jar
    (use-package markdown-mode
      :ensure t
      :mode ("README\\.md\\'" . gfm-mode)
      :custom
      (markdown-command "npx markdown-it-cli")
      (markdown-command-needs-filename t)
      :config
      ;; update preview buffer when md file is saved
      (add-hook 'before-save-hook 'markdown-live-preview-re-export))
    ```

## NOTES

* [PAS Vault REST API doc](https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/WebServices/Implementing%20Privileged%20Account%20Security%20Web%20Services%20.htm?tocpath=Developer%7CREST%20APIs%7C_____0)
* [PAS Add Account](https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/WebServices/Add%20Account%20v10.htm?tocpath=Developer%7CREST%20APIs%7CAccounts%7C_____5)

* platform id: "winlocal"  # this goes into the json body
* platform id: "unixssh" # this goes into the json body

  ```json
  {
    "name": "INSTANCE ID",
    "address": "PUBLIC DNS",
    "userName": "Administrator", # or Ubuntu
    "platformId": "string",
    "safeName": "string",
    "secretType": "key",  # windows: "password"
    "secret": "string"  # PEM Key contents, or windows raw plaintext
  }
  ```

### PAS Automation MVP diagram

```plantuml
@startuml pas-automation-diagram.png

' Render: plantuml -tpng README.md -o images

title Accelerator: PAS Automation - MVP

participant "User"
participant "User compute"
participant "ProvEngine"
participant "New EC2 Instance"
participant "CyberArk Identity"
participant "CyberArk PrivCloud"
participant "CyberArk Conjur Cloud"

"User"->"ProvEngine": Submit request
"ProvEngine"->"New EC2 Instance": Provision
rnote over "New EC2 Instance"
v1: provision w/ hardcoded creds
v2: pull creds from vault
endnote
"ProvEngine"<-"New EC2 Instance": Get password
"ProvEngine"->"CyberArk Conjur Cloud": auth-iam
"ProvEngine"<-"CyberArk Conjur Cloud": Conjur Token
"ProvEngine"<-"CyberArk Conjur Cloud": Retrieve PCloud/Conjur Admin password
"ProvEngine"->"CyberArk Identity": Oauth2 conf client authn
"ProvEngine"<-"CyberArk Identity": PCloud token
"ProvEngine"->"CyberArk Identity": check if requesting user has access\nto requested safe
"ProvEngine"->"CyberArk PrivCloud": Create Windows account in existing safe
"User"<-"ProvEngine": confirmation
"User compute"->"New EC2 Instance": access EC2 instance w/ DPA or whatever
@enduml
```
