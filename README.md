# ESM

The esm.ps1 file showcases the usage of McAfee ESM API. Using this file, the policy roll-out can be automated. Just load the file into PowerShell ISE, change the ESM IP address according to your local infrastructure, and provide the required information once executed.

#migrateDataSources

This script assists in migrating data sources between Receivers, including client data sources. Please note that child data sources are migrated into parent data sources.

The following lines have to be adapted:
21: ESM hostname/IP Address
36: ID of source Event Receiver
37: ID of target Event Receiver
