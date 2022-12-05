### source : mwdb / triage

#### #emotet, #qakbot, #icedid

##### python3 API [script](https://github.com/A-dd-Y/secops/blob/main/PythonScripts/github-mwdb-triage.py) for auto collection.

##### IOCs of all 3 are merged in single file, for seperate IOC, please check [This Folder.](https://github.com/A-dd-Y/secops/tree/main/MalwareIOC)

#

##### IOC Update : Weekly
##### Caution : It's an auto IOC collection with API and may contain False Positives. !!

#

##### SHA256 Query

```kql
let git = materialize(externaldata(SHA256:string)
    [@"https://raw.githubusercontent.com/A-dd-Y/secops/main/MalwareIOC/SHA256.txt"]
    with (format="txt", ignoreFirstRecord=false)
);
union (git | join (AlertEvidence | where isnotempty(SHA256)) on SHA256),(git | join (DeviceEvents | where isnotempty(SHA256)) on SHA256),
(git | join (DeviceFileEvents | where isnotempty(SHA256)) on SHA256),(git | join (DeviceImageLoadEvents | where isnotempty(SHA256)) on SHA256),
(git | join (DeviceProcessEvents | where isnotempty(SHA256)) on SHA256),(git | join (EmailAttachmentInfo | where isnotempty(SHA256)) on SHA256)
| summarize uniqueCount = count() by SHA256
| sort by uniqueCount
```


##### C2 Query

```kql
let git = materialize(externaldata(RemoteIP:string, RemotePort:string)
    [@"https://raw.githubusercontent.com/A-dd-Y/secops/main/MalwareIOC/C2.txt"]
    with (format="txt", ignoreFirstRecord=true)
);
union (git | join (AlertEvidence | where isnotempty(RemoteIP)) on RemoteIP),(git | join (DeviceEvents | where isnotempty(RemoteIP)) on RemoteIP),
(git | join (DeviceNetworkEvents | where isnotempty(RemoteIP)) on RemoteIP),(git | join (DeviceLogonEvents | where isnotempty(RemoteIP)) on RemoteIP)
//| invoke FileProfile(InitiatingProcessSHA1)
| summarize uniqueCount = count() by RemoteIP
| sort by uniqueCount
```

```kql
let git = materialize(externaldata(RemoteUrl:string, RemotePort:string)
    [@"https://raw.githubusercontent.com/A-dd-Y/secops/main/MalwareIOC/C2.txt"]
    with (format="txt", ignoreFirstRecord=true)
);
union (git | join (AlertEvidence | where isnotempty(RemoteUrl)) on RemoteUrl),(git | join (DeviceEvents | where isnotempty(RemoteUrl)) on RemoteUrl),
(git | join (DeviceNetworkEvents | where isnotempty(RemoteUrl)) on RemoteUrl)
//| invoke FileProfile(InitiatingProcessSHA1)
| where not(RemoteUrl has_any ("google.com","gmail.com"))
| summarize uniqueCount = count() by RemoteUrl
| sort by uniqueCount
```
#