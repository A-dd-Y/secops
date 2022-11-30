See [China-Nexus- UNC4191](https://www.mandiant.com/resources/blog/china-nexus-espionage-southeast-asia)

#### MDE Hunting Query

#

#### China-Nexus IOC Hunting

```kusto
search in (AlertEvidence, DeviceEvents, DeviceFileEvents, DeviceImageLoadEvents, DeviceProcessEvents)
Timestamp > now(-30d)
| where SHA1 has_any ("3f1cb1bef6bff56e5fcfbc03c3bbff6e45f2826a","2dd2e2fd578d64461e89f70cf85224c36fb3a442","8b8ba74b785c6c7441dbd1b90fff580771121cd4",
"86a1c40b75a5722e87057469521d7bd9e48a8d2c","d1e059851dae393d704f654da6e66a4e64559c3f","2bf5b2c50a5ace101995f1c261da62dae5a2311d",
"988ed0745f01f660f3f5d945e7f083a301fbefaa","0991f6fb6e4598d1d3cfd3eed04abd94a5e2d2b3","1b480bb3a9e73a4c1aab8f8a5ca5e1910abe44fd")
or MD5 has_any ("7753da1d7466f251b60673841a97ac5a","c10abb9f88f485d38e25bc5a0e757d1e","6900cf5937287a7ae87d90a4b4b4dec5","f632e4b9d663d69edaa8224a43b59033",
"8ec339a89ec786b2aea556bedee679c7","f45726a9508376fdd335004fca65392a","707de51327f6cae5679dee8e4e2202ba","ea7f5b7fdb1e637e4e73f6bf43dcf090")
| summarize count()
```

```kusto
search in (AlertEvidence, DeviceEvents, DeviceNetworkEvents)
Timestamp > now(-30d)
| where RemoteUrl contains "theworkpc.com"
| summarize count()
```

```kusto
search in (AlertEvidence, DeviceEvents, DeviceFileEvents,DeviceImageLoadEvents,DeviceProcessEvents)
Timestamp > now(-30d)
| where FolderPath contains @"C:\ProgramData\udisk" or FolderPath contains @"C:\Users\Public\Libraries\CNNUDTV"
| summarize count()
```

#

#### China-Nexus TTPs Hunting

##### The attacker use initial infection via USB devices, the threat actor leveraged legitimately signed binaries to side-load malware, including three new families Mandiant refer to as MISTCLOAK, DARKDEW, and BLUEHAZE. Successful compromise led to the deployment of a renamed NCAT binary and execution of a reverse shell on the victim’s system, providing backdoor access to the threat actor. The malware self-replicates by infecting new removable drives that are plugged into a compromised system, allowing the malicious payloads to propagate to additional systems and potentially collect data from air-gapped systems.

```kusto
search in (AlertEvidence, DeviceEvents, DeviceProcessEvents)
Timestamp > now(-30d)
| where (ProcessCommandLine contains "nltest /domain_trusts /all_Trusts" or ProcessCommandLine contains "net group \"Domain Admins\" /domain" or ProcessCommandLine contains "net group \"Administrators\"")
or (ProcessCommandLine contains "/C reg add " and ProcessCommandLine contains @"\CurrentVersion\Run" and (ProcessCommandLine contains ".exe" or ProcessCommandLine contains ".dll"))
or (ProcessCommandLine contains "explorer" and ProcessCommandLine contains @"\autorun.inf")
or (ProcessCommandLine contains "/C copy" and ProcessCommandLine contains @"C:\\Users\\Public\\Libraries\\")
or (ProcessCommandLine contains "/C wuwebv.exe -t -e " and ProcessCommandLine contains @"C:\\Windows\\System32\\cmd.exe")
| summarize CmdLine = count() by ProcessCommandLine | sort by CmdLine
```

```kusto
search in (DeviceEvents,DeviceFileEvents,DeviceImageLoadEvents,DeviceLogonEvents,DeviceNetworkEvents,DeviceProcessEvents,DeviceRegistryEvents)
Timestamp > now(-30d)
| where (InitiatingProcessCommandLine contains "nltest /domain_trusts /all_Trusts" or InitiatingProcessCommandLine contains "net group \"Domain Admins\" /domain" or InitiatingProcessCommandLine contains "net group \"Administrators\"")
or (InitiatingProcessCommandLine contains "/C reg add " and InitiatingProcessCommandLine contains @"\CurrentVersion\Run" and (ProcessCommandLine contains ".exe" or InitiatingProcessCommandLine contains ".dll"))
or (InitiatingProcessCommandLine contains "explorer" and InitiatingProcessCommandLine contains @"\autorun.inf")
or (InitiatingProcessCommandLine contains "/C copy" and InitiatingProcessCommandLine contains @"C:\\Users\\Public\\Libraries\\")
or (InitiatingProcessCommandLine contains "/C wuwebv.exe -t -e " and InitiatingProcessCommandLine contains @"C:\\Windows\\System32\\cmd.exe")
| summarize CmdLine = count() by InitiatingProcessCommandLine | sort by CmdLine
```


```kusto
search in (DeviceEvents,DeviceFileEvents,DeviceImageLoadEvents,DeviceLogonEvents,DeviceNetworkEvents,DeviceProcessEvents,DeviceRegistryEvents)
Timestamp > now(-30d)
| where InitiatingProcessFolderPath contains @"C:\Users\Public\Libraries\"
| summarize count()
```


```kusto
search in (DeviceEvents,DeviceFileEvents,DeviceImageLoadEvents,DeviceLogonEvents,DeviceNetworkEvents,DeviceProcessEvents,DeviceRegistryEvents)
Timestamp > now(-30d)
| where (InitiatingProcessFolderPath contains @"D:\" and ProcessCommandLine contains @"\autorun.inf\")
or InitiatingProcessVersionInfoOriginalFileName contains "RzCefRenderProcess.exe"
| summarize ucount = count() by ActionType | sort by ucount
```

#