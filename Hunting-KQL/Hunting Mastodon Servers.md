##### [mastodon-api-script](https://github.com/A-dd-Y/secops/blob/main/PythonScripts/mastodon-fqdn.py) for auto collection.

##### FQDN List : [Mastodon-FQDN-List](https://raw.githubusercontent.com/A-dd-Y/secops/main/MalwareIOC/mastodon-fqdn-list.txt)

#

```kql
let git = materialize(externaldata(RemoteUrl:string)
    [@"https://raw.githubusercontent.com/A-dd-Y/secops/main/MalwareIOC/mastodon-fqdn-list.txt"]
    with (format="txt", ignoreFirstRecord=false)
);
union (git | join (AlertEvidence | where isnotempty(RemoteUrl)) on RemoteUrl),(git | join (DeviceEvents | where isnotempty(RemoteUrl)) on RemoteUrl),
(git | join (DeviceNetworkEvents | where isnotempty(RemoteUrl)) on RemoteUrl)
//| invoke FileProfile(InitiatingProcessSHA1)
| summarize uniqueCount = count() by RemoteUrl
| sort by uniqueCount
```
#