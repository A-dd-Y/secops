#### Calculate Shannon Entropy in KQL

see [Shannon Entropy](https://en.wikipedia.org/wiki/Entropy_(information_theory))

#

```kql
let ideal_entropy = (len:int)
{
    let prob = 1.0 / len ;
    print IdealEntropy = - 1.0 * len * (prob) * log(prob) / log(2.0)
};
ideal_entropy(20)
```
#

```kql
let shannon = view(str:string)
{
    let utf = to_utf8(str);
    let strlen = strlen(str);
    print characters = utf, length = strlen
    | mv-expand characters | summarize unique_char = count() by tostring(characters),length | project-away characters
    | extend prob = todecimal(unique_char) / todecimal(length)
    | extend cal = - prob * log(prob) / log(2.0)
    | summarize Entropy = round(sum(cal),5)
};
shannon("calculating shannon entropy ... 123$%^")
```

#

##### URL Entropy

```kql
DeviceNetworkEvents
| where Timestamp > now(-1m)
| where isnotempty(RemoteUrl)
| extend utf = to_utf8(RemoteUrl)
| extend urllen = strlen(RemoteUrl)
| distinct RemoteUrl, tostring(utf), urllen
| mv-expand todynamic(utf) | summarize uniq = count() by tostring(utf), urllen, RemoteUrl | project urllen, uniq, RemoteUrl
| extend prob = todecimal(uniq) / todecimal(urllen)
| extend cal = - prob * log(prob) / log(2.0)
| summarize entropy = round(sum(cal),5) by RemoteUrl, urllen | sort by entropy desc
```

#

##### CommandLine Entropy

```kql
DeviceProcessEvents
| where Timestamp > now(-1m)
| where isnotempty(ProcessCommandLine)
| extend utf = to_utf8(ProcessCommandLine)
| extend cmdlen = strlen(ProcessCommandLine)
| distinct ProcessCommandLine, tostring(utf), cmdlen
| mv-expand todynamic(utf) | summarize uniq = count() by tostring(utf), cmdlen, ProcessCommandLine | project cmdlen, uniq, ProcessCommandLine
| extend prob = todecimal(uniq) / todecimal(cmdlen)
| extend cal = - prob * log(prob) / log(2.0)
| summarize entropy = round(sum(cal),5) by ProcessCommandLine, cmdlen | sort by entropy desc
```

#

##### CommandLine Entropy

```kql
DeviceProcessEvents
| where Timestamp > now(-1m)
| where isnotempty(InitiatingProcessCommandLine)
| extend utf = to_utf8(InitiatingProcessCommandLine)
| extend cmdlen = strlen(InitiatingProcessCommandLine)
| distinct InitiatingProcessCommandLine, tostring(utf), cmdlen
| mv-expand todynamic(utf) | summarize uniq = count() by tostring(utf), cmdlen, InitiatingProcessCommandLine | project cmdlen, uniq, InitiatingProcessCommandLine
| extend prob = todecimal(uniq) / todecimal(cmdlen)
| extend cal = - prob * log(prob) / log(2.0)
| summarize entropy = round(sum(cal),5) by InitiatingProcessCommandLine, cmdlen | sort by entropy desc
```

#