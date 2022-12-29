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