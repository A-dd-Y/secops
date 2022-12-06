#!/usr/bin/env python

""" MWDB/Triage IOC [C2, SHA256] Collection.

This program is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation, either version 3 of the License, or any later version.

This program is distributed in the hope that it will be useful, but WITHOUT
ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
You should have received a copy of the GNU General Public License along with
this program. If not, see <http://www.gnu.org/licenses/>.
"""

__date__ = "2022/11/22"
__author__ = "secops_addy"
__contact__ = "@secops_addy"
__license__ = "GPLv3"

import requests, json, urllib3, sys

urllib3.disable_warnings()
argumentList = sys.argv[1:]

###################################################################################################

mwdbAPI = ""
triageAPI = ""

path = "C:\\Users\\"

###################################################################################################


def remove(duplicate):

    final_list = []
    for num in duplicate:
        if num not in final_list:
            final_list.append(num)

    return final_list


###################################################################################################


def mwdbMain():

    payload = {}
    headers = {
        "accept": "application/json",
        "Authorization": "Bearer " + mwdbAPI,
        "connection": "keep-alive",
    }
    tag = familyOption
    hash_array = []
    c2_array = []

    try:

        def getHash():

            url = "https://virus.exchange/api/file/count?query=tag:"
            uri = url + tag
            response = requests.get(uri, headers=headers, data=payload, verify=False)
            jsonData = json.loads(response.text)
            sample_count = jsonData["count"]

            url = "https://virus.exchange/api/file?query=tag:"

            query = url + tag
            response = requests.get(query, headers=headers, data=payload, verify=False)
            jsonData = json.loads(response.text)
            for sha256 in jsonData["files"]:
                hash_array.append(sha256["sha256"])
            # loop_count = sample_count / 10
            loop_count = int(sampleCountOption) / 10
            if loop_count > 1:
                for i in range(1, int(loop_count)):
                    try:
                        older_than = hash_array[-1]
                        url = (
                            "https://virus.exchange/api/file?older_than="
                            + older_than
                            + "&query=tag:"
                        )
                        query = url + tag
                        response = requests.get(
                            query, headers=headers, data=payload, verify=False
                        )
                        jsonData = json.loads(response.text)
                        for sha256 in jsonData["files"]:
                            hash_array.append(sha256["sha256"])
                        i += 1
                        if i <= loop_count:
                            continue
                        else:
                            break
                    except Exception as e:
                        print(e, "Error !!!")
                        pass
            return remove(hash_array)

    except Exception as e:
        print(e, "Error !!!")

    try:

        def getC2():

            c2_array_raw = []
            for i in hash_array:
                try:
                    url = "https://virus.exchange/api/file/"
                    uri = url + i
                    response = requests.get(
                        uri, headers=headers, data=payload, verify=False
                    )
                    jsonData = json.loads(response.text)
                    try:
                        c2_array_raw = jsonData["latest_config"]["cfg"]["c2"]
                    except:
                        pass
                    try:
                        c2_array_raw = jsonData["latest_config"]["cfg"]["decoy"]
                    except:
                        pass
                    for c2 in c2_array_raw:
                        c2 = c2.replace("/", "")
                        c2 = c2.replace("http:", "")
                        c2 = c2.replace("https:", "")
                        c2 = c2.replace(":", ",")
                        c2_array.append(c2)
                except Exception as e:
                    print(e, "Error !!!")
                    pass
            return remove(c2_array)

    except Exception as e:
        print(e, "Error !!!")

    try:

        def saveFile():

            print("\n", f"* Collecting {tag} SHA256 from MWDB...", "\n")
            hash = getHash()
            name = "mwdb-" + tag + "-sha256.txt"
            rec = path + name
            with open(rec, "w") as hf:
                for i in hash:
                    hf.write(i)
                    hf.write("\n")
            print("\t", "...Completed!!", "\n")
            print(f" * Collecting {tag} C2 from MWDB...", "\n")
            c2 = getC2()
            name = "mwdb-" + tag + "-c2.txt"
            rec = path + name
            with open(rec, "w") as cf:
                for i in c2:
                    cf.write(i)
                    cf.write("\n")
            print("\t", "...Completed!!", "\n")
            return

    except Exception as e:
        print(e, "Error !!!")

    saveFile()
    print("\n", "...All Done!!", "\n\n")

    return


###################################################################################################


def triageMain():

    payload = {}
    headers = {
        "accept": "application/json",
        "Authorization": "Bearer " + triageAPI,
        "connection": "keep-alive",
    }
    score = "10"
    family = familyOption
    c2_array = []
    sample_id = []
    hash_array = []

    try:

        def getSampleID():

            url = "https://tria.ge/api/v0/search?query="
            uri = url + "family:" + family + "+AND+" + "score:" + score
            response = requests.get(uri, headers=headers, data=payload, verify=False)
            if response.status_code == 200:
                jsonData = json.loads(response.text)
                if len(jsonData["data"]) != 0:
                    for id in jsonData["data"]:
                        sample_id.append(id.get("id"))
                    if not (jsonData.get("next") is None):
                        offset = jsonData["next"]
                        while True:
                            try:
                                if len(sample_id) <= int(sampleCountOption):
                                    uri_next = uri + "&offset=" + offset
                                    response = requests.get(
                                        uri_next,
                                        headers=headers,
                                        data=payload,
                                        verify=False,
                                    )
                                    if response.status_code == 200:
                                        jsonData = json.loads(response.text)
                                        for id in jsonData["data"]:
                                            sample_id.append(id.get("id"))
                                        if not (jsonData.get("next") is None):
                                            offset = jsonData["next"]
                                        else:
                                            break
                                else:
                                    break
                            except Exception as e:
                                print(e, "Error !!!")
                                pass

            return remove(sample_id)

    except Exception as e:
        print(e, "Error !!!")

    try:

        def getData():

            c2_raw = []
            for sid in sample_id:
                try:
                    uri = "https://tria.ge/api/v0/samples/" + sid + "/overview.json"
                    response = requests.get(
                        uri, headers=headers, data=payload, verify=False
                    )
                    if response.status_code == 200:
                        jsonData = json.loads(response.text)
                        try:
                            c2_raw = jsonData["extracted"][0]["config"]["c2"]
                        except:
                            pass
                        try:
                            c2_raw = jsonData["extracted"][1]["config"]["c2"]
                        except:
                            pass
                        for c2 in c2_raw:
                            c2 = c2.replace("/", "")
                            c2 = c2.replace("http:", "")
                            c2 = c2.replace("https:", "")
                            c2 = c2.replace(":", ",")
                            c2_array.append(c2)
                        sha_raw = jsonData["sample"]["sha256"]
                        hash_array.append(sha_raw)
                except Exception as e:
                    print(e)
                    pass

            return remove(c2_array), remove(hash_array)

    except Exception as e:
        print(e, "Error !!!")

    try:

        def saveFile():

            getSampleID()
            print("\n", f"* Collecting {family} C2 & SHA256 from Triage...", "\n")
            C2_Data, Hash_Data = getData()
            name = "triage-" + family + "-sha256.txt"
            rec = path + name
            with open(rec, "w") as hf:
                for i in Hash_Data:
                    hf.write(i)
                    hf.write("\n")
            name = "triage-" + family + "-c2.txt"
            rec = path + name
            with open(rec, "w") as cf:
                for i in C2_Data:
                    cf.write(i)
                    cf.write("\n")
            print("\t", "...Completed!!", "\n")

            return

    except Exception as e:
        print(e, "Error !!!")

    saveFile()
    print("\n", "...All Done!!", "\n\n")

    return


###################################################################################################


def helpFun():

    print(
        "\n",
        "example : -s mwdb -t emotet -c 20 (enter multiple of 10)",
        "\n\t",
        "  -s triage -t qakbot -c 100 (enter multiple of 50)",
        "\n\n",
    )
    print(argumentList)

    return


try:
    sourceOption = sys.argv[2]
    familyOption = sys.argv[4]
    sampleCountOption = sys.argv[6]
except:
    helpFun()
    sys.exit()

if sourceOption == "mwdb":
    try:
        mwdbMain()
    except Exception as e:
        print(e, "Error !!!")
elif sourceOption == "triage":
    try:
        triageMain()
    except Exception as e:
        print(e, "Error !!!")
else:
    helpFun()
    sys.exit()

###################################################################################################
