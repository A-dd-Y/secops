import requests, json, urllib3, sys
urllib3.disable_warnings()

###################################################################################################


def remove(duplicate):

    final_list = []
    for num in duplicate:
        if num not in final_list:
            final_list.append(num)

    return final_list


def savefile():
    print("\n", f"* Collecting mastodon fqdn list from instances.social...", "\n")
    fqdn = get_fqdn()
    name = 'mastodon-fqdn-list.txt'
    path = '/change/this/path/' # <<<<<<<<<<<<<<<<************** changethis
    reso = path+name
    with open(reso,'w') as file:
        for rec in fqdn:
            file.write(rec)
            file.write('\n')
    print("\t", "...Completed!!", "\n")
    return None


###################################################################################################

def get_fqdn():
    url = 'https://instances.social/api/1.0/instances/list'

    headers = {
        'Authorization': 'Bearer <API>', # <<<<<<<<<<<<<<<<************** changethis
    }

    params = (
        ('count', '0'),
    )

    fqdn = []

    res = requests.get(url,headers=headers,params=params)

    if res.status_code == 200:
        jd = json.loads(res.text)
        for name in jd['instances']:
            fqdn.append(name['name'])
        remove(fqdn)
    else:
        sys.exit()
    return fqdn
###################################################################################################

savefile()