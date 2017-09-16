import boto3

def get_items_by_key_subkey(fx, items_key, sub_key, subkey_value):
    lst_groups = []

    items = fx
    for v in items[items_key]:
        if v[sub_key] == subkey_value:
            lst_groups.append(v)
    return lst_groups


def delete_security_groups(client, group_name):
    sgs = get_items_by_key_subkey(client.describe_security_groups(), items_key = "SecurityGroups", sub_key="GroupName", subkey_value=group_name)
    print("Found a total of {} security groups".format(len(sgs)))
    if sgs:
        for group in sgs:
            client.delete_security_group(GroupId=group["GroupId"])
