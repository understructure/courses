import boto3
import json
import os


def create_client(profile="default", client_type="ec2"):
    """
    I create a client (usually ec2) that can be used to setup VPCs, security groups, instances, etc.
    :param profile: String
    :return: boto3.Session.client
    """
    session = boto3.Session(profile_name=profile)
    # Any clients created from this session will use credentials
    # from the [dev] section of ~/.aws/credentials.
    client = session.client(client_type)
    return client


def find_resource_by_tag(client, tag_key, tag_value, return_value, fx, items_key):
    """
    I return an attribute (usually the id) from a response from the AWS boto3 library.
    :param client: 
    :param tag_key: 
    :param tag_value: 
    :param return_value: 
    :param fx: 
    :param items_key: 
    :return: 
    """
    retval = None
    items = fx
    for v in items[items_key]:
        if v.get("Tags", None):
            for t in v.get("Tags"):
                if t["Key"] == tag_key and t["Value"] == tag_value:
                    retval = v[return_value]
    return retval


def conflicting_subnet_exists(client, vpc_id, cidr_block):
    """
    I return a subnet ID if one exists that will conflict with a CIDR block in a VPC.
    :param client:
    :param vpc_id:
    :param cidr_block:
    :return:
    """
    subz = client.describe_subnets()
    cidrz = [sub["SubnetId"] for sub in subz["Subnets"] if sub["VpcId"] == vpc_id and sub["CidrBlock"] == cidr_block]
    return cidrz


def create_subnet(client, vpc_id, vpc_name, cidr_block="10.0.0.0/28"):
    """

    :param client:
    :param vpc_id:
    :param vpc_name:
    :param cidr_block:
    :return:
    """
    response = client.create_subnet(VpcId=vpc_id, CidrBlock=cidr_block)
    assert response["ResponseMetadata"]["HTTPStatusCode"] == 200
    subnet_id = response["Subnet"]["SubnetId"]
    response = client.create_tags(Resources=[subnet_id], Tags=[{"Key": "Name", "Value": vpc_name + "-subnet"}])
    assert response["ResponseMetadata"]["HTTPStatusCode"] == 200
    return subnet_id


def create_route_table(client, vpc_id):
    """

    :param client:
    :param vpc_id:
    :return:
    """
    response = client.create_route_table(VpcId=vpc_id)
    assert response["ResponseMetadata"]["HTTPStatusCode"] == 200
    route_table_id = response["RouteTable"]["RouteTableId"]
    return route_table_id


def create_route(client, route_table_id, gateway_id, dest_cidr_block="0.0.0.0/0"):
    """

    :param client:
    :param route_table_id:
    :param gateway_id:
    :param dest_cidr_block:
    :return:
    """
    response = client.create_route(RouteTableId=route_table_id, DestinationCidrBlock=dest_cidr_block, GatewayId=gateway_id)
    assert response["ResponseMetadata"]["HTTPStatusCode"] == 200
    assert response["Return"] == True


def get_create_vpc(client, str_name, cidr_block="10.0.0.0/28"):
    """

    :param client:
    :param str_name:
    :param cidr_block:
    :return:
    """
    vpc_id = find_resource_by_tag(client, "Name", str_name, "VpcId", client.describe_vpcs(), 'Vpcs')
    if len(vpc_id):
        print("VPC {} exists, VpcId: {}".format(str_name, vpc_id))
    else:
        response = client.create_vpc(CidrBlock=cidr_block)
        vpc_id = response["Vpc"]["VpcId"]
        response = client.create_tags(Resources=[vpc_id], Tags=[{"Key": "Name", "Value": str_name}])
        success = response['ResponseMetadata']['HTTPStatusCode'] == 200

        client.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames = {"Value": True})
        client.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport = {"Value": True})
        print("VPC {} created successfully, VpcId: {}".format(str_name, vpc_id))
    return vpc_id


def check_gateway_attached(client, gateway_id, vpc_id):
    """

    :param client:
    :param gateway_id:
    :param vpc_id:
    :return:
    """
    gateways = client.describe_internet_gateways(InternetGatewayIds=[gateway_id])

    if len(gateways["InternetGateways"][0]["Attachments"]):
        attached_vpc_id = gateways["InternetGateways"][0]["Attachments"][0]["VpcId"]
        print("Gateway {} is attached to VPC {}".format(gateway_id, attached_vpc_id))
        return True
    else:
        print("Need to attach gateway {} to vpc {}".format(gateway_id, vpc_id))
        return False


def get_create_authorize_security_group(client, seg_name, lst_ports, ingress_cidr):
    """
    I should probably be broken up into smaller functions.
    :param client: boto3.Session.client (ec2)
    :param seg_name: String - name of the security group
    :param lst_ports: Dict - dict of p_to, p_from keys.  Should also have p_protocol.
    :param ingress_cidr: - CIDR block to allow ingress for ports, should probably be in the dict.
    :return:
    """
    group_setup = False
    ports_already_setup = []
    segs = client.describe_security_groups()
    for g in segs["SecurityGroups"]:
        if g["GroupName"] == seg_name:
            group_setup = True
            security_group_id = g["GroupId"]
            for p in g["IpPermissions"]:
                for port in lst_ports:
                    if port.get("p_from", None) == p["FromPort"] and port.get("p_to", None) == p["ToPort"]:
                        # ports already setup
                        ports_already_setup.append(port)
                        if len(lst_ports) == len(ports_already_setup):
                            break
                    
    if not group_setup:
        print("Creating security group {}".format(seg_name))
        response = client.create_security_group(VpcId=vpc_id, GroupName=seg_name, Description=group_desc)
        security_group_id = response["GroupId"]
    else:
        print("Security group {} exists, GroupId is {}".format(seg_name, security_group_id))
    
    ports_to_setup = [x for x in lst_ports if x not in ports_already_setup]
    if len(ports_to_setup):
        for p in ports_to_setup:
            response = client.authorize_security_group_ingress(GroupId=security_group_id, IpPermissions=[{'FromPort': p["p_from"], 'ToPort': p["p_to"], 'IpProtocol': 'tcp', 'IpRanges': [{'CidrIp': ingress_cidr}]}])
            assert response["ResponseMetadata"]["HTTPStatusCode"] == 200
    return security_group_id





def create_ssh_key(client, vpc_name, delete_first=False):
    """

    :param client:
    :param vpc_name:
    :param delete_first: Boolean - whether to try to delete the key first and recreate it
    :return:
    """
    key_name = "aws-key-" + vpc_name
    home = str(Path.home())
    ssh_dir = os.sep.join([home, ".ssh/"])
    key_path = ssh_dir + key_name + ".pem"

    if delete_first:
        try:
            client.delete_key_pair(KeyName=key_name)
            print("Key {} deleted successfully".format(key_name))
        except:
            pass

    d_key = None
    try:
        client.describe_key_pairs(KeyNames=[key_name])
    except:
        d_key = client.create_key_pair(KeyName=key_name)

    if d_key is not None:
        with open(key_path, 'w') as f:
            try:
                f.write(d_key["KeyMaterial"])
                print("Key {} written successfully".format(key_name))
            except Exception as e:
                print(str(e))
                exit(1)
    else:
        with open(key_path, 'r') as f:
            str_key = f.read()
        if len(str_key):
            print("Key already exists and is in .ssh directory")
        else:
            print("Could not load key file text, aborting")
            exit(1)
    return key_name


def main(my_profile="default", vpc_name="fast-ai", cidr_block="10.0.0.0/28", ingress_cidr = "0.0.0.0/0"):
    """

    :param my_profile: String - name of a profile used with AWS (in ~/.aws/credentials)
    :param vpc_name: String - name of the VPC that will be appended to the beginning of all other named objects created.
    :param cidr_block:
    :return:
    """

    ec2_client = create_client(my_profile)
    vpc_id = get_create_vpc(ec2_client, vpc_name)
    
    # see if gateway exists
    fastai_gateway = find_resource_by_tag(ec2_client, "Name", vpc_name + "-gateway", "InternetGatewayId", ec2_client.describe_internet_gateways(), 'InternetGateways')
    
    if fastai_gateway:
        # check attached
        print("Internet Gateway {} exists".format(vpc_id))
        attached = check_gateway_attached(ec2_client, fastai_gateway, vpc_id)
        if not attached:
            response = attach_gateway(ec2_client, fastai_gateway, vpc_id)
            assert response["ResponseMetadata"]["HTTPStatusCode"] == 200
    else:
        response = ec2_client.create_internet_gateway()
        assert response["ResponseMetadata"]["HTTPStatusCode"] == 200
        print("Internet Gateway {} created successfully".format(vpc_id))
        gateway_id = response["InternetGateway"]["InternetGatewayId"]
        response = attach_gateway(ec2_client, gateway_id, vpc_id)
        assert response["ResponseMetadata"]["HTTPStatusCode"] == 200
    
    subnet_id = find_resource_by_tag(ec2_client, "Name", vpc_name + "-subnet", "SubnetId", ec2_client.describe_subnets(), 'Subnets')
    if not subnet_id:
        # check to make sure it's not there and just not tagged as fast-ai-subnet
        exists_untagged = conflicting_subnet_exists(ec2_client, vpc_id, cidr_block)
        if not exists_untagged:
            subnet_id = create_subnet(ec2_client, vpc_id, vpc_name, cidr_block)
        else:
            subnet_id = exists_untagged[0]
        response = ec2_client.create_tags(Resources=[subnet_id], Tags=[{"Key": "Name", "Value": vpc_name + "-subnet"}])
        assert response["ResponseMetadata"]["HTTPStatusCode"] == 200
    print("Subnet {} created and tagged successfully".format(subnet_id))
    
    # route table
    route_table_id = find_resource_by_tag(ec2_client, "Name", vpc_name + "-route-table", "RouteTableId", ec2_client.describe_route_tables(), "RouteTables")

    if route_table_id:
        pass
        # technically should check to make sure it's setup right and in the correct vpc
        #     route_table = client.describe_route_tables(RouteTableIds=[route_table_id])
        #     if route_table["RouteTables"][0]["VpcId"] != vpc_id:
        #         d_route["route_table_id"] = create_route_table(ec2_client, vpc_id)
    else:
        route_table_id = create_route_table(ec2_client, vpc_id)

    response = ec2_client.create_tags(Resources=[route_table_id], Tags=[{"Key": "Name", "Value": vpc_name + "-route-table"}])
    assert response["ResponseMetadata"]["HTTPStatusCode"] == 200

    response = ec2_client.associate_route_table(RouteTableId=route_table_id, SubnetId=subnet_id)
    assert response["ResponseMetadata"]["HTTPStatusCode"] == 200
    association_id = response["AssociationId"]
    
    # security group
    security_group_id = get_create_authorize_security_group(ec2_client, vpc_name + "-security-group", [{"p_from":22, "p_to":22}, {"p_from": 8888, "p_to":8898}], ingress_cidr)
    assert len(security_group_id) > 0

    key_name = create_ssh_key(client, vpc_name, delete_first=False)

# testing:
# main("captech")

# troubleshooting:
# client = create_client("captech")


# wipe out objects so we can start over
# vpc_id = get_create_vpc(client, "fast-ai")
# client.delete_vpc(VpcId=vpc_id)
# client.describe_vpcs(VpcIds=[vpc_id])
