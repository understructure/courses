
import boto3
from datetime import datetime, timedelta
import json
import math
import sys
import time
import os
from pathlib import Path


def find_resource_by_tag(client, tag_key, tag_value, return_value, fx, items_key):
    """

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
    subz = client.describe_subnets()
    cidrz = [sub["SubnetId"] for sub in subz["Subnets"] if sub["VpcId"] == vpc_id and sub["CidrBlock"] == cidr_block]
    return cidrz


def create_client(profile="default"):
    session = boto3.Session(profile_name=profile)
    # Any clients created from this session will use credentials
    # from the [dev] section of ~/.aws/credentials.
    client = session.client('ec2')
    return client


def create_subnet(client, vpc_id, vpc_name, cidr_block="10.0.0.0/28"):
    response = client.create_subnet(VpcId=vpc_id, CidrBlock=cidr_block)
    assert response["ResponseMetadata"]["HTTPStatusCode"] == 200
    subnet_id = response["Subnet"]["SubnetId"]
    response = client.create_tags(Resources=[subnet_id], Tags=[{"Key": "Name", "Value": vpc_name + "-subnet"}])
    assert response["ResponseMetadata"]["HTTPStatusCode"] == 200
    return subnet_id


def create_route_table(client, vpc_id):
    response = client.create_route_table(VpcId=vpc_id)
    assert response["ResponseMetadata"]["HTTPStatusCode"] == 200
    route_table_id = response["RouteTable"]["RouteTableId"]
    return route_table_id


def create_route(client, route_table_id, gateway_id, dest_cidr_block="0.0.0.0/0"):
    response = client.create_route(RouteTableId=route_table_id, DestinationCidrBlock=dest_cidr_block,
                                   GatewayId=gateway_id)
    assert response["ResponseMetadata"]["HTTPStatusCode"] == 200
    assert response["Return"] == True


def get_create_vpc(client, str_name, cidr_block="10.0.0.0/28"):
    vpc_id = find_resource_by_tag(client, "Name", str_name, "VpcId", client.describe_vpcs(), 'Vpcs')
    if vpc_id:
        print("VPC {} exists, VpcId: {}".format(str_name, vpc_id))
    else:
        response = client.create_vpc(CidrBlock=cidr_block)
        vpc_id = response["Vpc"]["VpcId"]
        response = client.create_tags(Resources=[vpc_id], Tags=[{"Key": "Name", "Value": str_name}])
        assert response['ResponseMetadata']['HTTPStatusCode'] == 200

        client.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})
        client.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
        print("VPC {} created successfully, VpcId: {}".format(str_name, vpc_id))
    return vpc_id


def check_gateway_attached(client, gateway_id, vpc_id):
    gateways = client.describe_internet_gateways(InternetGatewayIds=[gateway_id])

    if len(gateways["InternetGateways"][0]["Attachments"]):
        attached_vpc_id = gateways["InternetGateways"][0]["Attachments"][0]["VpcId"]
        print("Gateway {} is attached to VPC {}".format(gateway_id, attached_vpc_id))
        return True
    else:
        print("Need to attach gateway {} to vpc {}".format(gateway_id, vpc_id))
        return False


def attach_gateway(client, gateway_id, vpc_id):
    response = client.attach_internet_gateway(InternetGatewayId=gateway_id, VpcId=vpc_id)
    assert response["ResponseMetadata"]["HTTPStatusCode"] == 200
    return response


def get_create_authorize_security_group(client, vpc_id, seg_name, lst_ports, ingress_cidr, group_desc):
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
            response = client.authorize_security_group_ingress(GroupId=security_group_id, IpPermissions=[
                {'FromPort': p["p_from"], 'ToPort': p["p_to"], 'IpProtocol': 'tcp',
                 'IpRanges': [{'CidrIp': ingress_cidr}]}])
            assert response["ResponseMetadata"]["HTTPStatusCode"] == 200
    return security_group_id


def get_ami(region):
    if region == "us-west-2":
        ami = "ami-f8fd5998"
    elif region == "eu-west-1":
        ami = "ami-9e1a35ed"
    elif region == "us-east-1":
        ami = "ami-9c5b438b"
    else:
        print("Only us-west-2 (Oregon), eu-west-1 (Ireland), and us-east-1 (Virginia) are currently supported")
        exit(1)
    return ami


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


def get_instances_by_name(client, instance_name):
    response = client.describe_instances()
    instances = []
    # response["Reservations"][0]["Instances"][0]["Tags"]
    try:
        for r in response["Reservations"]:
            for i in r["Instances"]:
                for t in i["Tags"]:
                    if t.get("Key", None) == "Name" and t.get("Value", None) == instance_name:
                        instances.append(i["InstanceId"])
    except Exception as e:
        print(str(e))

    return instances


def destroy_enviornment(client, vpc_name, region="us-east-1"):
    #     aws ec2 disassociate-address --association-id
    #     aws ec2 release-address --allocation-id
    #     aws ec2 terminate-instances --instance-ids
    #     aws ec2 wait instance-terminated --instance-ids
    #     aws ec2 delete-security-group --group-id
    #     aws ec2 disassociate-route-table --association-id
    #     aws ec2 delete-route-table --route-table-id
    #     aws ec2 detach-internet-gateway --internet-gateway-id  --vpc-id
    #     aws ec2 delete-internet-gateway --internet-gateway-id
    #     aws ec2 delete-subnet --subnet-id
    #     aws ec2 delete-vpc --vpc-id
    #     echo If you want to delete the key-pair, plea

    instance_name = vpc_name + "-gpu-machine"
    print("Checking for instances named " + instance_name + "...")
    # change this to
    # lst_instances = find_resource_by_tag(client, "Name", instance_name, "InstanceId", client.describe_instances(), "Instances")
    # ec2_client, "Name", vpc_name + "-gateway", "InternetGatewayId", ec2_client.describe_internet_gateways(), 'InternetGateways'
    lst_instances = get_instances_by_name(client, instance_name)

    print("Found a total of {} instances named {}".format(len(lst_instances), instance_name))

    if instances:
        response = client.terminate_instances(InstanceIds=lst_instances)
        print(response)
    # check to make sure instance(s) are terminated

    associations = find_resource_by_tag(client, "Name", vpc_name + "-route-table", "Associations",
                                        client.describe_route_tables(), "RouteTables")
    for a in associations:
        client.disassociate_route_table(AssociationId=a["RouteTableAssociationId"])


def check_attach_internet_gateway(client, vpc_id, vpc_name):
    gateway_id = find_resource_by_tag(client, "Name", vpc_name + "-gateway", "InternetGatewayId",
                                      client.describe_internet_gateways(), 'InternetGateways')

    if gateway_id:
        # check attached
        print("Internet Gateway {} exists".format(gateway_id))
        attached = check_gateway_attached(client, gateway_id, vpc_id)
        if not attached:
            response = attach_gateway(client, gateway_id, vpc_id)
            assert response["ResponseMetadata"]["HTTPStatusCode"] == 200
            print("Gateway {} successfully attached to VPC {}".format(gateway_id, vpc_id))
    else:
        response = client.create_internet_gateway()
        assert response["ResponseMetadata"]["HTTPStatusCode"] == 200
        gateway_id = response["InternetGateway"]["InternetGatewayId"]
        print("Internet Gateway {} created successfully".format(gateway_id))
        response = attach_gateway(client, gateway_id, vpc_id)
        assert response["ResponseMetadata"]["HTTPStatusCode"] == 200
        response = client.create_tags(Resources=[gateway_id], Tags=[{"Key": "Name", "Value": vpc_name + "-gateway"}])
        assert response["ResponseMetadata"]["HTTPStatusCode"] == 200
    return gateway_id


def assign_elastic_ip(client, instance_id, allocation_id):
    iterations = 0
    max_iterations = 10
    while iterations < max_iterations:
        print("Waiting for instance to start, waiting 5 seconds...")
        time.sleep(5)
        status = client.describe_instance_status(InstanceIds=[instance_id])
        if not status["InstanceStatuses"]:
            print("Instance {} could not be found".format(instance_id))
            time.sleep(5)
            iterations += 1
        elif status["InstanceStatuses"][0]["InstanceState"]["Name"] != "running":
            print("Not running yet, sleeping for 10 seconds...")
            time.sleep(5)
            iterations += 1
        else:
            print("Instance Id {} now has status {}".format(instance_id,
                                                            status["InstanceStatuses"][0]["InstanceState"]["Name"]))
            response = client.associate_address(AllocationId=allocation_id, InstanceId=instance_id)
            assert response["ResponseMetadata"]["HTTPStatusCode"] == 200
            print("Elastic IP assigned successfully")
            break

    if iterations > max_iterations:
        print("Could not assign elastic IP in {} iterations".format(iterations))



def main(my_profile="default", vpc_name="fast-ai", cidr_block="10.0.0.0/28", instance_type="p2.xlarge",
         region="us-east-1", use_spot=False):
    retvals = {}
    ingress_cidr = "0.0.0.0/0"
    ec2_client = create_client(my_profile)
    # vpc_id = find_resource_by_tag(ec2_client, "Name", vpc_name, "VpcId", ec2_client.describe_vpcs(), 'Vpcs')
    # if vpc_id is None:
    vpc_id = get_create_vpc(ec2_client, vpc_name)
    retvals["vpc_id"] = vpc_id
    # see if gateway exists
    gateway_id = check_attach_internet_gateway(ec2_client, vpc_id, vpc_name)
    retvals["gateway_id"] = gateway_id
    subnet_id = find_resource_by_tag(ec2_client, "Name", vpc_name + "-subnet", "SubnetId",
                                     ec2_client.describe_subnets(), 'Subnets')
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
    retvals["subnet_id"] = subnet_id

    # route table
    route_table_id = find_resource_by_tag(ec2_client, "Name", vpc_name + "-route-table", "RouteTableId",
                                          ec2_client.describe_route_tables(), "RouteTables")

    if route_table_id:
        pass
        # technically should check to make sure it's setup right and in the correct vpc
        #     route_table = client.describe_route_tables(RouteTableIds=[route_table_id])
        #     if route_table["RouteTables"][0]["VpcId"] != vpc_id:
        #         d_route["route_table_id"] = create_route_table(ec2_client, vpc_id)
    else:
        route_table_id = create_route_table(ec2_client, vpc_id)

    retvals["route_table_id"] = route_table_id

    response = ec2_client.create_tags(Resources=[route_table_id],
                                      Tags=[{"Key": "Name", "Value": vpc_name + "-route-table"}])
    assert response["ResponseMetadata"]["HTTPStatusCode"] == 200

    response = ec2_client.associate_route_table(RouteTableId=route_table_id, SubnetId=subnet_id)
    assert response["ResponseMetadata"]["HTTPStatusCode"] == 200
    association_id = response["AssociationId"]

    retvals["association_id"] = association_id
    # security group
    security_group_id = get_create_authorize_security_group(ec2_client, vpc_id, vpc_name + "-security-group",
                                                            [{"p_from": 22, "p_to": 22},
                                                             {"p_from": 8888, "p_to": 8898}], ingress_cidr,
                                                            "Security group for Fast AI")
    assert len(security_group_id) > 0
    retvals["security_group_id"] = security_group_id

    image_id = get_ami(region)
    retvals["image_id"] = image_id

    key_name = create_ssh_key(client, vpc_name, delete_first=False)

    response = client.run_instances(ImageId=image_id, InstanceType=instance_type
                                    , KeyName=key_name, MaxCount=1, MinCount=1, SubnetId=subnet_id
                                    , SecurityGroupIds=[security_group_id]
                                    , BlockDeviceMappings=[{"DeviceName": "/dev/sda1", "Ebs":
            {"VolumeSize": 128, "VolumeType": "gp2"}}])
    assert response["ResponseMetadata"]["HTTPStatusCode"] == 200
    instance_id = response["Instances"][0]["InstanceId"]
    print("Instance {} has started successfully".format(instance_id))
    retvals["instance_id"] = instance_id

    client.create_tags(Resources=[instance_id], Tags=[{"Key": "Name", "Value": vpc_name + "-gpu-machine"}])
    response = client.allocate_address(Domain='vpc')
    assert response["ResponseMetadata"]["HTTPStatusCode"] == 200
    allocation_id = response["AllocationId"]
    public_ip = response["PublicIp"]
    print("Allocation of public IP {} successful, allocation id: {}".format(public_ip, allocation_id))

    retvals["allocation_id"] = allocation_id
    retvals["public_ip"] = public_ip

    assign_elastic_ip(client, instance_id, allocation_id)

    return retvals
