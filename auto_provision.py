#!/usr/bin/python3

import sys, getopt
import os

## automation for features
from time import sleep

## Python moduules for sleep,logging and regular expression
import sys
import logging
import time, os, io, re
import pdb
import json
import requests
import base64
import pdb
import time
import pathlib
import itertools
import re
import logging
import time
import pdb
import datetime as dt
import shutil

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

columns = shutil.get_terminal_size().columns

# REST Headers
HEADERS = {'Content-type': 'application/vnd.yang.data+xml',
                   'Accept': 'application/vnd.yang.data+xml, application/vnd.yang.collection+xml'}
GET_HEADERS = {'Content-type': 'application/vnd.yang.data+json',
                   'Accept': 'application/vnd.yang.data+json, application/vnd.yang.collection+json'}

# REST HTTP Status codes
STATUS_OK = 200
CREATED = 201
NO_CONTENT = 204
NOT_FOUND = 404
ACCEPTED = 202
requests.packages.urllib3.disable_warnings()

def request_DNAC_token(DNAC_IP,user,pswd):
    encoded = user+':'+pswd
    encoded = encoded.encode('ascii')
    token = base64.b64encode(encoded)
    token = str(token)
    token = token[2:-1]
    REQUEST_DNAC_TOKEN_HEADER = {'Content-type':'application/json','Authorization':'Basic '+token}
    try:
        uri = 'https://' + DNAC_IP+'/api/system/v1/auth/token'
        response = requests.post(uri, headers=REQUEST_DNAC_TOKEN_HEADER, verify=False)
        
        expected_status_codes = [CREATED]
        if expected_status_codes == [CREATED]:
            time.sleep(2)
            return json.loads(response.text)['Token']
        else:
            raise Exception('Create of %s failed' % entity)
    except Exception as err:
        raise Exception
    
class DnaServices(object):
    def __init__(self,dnac_ip,user,pswd):
        self.token = request_DNAC_token(dnac_ip,user,pswd)
        self.dnac_ip = dnac_ip
        self.user = user
        self.pswd = pswd
        if (len(sys.argv) == 1):
            self.debug = 0
        else:
            self.debug = 1
        self.part_url = 'https://'+self.dnac_ip
        
    def log_n_print(self,*msg):
        if(self.debug == 1):
            logger.info(msg)
            print(msg)
        
    def sync_devices(self,dev_ids):
        token = self.token
        headers={'x-auth-token':token, 'Content-Type':'application/json'}
        url = self.part_url+'/dna/intent/api/v1/network-device/sync'
        dev_ids = json.dumps(dev_ids)
        response = requests.request("PUT", url, headers=headers, data = dev_ids, verify=False)
        return json.loads(response.text)
        
    def provision_device(self,dev_id,dev_name,site):
        payload = [
            {
                "type":"DeviceInfo",
                "name":dev_name,
                "networkDeviceId":dev_id,
                "targetIdList":[dev_id],
                "siteId":site
            }
        ]
        response = self.post(self.part_url + '/api/v2/data/customer-facing-service/DeviceInfo', payload, "provision device")
        status_uri = self.part_url + response['response']['url']
        response = self.get(status_uri,'task status')
        if (response['response']['isError']):
            time.sleep(30)
            response = self.post(self.part_url + '/api/v2/data/customer-facing-service/DeviceInfo', payload, "provision device")
        else:
            pass
    
    def get_domain_name(self,site_id):
        url = self.part_url+'/api/v1/commonsetting/global/'+site_id
        out = self.get(url,'status')
        for instance in out['response']:
            if instance['instanceType'] == 'dns':
                return(instance['value'][0]['domainName'])
            
    def post(self,uri, payload, entity):
        """
        This function is used to create entity giving URI and payload
        """
        token = self.token
        try:
            self.log_n_print('Request URI: %s' % uri)
            if (self.debug == 1):
                self.log_n_print('payload')
                self.log_n_print(payload)
                self.log_n_print(uri)
            self.log_n_print('************ Create %s via POST ************' % entity)
            if 'file' in payload:
                self.log_n_print('file payload')
                response = requests.post(uri, files=payload, headers={'x-auth-token':token}, verify=False)
                if re.search("token expired",str(response.text)):
                    self.log_n_print("token expired , getting token again")
                    self.token = request_DNAC_token(self.dnac_ip,self.user,self.pswd)
                    token = self.token
                    response = requests.post(uri, files=payload, headers={'x-auth-token':token}, verify=False)
            else:
                if (self.debug == 1):
                    self.log_n_print('json payload')
                response = requests.post(uri, json=payload, headers={'x-auth-token':token, 'Content-Type':'application/json'}, verify=False)
                if re.search("token expired",str(response.text)):
                    self.log_n_print("token expired , getting token again")
                    self.token = request_DNAC_token(self.dnac_ip,self.user,self.pswd)
                    token = self.token
                    response = requests.post(uri, json=payload, headers={'x-auth-token':token, 'Content-Type':'application/json'}, verify=False)
            self.log_n_print("response.status_code_POST = %s" % response.status_code)

            # Comparing expected_status_code with response_status_code
            expected_status_codes = [ACCEPTED, STATUS_OK]
            if(response.status_code in expected_status_codes):
                self.log_n_print("Create %s successful via POST operation !!! " % entity)
                time.sleep(2)
                if (self.debug == 1):
                    self.log_n_print(json.loads(response.text))
                return json.loads(response.text)
            else:
                self.log_n_print('Expected')
                self.log_n_print(expected_status_codes)
                self.log_n_print('Got')
                self.log_n_print(response.status_code)
                logger.error('Create of %s failed' % entity)
                raise Exception('Create of %s failed' % entity)
        except Exception as err:
            self.log_n_print('create(): FAILED. Exception occurred: {}'.format(err))
            raise Exception
        
    def put(self,uri, payload, entity):
        token = self.token
        """
        This function is used to create entity giving URI and payload
        """
        try:
            self.log_n_print('Request URI: %s' % uri)
            if (self.debug == 1):
                self.log_n_print(payload)
                self.log_n_print(uri)
            self.log_n_print('************Create %s via PUT ************' % entity)
            if (self.debug == 1):
                self.log_n_print(uri)
            response = requests.put(uri, data=payload, headers={'x-auth-token':token, 'Content-Type':'application/json'}, verify=False)
            if (self.debug == 1):
                self.log_n_print(str(response.text))
            if re.search("token expired",str(response.text)):
                self.log_n_print("token expired , getting token again")
                self.token = request_DNAC_token(self.dnac_ip,self.user,self.pswd)
                token = self.token
                response = requests.put(uri, data=payload, headers={'x-auth-token':token, 'Content-Type':'application/json'}, verify=False)
            self.log_n_print("response.status_code_PUT = %s" % response.status_code)
            # Comparing expected_status_code with response_status_code
            expected_status_codes = [CREATED, NO_CONTENT, ACCEPTED]
            if(response.status_code in expected_status_codes):
                self.log_n_print("Create %s passed via PUT operation !!! " % entity)
                time.sleep(2)
                if (self.debug == 1):
                    self.log_n_print(json.loads(response.text))
                return json.loads(response.text)
            else:
                logger.error('Create of %s failed' % entity)
                raise Exception('Create of %s failed' % entity)
        except Exception as err:
            self.log_n_print('put(): FAILED. Exception occurred: {}'.format(err))
            raise Exception

    def get(self,uri, entity, expected_result="expected_result_success"):
        token = self.token
        """
        This function is used to get entity giving URI
        """
        #print(token)
        try:
            self.log_n_print('Request URI: %s' % uri)
            if (self.debug == 1):
                self.log_n_print(uri)
            self.log_n_print('************ Get %s ************' % entity)
            response = requests.get(uri, headers={'x-auth-token':token}, verify=False)
            self.log_n_print("response.status_code_GET = %s" % response.status_code)
            if re.search("token expired",str(response.text)):
                self.log_n_print("token expired , getting token again")
                self.token = request_DNAC_token(self.dnac_ip,self.user,self.pswd)
                token = self.token
                response = requests.get(uri, headers={'x-auth-token':token}, verify=False)
            if(expected_result == "expected_result_failure"):
                # Comparing expected_status_code with response_status_code
                expected_status_codes = [NOT_FOUND, NO_CONTENT]
                if(response.status_code in expected_status_codes):
                    self.log_n_print("%s does not exist !!! " % entity)
                    time.sleep(2)
                    self.log_n_print(response.text)
                    return response.text
                else:
                    if (self.debug == 1):
                        self.log_n_print("Get %s failed !!! " % entity)
            else:
                # Comparing expected_status_code with response_status_code
                expected_status_code = STATUS_OK
                if(expected_status_code == response.status_code):
                    self.log_n_print("Get %s passed !!! " % entity)
                    time.sleep(2)
                    if (self.debug == 1):
                        self.log_n_print(json.loads(response.text))
                    return json.loads(response.text)
                elif(ACCEPTED == response.status_code):
                    self.log_n_print("Get %s passed !!! " % entity)
                    time.sleep(2)
                    if (self.debug == 1):
                        self.log_n_print(json.loads(response.text))
                    return json.loads(response.text)
                else:
                    if (self.debug == 1):
                        self.log_n_print("Get %s failed !!! " % entity)
        except Exception as err:
            self.log_n_print('self.get(): FAILED. Exception occurred: {}'.format(err))
            raise Exception

    def delete(self,uri, entity, expected_result="expected_result_success"):
        token = self.token
        """
        This function is used to delete entity giving URI
        """
        try:
            self.log_n_print('Request URI: %s' % uri)
            self.log_n_print('************ delete %s ************' % entity)
            response_delete = requests.delete(uri, headers={'x-auth-token':token,'Content-Type':'application/json'}, verify=False)
            self.log_n_print("response.status_code_DELETE = %s" % response_delete.status_code)
            if re.search("token expired",str(response_delete.text)):
                self.log_n_print("token expired , getting token again")
                self.token = request_DNAC_token(self.dnac_ip,self.user,self.pswd)
                token = self.token
                response_delete = requests.delete(uri, headers={'x-auth-token':token,'Content-Type':'application/json'}, verify=False)
            # Comparing expected_status_code with response_status_code
            if(expected_result == "expected_result_failure"):
                # Comparing expected_status_code with response_status_code
                expected_status_codes = [NOT_FOUND, NO_CONTENT]
                if(response.status_code in expected_status_codes):
                    self.log_n_print("%s does not exist !!! " % entity)
                    time.sleep(2)
                    return json.loads(response_delete.text)
                else:
                    self.log_n_print("Delete %s failed !!! " % entity)
                    raise Exception('Delete %s failed' % entity)
            else:
                expected_status_code = [ACCEPTED, STATUS_OK]
                if(response_delete.status_code in expected_status_code):
                    self.log_n_print("Delete %s successful !!! " % entity)
                    self.log_n_print(response_delete.text)
                    time.sleep(2)
                    return json.loads(response_delete.text)
                else:
                    logger.error('Delete %s failed' % entity)
                    raise Exception('Delete %s failed' % entity)
        except Exception as err:
            self.log_n_print('delete(): FAILED. Exception occurred: {}'.format(err))
            raise Exception
    
    def get_pnp_process_percentage(self,serial_no):
        uri = self.part_url+'/api/v1/onboarding/pnp-device?serialNumber='+serial_no
        out = self.get(uri,'pnp status')
        if (out[0]['deviceInfo']['state'] == "Unclaimed"):
            return('10')
        elif (out[0]['deviceInfo']['state'] == "Onboarding"):
            return('70')
        elif(out[0]['deviceInfo']['state'] == "Provisioned"):
            return('100')
        elif(out[0]['deviceInfo']['state'] == "Error"):
            return('0')
        else:
            return('40')
            
    def get_current_time(self):
        dnac_ip = self.dnac_ip
        entity = "time"
        uri = 'https://' + dnac_ip + '/api/assurance/v1/time'
        response = self.get(uri,entity)
        for ent in response['response']:
            if (ent['timeType'] == 'CURRENT'):
                return ent['time']
            
    def get_assurance_interfaces(self,dev_id):
        dnac_ip = self.dnac_ip
        current_time = self.get_current_time()
        start_time = current_time - 10800000
        uri = 'https://' + dnac_ip + '/api/assurance/v1/network-device/'+dev_id+'/interfaces'
        payload = {"orderBy":"name","order":"INCR","limit":200,"offset":0,"endTime":current_time,"startTime":start_time}
        response = self.post(uri,payload,'get interface details')
        return response
    
    def get_project_id(self,project):
        token = self.token
        dnac_ip = self.dnac_ip
        uri = 'https://' + dnac_ip + '/api/v1/template-programmer/project?name='+project
        response = self.get(uri,'project id')
        return response[0]['id']
    
    def get_tag_id(self,tag):
        token = self.token
        dnac_ip = self.dnac_ip
        uri = 'https://' + dnac_ip + '/api/v2/tag?name='+tag
        response = self.get(uri,'tag id')
        try:
            return response['response'][0]['id']
        except:
            self.create_tag(tag)
            
    def create_tag(self,tag):
        token = self.token
        dnac_ip = self.dnac_ip
        uri = 'https://' + dnac_ip + '/api/v2/tag'
        payload = {"type":["TAG"],"name":tag,"description":'null',"dynamicRules":[]}
        response = self.post(uri, payload, 'create tag')
        status_uri = 'https://' + dnac_ip + response['response']['url']
        response = self.get(status_uri,'task status')
        if (response['response']['isError']):
            return 'Failure', response['response']['failureReason']
        else:
            self.log_n_print(response['response']['progress'])
        
    def claim_device(self,host_name,dev_id,site_id,template_name,param):
        template_id = self.get_template_id(template_name,'Onboarding Configuration')
        payload = {"siteId":site_id,"deviceId":dev_id,"hostname":host_name,"type":"Default",\
            "imageInfo":{"imageId":"","skip":"false"},"configInfo":{"configId":template_id,"configParameters":param}
            }
        claim_device_status = self.post(self.part_url + '/api/v1/onboarding/pnp-device/site-claim',payload, " Claim "+host_name)
        return(claim_device_status)
    
    def get_dev_id_from_ip(self, device_ip):
        url = self.part_url+'/api/v1/network-device/ip-address/' + device_ip
        out = self.get(url,'device')
        return(out['response']['id'])
    
    def get_unclaimed_device_list(self):
        uri = self.part_url+ '/api/v1/onboarding/pnp-device?state=Unclaimed'
        response = self.get(uri,'pnp unclaimed device')
        return_list = []
        for dev in response:
            try:
                dummy = dev['deviceInfo']['httpHeaders']
            except:
                continue
            for i in dev['deviceInfo']['httpHeaders']:
                if (i['key'] == 'clientAddress'):
                    ip = i['value']
            dev_id = dev['id']
            dev_serial = dev['deviceInfo']['serialNumber']
            dev_pid = dev['deviceInfo']['pid']
            neighbor_list = []
            for neighbor in dev['deviceInfo']['neighborLinks']:
                if (neighbor['remoteDeviceName'] == 'Switch'):
                    pass
                else:
                    neighbor_list.append(neighbor['remoteDeviceName'])
            neighbor_list = set(neighbor_list)
            neighbor_list = list(neighbor_list)
            for interface in dev['deviceInfo']['ipInterfaces']:
                if 'ipv4Address' in interface.keys():
                    if interface['ipv4Address']==ip:
                        pnp_vlan = interface['name']
                        vlan_no = re.search(r"Vlan([0-9]+)", pnp_vlan)
                        pnp_startup_vlan = vlan_no.group(1)
            return_list.append([dev_id,dev_serial,dev_pid,ip,neighbor_list,pnp_startup_vlan])
        return return_list
         
    def delete_template(self,temp_name,project):
        token = self.token
        dnac_ip = self.dnac_ip
        template_id = self.get_template_id(temp_name,project)
        if (str(template_id) == "0"):
            self.log_n_print(temp_name+" template not present")
            return 'Success'
        uri = 'https://' + dnac_ip + '/api/v1/template-programmer/template/'+str(template_id)
        response = self.delete(uri, 'template')
        status_uri = 'https://' + dnac_ip + response['response']['url']
        response = self.get(status_uri,'task status')
        if (response['response']['isError']):
            return 'Failure', response['response']['failureReason']
        else:
            return 'Success'
        
    def get_template_id(self,temp_name,project):
        token = self.token
        dnac_ip = self.dnac_ip
        uri = 'https://' + dnac_ip + '/api/v1/template-programmer/project'
        response = self.get(uri,'template name')
        for proj in response:
            if (proj['name'] == project):
                for temp in proj['templates']:
                    if (temp['name'] == temp_name):
                        return temp['id']
        return 0
    
    def commit_template(self,temp_name,project):
        token = self.token
        dnac_ip = self.dnac_ip
        uri = 'https://' + dnac_ip + '/api/v1/template-programmer/template/version'
        temp_id = self.get_template_id(temp_name,project)
        payload = {"comments":"","templateId":temp_id}
        response = self.post(uri, payload, 'create tag')
        status_uri = 'https://' + dnac_ip + response['response']['url']
        response = self.get(status_uri,'task status')
        if (response['response']['isError']):
            return 'Failure', response['response']['failureReason']
        else:
            self.log_n_print(response['response']['progress'])
            
    def create_template(self,temp_name,project,tag,content_list,param_list):
        token = self.token
        dnac_ip = self.dnac_ip
        proj_id = self.get_project_id(project)
        tag_id = self.get_tag_id(tag)
        uri = 'https://' + dnac_ip + '/api/v1/template-programmer/project/'+proj_id+'/template'
        
        payload = {"name":temp_name,"composite":"false","containingTemplates":[],"description":temp_name,"tags":[{"id":tag_id,"name":tag}],"deviceTypes":[{"productFamily":"Switches and Hubs"}],"softwareType":"IOS-XE","softwareVersion":"null"}
        response = self.post(uri, payload, 'create template')
        status_uri = 'https://' + dnac_ip + response['response']['url']
        response = self.get(status_uri,'task status')
        if (response['response']['isError']):
            return 'Failure', response['response']['failureReason']
        else:
            self.log_n_print(response['response']['progress'])
        template_id = self.get_template_id(temp_name,project)
        payload = {"comments":"","templateId":template_id}
        uri = 'https://' + dnac_ip + '/api/v1/template-programmer/template'
        content_string = "\n".join(content_list)
        template_param_payload = []
        for param in param_list:
            template_param_payload.append({"parameterName":param[0],"notParam":param[1],"dataType":"STRING","defaultValue":"null","description":param[0],"required":"true","displayName":param[0],"instructionText":param[0],"group":"null","order":1,"range":[],"key":"null","provider":"null","binding":"","paramArray":"false"})
        payload = {"name":temp_name,"description":temp_name,"tags":[{"id":tag_id,"name":tag}],"deviceTypes":[{"productFamily":"Switches and Hubs"}],"softwareType":"IOS-XE","composite":"false","containingTemplates":[],"softwareVersion":"","projectName":project,"projectId":proj_id,"parentTemplateId":template_id,"id":template_id,"templateContent":content_string,"templateParams":template_param_payload,"rollbackTemplateContent":"","rollbackTemplateParams":[]}
        payload = json.dumps(payload)
        response = self.put(uri, payload, 'commit template')
        status_uri = 'https://' + dnac_ip + response['response']['url']
        response = self.get(status_uri,'task status')
        if (response['response']['isError']):
            return 'Failure', response['response']['failureReason']
        else:
            self.log_n_print(response['response']['progress'])
            
    def get_all_site_ids(self):
        site_uuids = []
        response = self.get(self.part_url + '/api/v1/group', "get all Sites ID's")
        for item in response['response']:
         if 'groupTypeList' in item.keys():
          if item['groupTypeList']!=['SITE']:
             continue
          if 'additionalInfo' in item.keys():
           for item1 in item['additionalInfo']:
            if item1['nameSpace']=='Location':
             if 'type' in item1['attributes'].keys():
              if item1['attributes']['type']=='building':
               v = [item["groupNameHierarchy"], item["id"]]
               site_uuids.append(v)
        return(site_uuids)

    def get_device_onboarding_status(self, device_id):
        uri = self.part_url+'/api/v2/data/device-config-status?deviceId='+device_id+'&isLatest=true'
        response = self.get(uri,'status')
        return(response['response'][0]['status'])
    
def create_pnp_startup_vlan_template(dnac,stp_mode):
    auto_conf_plus_pnp_startup_vlan_list = ['parameter-map type subscriber attribute-to-service BUILTIN_DEVICE_TO_TEMPLATE',
                                                '4 map device-type regex "Cisco-Switch"',
                                                '10 interface-template SWITCH_INTERFACE_TEMPLATE',
                                                'access-session mac-move deny',
                                                'access-session interface-template sticky timer 30',
                                                'device classifier',
                                                'autoconf enable',
                                                'template SWITCH_INTERFACE_TEMPLATE',
                                                'switchport mode trunk',
                                                'spanning-tree mode '+stp_mode,
                                                '#if ($apply_pnp_vlan == 1)',
                                                'pnp startup-vlan $vlan_id',
                                                '#end']
    
    print('creating Day0 config template, under Onboarding Configuration'.center(columns),end="\r")
    try:
        dnac.delete_template('pnp_startup_vlan_auto_conf','Onboarding Configuration')
    except:
        pass
    dnac.create_template('pnp_startup_vlan_auto_conf','Onboarding Configuration','pnp',auto_conf_plus_pnp_startup_vlan_list,[['apply_pnp_vlan',False],['vlan_id',False]])
    dnac.commit_template('pnp_startup_vlan_auto_conf','Onboarding Configuration')
    print('creating Day0 config template, under Onboarding Configuration - Success'.center(columns),end="\r")
    print("\r")
        
def print_center(msg):
    print(msg.center(columns))
    
def get_valid_input(max_value,min_value=1):
    global entered_input
    print(">",end=" ")
    got = input()
    max_list = [i for i in range(min_value,max_value+1)]
    for i in range(min_value,max_value+1):
        try:
            got = int(got)
        except:
            break
        if (got == i):
            entered_input =  i
            return
    print('Invalid input, valid values are from '+str(min_value)+' to '+str(max_list[-1]))
    get_valid_input(max_value,min_value)

def get_valid_list(min_value, max_value):
    global entered_input
    print(">",end=" ")
    got = input()
    got_list = got.split(',')
    return_list = []
    if len(got_list)==1:
        try:
         if int(got_list[0]) == max_value:
            entered_input = [max_value]
            return
         if (int(got_list[0]) == max_value-1):
            entered_input = [max_value-1]
            return
        except:
            print('Invalid input, Sample input = 1,2,4')
            get_valid_list(min_value, max_value)
            return
    for i in got_list:
        try:
            if min_value <=int(i)<max_value:
                pass
            else:
                print('Invalid input entered in list: '+str(int(i))+', valid values are from '+str(min_value)+' to '+str(max_value-1))
                get_valid_list(min_value, max_value)
                return
        except:
            print('Invalid input, Sample input = 1,2,4')
            get_valid_list(min_value, max_value)
            return
        return_list.append(int(i))
    entered_input = return_list
    
print_center("*********************************************")                
print_center("*     Welcome To Auto Provision Wizard      *")
print_center("*********************************************")
print("\r")
print_center("Press Ctrl+C to exit the wizard\r")

print('Enter Dnac ip:',end =" ")
ip = input()
print('Dnac ip: '+ip)
print('Enter username:',end =" ")
user = input()
print('username '+user)
print('Enter Password:',end =" ")
password = input()
print('password '+password)

dnac = DnaServices(ip,user,password)


def claim_devices(dev_list_to_claim,selected_site_id):
    global no_of_devices_claimed, no_of_devices_needs_to_claimed
    for dev in dev_list_to_claim:
      if dev[-1] == '1':
        apply_pnp_vlan = 0
      else:
        apply_pnp_vlan = 1
      claim_device_status = dnac.claim_device('SN-'+dev[1],\
                                  dev[0],selected_site_id,'pnp_startup_vlan_auto_conf',\
                                  [{'key':'vlan_id',"value":dev[-1]},{'key':'apply_pnp_vlan',"value":apply_pnp_vlan}])

def get_unclaimed_device_list():
    iteration = 0
    total_iteration = 36
    while 1:
      msg = 'waiting for a unclaimed state device, time left = '+str(total_iteration*5-(iteration*5))+' secs'
      print(msg.center(columns),end="\r")
      unclaimed_devices = []
      try:
        unclaimed_devices=dnac.get_unclaimed_device_list()
      except:
        pass
      if (len(unclaimed_devices) == 0):
        if (iteration == total_iteration):
          print_center('No devices found in unclaimed state, exiting...')
          exit()
      else:
        print(msg.center(columns),end="\r")
        return(unclaimed_devices)
      iteration = iteration +1
      time.sleep(4)
      
def main_function(site_selection=1):
  global no_of_devices_claimed, no_of_devices_needs_to_claimed
  name_ids = dnac.get_all_site_ids()
  print('Select the site, where you want to add your devices')
  i = 1
  for name_id in name_ids:
      print('     '+str(i)+'. '+name_id[0])
      i = i +1
  get_valid_input(len(name_ids))
  selected_site_id = name_ids[entered_input-1][1]
  selected_site_name = name_ids[entered_input-1][0]
  print('Enter the total no of devices needs to be added')
  get_valid_input(40)
  no_of_devices_needs_to_claimed = entered_input
  print('Which STP mode you want to configure in devices')
  print('     1. mst         Multiple spanning tree mode')
  print('     2. pvst        Per-Vlan spanning tree mode')
  print('     3. rapid-pvst  Per-Vlan rapid spanning tree mode')
  get_valid_input(3)
  if (entered_input ==1):
    stp_mode = 'mst'
  elif (entered_input ==2):
    stp_mode = 'pvst'
  else:
    stp_mode = 'rapid-pvst'
  create_pnp_startup_vlan_template(dnac,stp_mode)
  id_list_for_sync = []
  while 1:
    unclaimed_devices = get_unclaimed_device_list()
    print_center('Found '+str(len(unclaimed_devices))+' devices in unclaimed state')
    print('Select the device to claim or list seperated by \',\' (Ex: 1,2,4)')
    i = 1
    for unclaimed_device in unclaimed_devices:
        print('     '+str(i)+'. Serial No: '+unclaimed_device[1]+', Platform: '+unclaimed_device[2]+', Neighbors- '+str(unclaimed_device[4]))
        i = i +1
    print('     '+str(i)+'. Re-discover')
    i = i +1
    print('     '+str(i)+'. All the above')
    get_valid_list(1,len(unclaimed_devices)+2)
    dev_list_to_claim = []
    if entered_input != [i-1]:
      print_center('Below devices will be added to '+selected_site_name+'\r')
    if entered_input == [i]:
        j = 1
        for unclaimed_device in unclaimed_devices:
            dev_list_to_claim.append([unclaimed_device[0],unclaimed_device[1],unclaimed_device[3],unclaimed_device[-1]])
            print_center(str(j)+'. Serial No: '+unclaimed_device[1])
            j = j +1
    elif entered_input == [i-1]:
        iteration = 0
        total_iteration = 10
        for i in range(0,total_iteration):
          msg = 'Re-discovery will start in '+str(total_iteration*3-(iteration*3))+' secs'
          print(msg.center(columns),end="\r")
          time.sleep(3)
          iteration = iteration + 1
        continue
    else:
        j = 1
        for i in entered_input:
            dev_list_to_claim.append([unclaimed_devices[i-1][0],unclaimed_devices[i-1][1],unclaimed_devices[i-1][3],unclaimed_devices[i-1][-1]])
            print_center(str(j)+'. Serial No: '+unclaimed_devices[i-1][1])
            j = j +1
    print('Do you want to proceed?')
    print('     1. Yes')
    print('     2. No')
    get_valid_input(2)
    if (entered_input == 2):
      exit()
    print_center('Claiming in progress..')  
    claim_devices(dev_list_to_claim,selected_site_id)
    print_center('Devices claimed, provisioning in progress..')
    domain_name = dnac.get_domain_name(selected_site_id)
    
    for dev in dev_list_to_claim:
     dev_provisioned = 0
     for i in range(0,60):
      if (i%4 ==0):
        dots = "."
      if (i%4 ==1):
        dots = ".."
      if (i%4 ==2):
        dots = "..."
      if (i%4 ==3):
        dots = "...."
      
      pnp_percentage = dnac.get_pnp_process_percentage(dev[1])
      if (pnp_percentage =='100'):
       pnp_percentage = '90'
      if (pnp_percentage =='0'):
        print_center('SN-'+dev[1]+' provision failed\r')
        break
      msg = 'SN-'+dev[1]+'.'+domain_name+' provisioning in progress'+dots+pnp_percentage+'%'
      print(msg.center(columns),end="\r")
      try:
          dev_id = dnac.get_dev_id_from_ip(dev[2])
      except Exception:
          time.sleep(5)
          continue
      if (dev_provisioned ==0):
        dnac.provision_device(dev_id,'SN-'+dev[1]+'.'+domain_name,selected_site_id)
        dev_provisioned = 1
      
      provision_status = dnac.get_device_onboarding_status(dev_id)
      if (provision_status == 'SUCCESS'):
          print_center('SN-'+dev[1]+'.'+domain_name+' provisioned successfully\r')
          id_list_for_sync.append(dev_id)
          no_of_devices_claimed = no_of_devices_claimed + 1
          break
      else:
          if (i == 29):
              print_center('SN-'+dev[1]+'.'+domain_name+' provision failed\r')
              no_of_devices_claimed = no_of_devices_claimed + 1
       
     if (no_of_devices_claimed == no_of_devices_needs_to_claimed):
        try:
            dnac.sync_devices(id_list_for_sync)
        except:
            pass
        print_center('All devices are added to site successfully')
        

no_of_devices_claimed = 0
no_of_devices_needs_to_claimed = 0
main_function()

while 1:
  print('Do you want to add more devices?')
  print('     1. Yes')
  print('     2. No')
  get_valid_input(2)
  if (entered_input == 2):
    exit()
  main_function()
