import requests
import json
from azure.common.credentials import ServicePrincipalCredentials
from azure.mgmt.keyvault import KeyVaultManagementClient
import os
import sys


# Get a secret from an azure key vault
# Takes 2 parameters and 1 optional parameter
# vault_name : Name of the key vault that contains the secret
# secret_name : The identitfier of the secret you want to retrieve from the key vault
# secret_version : Optional parameter to retrieve a specific version of a key if not provided will return latest version
def getSecret(vault_name, secret_name, secret_version = ''):
    #Get acess token to azure account
    data = { "grant_type" : "client_credentials", 
            "client_id" : os.environ['AZURE_CLIENT_ID'], 
            "client_secret" : os.environ['AZURE_CLIENT_SECRET'], 
            "resource" : "https://vault.azure.net"
        }
    headers = { "Content-Type" : "application/x-www-form-urlencoded" }
    r = requests.post("https://login.windows.net/{}/oauth2/token".format(os.environ['AZURE_TENANT_ID']), data=data, headers=headers)
    access_token = r.json()['access_token']
    #Get secret from KeyVault
    headers = {"Authorization":"Bearer {}".format(access_token) }
    r = requests.get('https://{}.vault.azure.net/secrets/{}/{}?api-version=2015-06-01'.format(vault_name, secret_name, secret_version), headers=headers)
    result = r.json()
    if 'value' in result.keys():
        return result["value"]
    else: 
        return 'Secret Not Found'

#Search all key vaults for a secret
# Takes 1 parameter and 1 optional parameter
# secret_name : The identitfier of the secret you want to retrieve from the key vault
# secret_version : Optional parameter to retrieve a specific version of a key if not provided will return latest version
def searchSecret(secret_name, secret_version = ''):
    credentials = ServicePrincipalCredentials(
        client_id= os.environ['AZURE_CLIENT_ID'],
        secret= os.environ['AZURE_CLIENT_SECRET'],
        tenant= os.environ['AZURE_TENANT_ID']
    )
    
    kvm_client = KeyVaultManagementClient(credentials,  os.environ['AZURE_SUBSCRIPTION_ID'])
    for vault in kvm_client.vaults.list():
        #return when secret found in vault
        secret = getSecret(vault.name, secret_name, secret_version = '')
        if (secret != 'Secret Not Found'):
            return secret
    return 'Secret Not Found'

if __name__ == "__main__":
    msg = 'Welcome to the keyvault manager api you can choose to get a secret from a vault using python AzureKeyVaultSecretService.py Get_Secret {Vault_Name} {Secret_Name} \n Or search all vaults for a secret with python AzureKeyVaultSecretService.py Search_Secret {Secret_Name}'    
    try:
        if (sys.argv[1] == 'Get_Secret'):
            msg = getSecret(sys.argv[2], sys.argv[3])
        if (sys.argv[1] == 'Search_Secret'):
            msg = searchSecret(sys.argv[2])
        print(msg)
    except:
        print(msg)
