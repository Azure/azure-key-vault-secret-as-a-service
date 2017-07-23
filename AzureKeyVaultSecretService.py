import requests
import json
from azure.common.credentials import ServicePrincipalCredentials
from azure.mgmt.keyvault import KeyVaultManagementClient

# Get a secret from an azure key vault
# Takes 2 parameters and 1 optional parameter
# vault_name : Name of the key vault that contains the secret
# secret_name : The identitfier of the secret you want to retrieve from the key vault
# secret_version : Optional parameter to retrieve a specific version of a key if not provided will return latest version
def getSecret(vault_name, secret_name, secret_version = ''):
    #Get acess token to azure account
    data = { "grant_type" : "client_credentials", 
            "os.environ['AZURE_CLIENT_ID']" : os.environ['AZURE_CLIENT_ID'], 
            "os.environ['AZURE_CLIENT_SECRET']" : os.environ['AZURE_CLIENT_SECRET'], 
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
        os.environ['AZURE_CLIENT_ID']= os.environ['AZURE_CLIENT_ID'],
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
    def process_command(x):
        default_msg = 'Welcome to the keyvault manager api you can choose to get a secret from a vault using Get_Secret {Vault_Name} {Secret_Name} or search all vaults for a secret using Search_Secret {Secret_Name}'
        return {
            'Get_Secret': getSecret(sys.argv[1], sys.argv[2]),
            'Search_Secret': searchSecret(sys.argv[1])
        }.get(x, print(default_msg))    

    process_command(sys.argv[0])