# Cert-Sync

This script was created after I found no better way of storing AKS cert-manager created certificates into Azure Keyvault. 

One of my biggest headaches was that Application gateway requires a certificate when an https listener is created. After the certifiate was generated automatically on the AKS cluster I used this application to sync the certificate onto Azure KeyVault where it can be used by application gateway. 

# Requirments
The Following are needed for cert-sync to run

* [aad-pod-identity](https://artifacthub.io/packages/helm/aad-pod-identity/aad-pod-identity) - Allows kubernetes pods to be autenticated to kubernetes resources (mainly keyvault)
* The pod needs to have following [roles](https://learn.microsoft.com/en-us/azure/key-vault/general/rbac-guide?tabs=azure-cli)
    * Key Vault Secrets Officer
    * Key Vault Cntributor

# Build

```
docker build -t michelefa1988/cert-sync -f Dockerfile.Build . 
```
## Run

The following environment variables are required for this script to run correctly
```
  interval_seconds: "130"
  key_vault_name: "kv-test"
  key_vault_resource_group: "rg-test"
  subscription_id: "xxxx-xxxx-xxxx-xxxx-xxxxx"
  config_path: "/config/config.json"
```
