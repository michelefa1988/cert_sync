#!/bin/bash

##########################################################################
### Script will sync a AKS lets encrypt certificate into Azure Key Vault
###
###
### 
###
##########################################################################

JQ="jq --raw-output --exit-status"


# interval_seconds="60"

# key_vault_name="kv-test-test"
# key_vault_resource_group="rg-test"

# config_path="/app/config.json"

# subscription_id="xxxx-xxxx-xxxx-xxxx-xxxxxxx"

function initialize(){
    if [ -z "$interval_seconds" ]; then
        interval_seconds="120"
        echo "interval_seconds not found. Setting default $interval_seconds seconds"
    fi
    if [ -z "$subscription_id" ]; then
        exit_error "Error - Missing subscription_id variable"
    fi
    if [ -z "$key_vault_name" ]; then
        exit_error "Error - Missing key_vault_name variable"
    fi
    if [ -z "$key_vault_resource_group" ]; then
        exit_error "Error - Missing key_vault_resource_group variable"
    fi
    if [ -z "$config_path" ]; then
        exit_error "Error - Missing config_path variable"
    fi
    checkConfigExists
}

function exit_error()
{
    echo "$1"
    exit 1

}
function checkConfigExists(){
    if [ -f "$config_path" ]; then
        echo "$config_path exists."
        config_json=$(cat $config_path)
    else 
        exit_error "$config_path does not exist"
    fi
}

#Lets make sure the certificate is indeed controller by certSync to avoid trouble
function checkTags(){
    tags_json=$(echo "$certificate_json" | $JQ ". | select ( .tags.\"managed-by\" == \"certSync\" )")

    if [ -z "$tags_json" ]; then
        return 1
    else
        return 0
    fi
}

function checkAzureKeyVaultCertificateExists (){
    cert_exists=$(az keyvault certificate list --vault-name $key_vault_name --query "contains([].id, 'https://$key_vault_name.vault.azure.net/certificates/$certificate_name_converted')")

    if [ "$cert_exists" == "true" ]; then
        return 0
    elif  [ "$cert_exists" == "false" ]; then
        return 1
    else
        exit_error "error exiting"
    fi
}

function checkAzureKeyVaultCertificateValid(){
    certificate_json=$(az keyvault certificate show  -o json --name $certificate_name_converted --vault-name $key_vault_name  --subscription $subscription_id --output json )
    checkTags

    if [ "$?" -eq "0" ]; then
        echo "Secret $certificate_name_converted managed by certSync"
        return 0
    elif [ "$?" -eq "1" ]; then
         echo "WARN: Azure KeyVault Secret $certificate_name_converted exists but is not managed by certSync"
         return 1
    else 
        exit_error "Error, exiting"
    fi

}

function checkAzureKeyVaultExists() {
    # Function below will thow exit 3 is keyvault does not exist. 
    key_vault_json=$(az keyvault show --output json --name $key_vault_name --subscription $subscription_id --resource-group $key_vault_resource_group)
}

function create_keyvault_certificate() {
    echo "Creating Azure KeyVault Certificate $certificate_name_converted"
    az keyvault certificate import --name $certificate_name_converted --vault-name $key_vault_name --subscription $subscription_id --tags "managed-by=certSync" -f ./temp/$certificate_name.pfx
}
function update_Azure_Certificate() {
    echo "Updating Azure KeyVault Certificate $certificate_name_converted"
    az keyvault certificate import --name $certificate_name_converted --vault-name $key_vault_name --subscription $subscription_id --tags "managed-by=certSync" -f ./temp/$certificate_name.pfx
}
function CompareCertificates() {
    if [ "$?" -eq "0" ]; then
        if [[ "$k8_certificate_thumbprint_clean" == "$thumbprint_azure_keyvault_certificate"  ]]; then
            echo "Certifite Matches. No action needed"
        else 
            echo "Certificate Mismatch, attemping to update"
            update_Azure_Certificate
        fi 
    elif [ "$?" -eq "1" ]; then
        echo "Certificate not managed by vault; skipping"

    else
        exit 1
    fi
}

#Start of script
initialize

az login --identity --allow-no-subscription

az account set --output json --subscription $subscription_id

while true
do
checkConfigExists
checkAzureKeyVaultExists

RecordCount=$(echo $config_json | $JQ ". | length" )

count=0
echo  ""
while [ $count -lt $RecordCount ]
do
    [[ -d ./temp ]] && rm -r ./temp
    mkdir ./temp
    namespace=$(echo $config_json | $JQ ".[$count].namespace")
    certificate_name=$(echo $config_json | $JQ ".[$count].certificate_name")
    certificate_password=$(echo $config_json | $JQ ".[$count].certificate_password")
    certificate_name_converted=$(echo "$certificate_name" | sed 's/\./-/g') 

    echo "Loading certificate $namespace/$certificate_name"
    get_k8_certificate_json=$(curl -s --cacert /var/run/secrets/kubernetes.io/serviceaccount/ca.crt -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" https://kubernetes.default.svc/apis/cert-manager.io/v1/namespaces/$namespace/certificates/$certificate_name)

    if [[ "$get_k8_certificate_json" == *"404"* ]]; then
        echo "Certificate $certificate_name not found in namespace $namespace; skipping"
    else 
        certificate_secret=$(echo $get_k8_certificate_json | $JQ ". | select ( .status.conditions[0].type == \"Ready\" ) | .spec.secretName")
        echo "certificate_secret: $certificate_secret"

        get_k8_secret_json=$(curl -s --cacert /var/run/secrets/kubernetes.io/serviceaccount/ca.crt -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" https://kubernetes.default.svc/api/v1/namespaces/$namespace/secrets/$certificate_secret)



        tls_crt=$( echo $get_k8_secret_json | $JQ .data.\"tls.crt\"  | base64 --decode > temp/tls_crt.crt) 
        tls_key=$( echo $get_k8_secret_json | $JQ .data.\"tls.key\"  | base64 --decode > temp/tls_key.key )

        openssl pkcs12 -export -out temp/$certificate_name.pfx -inkey temp/tls_key.key -in temp/tls_crt.crt -passout pass:$certificate_password
        k8_certificate_thumbprint=$(openssl pkcs12  -in ./temp/$certificate_name.pfx -nodes  -passin pass:$certificate_password | openssl x509 -noout -fingerprint)
        k8_certificate_thumbprint_clean="$(echo $k8_certificate_thumbprint | sed 's/\://g' | sed 's/SHA1 Fingerprint=//g')"
        echo "AKS Certificate $certificate_name: $k8_certificate_thumbprint_clean"

        checkAzureKeyVaultCertificateExists $certificate_name

        if [ "$?" -eq "0" ]; then
            checkAzureKeyVaultCertificateValid $certificate_name
            if [ "$?" -eq "0" ]; then
                thumbprint_azure_keyvault_certificate=$(echo $certificate_json | $JQ .x509ThumbprintHex )
                echo "Loading Azure KeyVault Certificate: $certificate_name_converted $thumbprint_azure_keyvault_certificate"
                CompareCertificates
            elif [ "$?" -eq "1" ]; then
                echo "skipping"
            else 
                exit_error "Exiting in error"
            fi
        elif [ "$?" -eq "1" ]; then
            echo "Creating Certificate"
            create_keyvault_certificate
        else
            exit_error "exiting in error"
        fi
    fi
    count=`expr $count + 1`
    touch ./health
    echo "**************************************************"

done
echo "Next check in $interval_seconds"
sleep $interval_seconds
done