function New-SelfSignedCertificate 
{
    #Get your credentials stored in variable O365creds
    $cloudcred=Get-Credential
   
    #Install and Login to Azure AD PowerShell With Admin Account
    #Install-Module AzureAD
    Connect-AzureAD -Credential $cloudcred

    #Install-Module Azure -AllowClobber
    #Import-Module Azure
    Connect-AzAccount -Credential $cloudcred
    
    #Define variablescls

    $currentDate      = Get-Date
    $notbefore        = $currentDate.AddDays(0)
    $notAfter         = $currentDate.AddYears(10)
    $pfxCertPath      = "C:\AADAppPrincipalCertificate.pfx"
    $cerCertPath      = "C:\AADAppPrincipalCertificate.cer"
    $pfxCertPassword  = "pass@word1"


# create the self signed certificate - This certificate is signed with a private key that uniquely and positively identifies the holder of the certificate.
#SSL certificates are used for website access.
    $sslCert = New-SelfSignedCertificate `
        -KeyExportPolicy  Exportable `
        -Subject          "SharePoint_Online_App_Principal - Created $currentDate" `
        -FriendlyName     "SharePoint_Online_App_Principal - Created $currentDate" `
        -NotAfter         $notAfter `
        -NotBefore        $notbefore `
        -Type             SSLServerAuthentication `
        -Provider         "Microsoft Enhanced RSA and AES Cryptographic Provider" `
        -KeyAlgorithm     "RSA" `
        -KeyLength        2048 `
        -HashAlgorithm    "SHA256" `
        -CertStoreLocation Cert:\LocalMachine\My

# export the .pfx cert
    $sslCert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx, $pfxCertPassword ) | Set-Content $pfxCertPath -Encoding Byte 


# export the .cer cert
    $sslCert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert ) | Set-Content $cerCertPath -Encoding Byte 

#get thumbprint of ssl certificate
    $Thumbprint = $sslCert.Thumbprint
    
#Retrieve the plain text password for use with `Get-Credential` in the next command.
    $securedCertPassword = ConvertTo-SecureString -String $pfxCertPassword -Force -AsPlainText
    
#Load the pfx certificate into an X509Certificate object.
    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate($pfxCertPath, $securedCertPassword)
    $Base64Password = [System.Convert]::ToBase64String($cert.GetRawCertData())

    #The certificate will be stored and will show up in Azure AD as the name given below "pfxCertificate"
    $pfxcertificateificateName = "pfxCertificate"

    $AutomationAccountName = Read-Host "Enter your Automation Account Name"
    $resourceGroup = Read-Host "Enter your Automation Account Name"
    New-AzAutomationCertificate -AutomationAccountName $AutomationAccountName -Name $pfxcertificateificateName -Path $pfxCertPath -Password $securedCertPassword -ResourceGroupName $resourceGroup -Exportable
    
#"uploading .cer certificate to the Azure AD Application linked to the Azure Automation Account"
    #Load the .cer certificate into an X509Certificate object.
    $cercertificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate($cerSecurityPath)

    $certValue = [System.Convert]::ToBase64String($cercertificate.GetRawCertData())

    $AzADAppDisplayName = Read-Host "Enter your Azure AD Application Display Name"
    $AzureADAppId = (Get-AzureADApplication -Filter "DisplayName eq '$($AzADAppDisplayName)'").AppId

    #The supplied base64 encoded public X509 certificate ("myapp.cer") is added to the azure AD application previously created and associated with the Automation Run As Account account
    New-AzADAppCredential -ApplicationId $AzureADAppId -CertValue $certValue -StartDate $notbefore -EndDate $notAfter

}

