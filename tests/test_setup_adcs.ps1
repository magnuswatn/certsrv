<#
.SYNOPSIS
    Script to install an Active Directory Certificate Services server from scratch.
.DESCRIPTION
    This script will install an ADCS server for testing/lab use.

    It will install ADDS first, and then ADCS, so that we get an "Enterprise" CA, with template support.
    It will also retrieve a certificate from Let's Encrypt for TLS support.
    (For this to work the server must be reachable on the internet on port 80)

    After this is done, the WebServer_Manual template must be manually created for the tests to run OK
.PARAMETER Email
    Email address to be used with registration with Let's Encnrypt.
.PARAMETER DnsName
    DnsName to get a certificate for.
.NOTES
    Magnus Watn <magnus@watn.no>
#>
Param([Parameter(mandatory=$true)][String]$Email,
      [Parameter(mandatory=$true)][String]$DnsName)


function Install-ADCS {
    Import-Module ServerManager
    Add-WindowsFeature Adcs-Cert-Authority, ADCS-Web-Enrollment, Web-Basic-Auth, RSAT-ADCS-Mgmt, Web-Mgmt-Console

    Install-AdcsCertificationAuthority -CACommonName certsrv-test -CAType EnterpriseRootCA -Force
    Install-AdcsWebEnrollment -Force

    # enable basic auth
    Set-WebConfigurationProperty -Filter "/system.webServer/security/authentication/basicAuthentication" -Name Enabled -Value True -PSPath "IIS:\" -Location "Default Web Site/Certsrv"
}


function Install-ADDS {
    Add-WindowsFeature AD-Domain-Services

    Import-Module ADDSDeployment
    $password = ConvertTo-SecureString "SuperSikkertPassord123" -AsPlainText -Force
    Install-ADDSForest -DomainName certsrvtest.local -SafeModeAdministratorPassword $password -Force
}


function Install-ACMECertificate($mail, $dns) {

    Install-PackageProvider -Name NuGet -Force
    Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
    Install-Module -Name ACMESharp -AllowClobber
    Install-Module -Name ACMESharp.Providers.IIS

    Import-Module ACMESharp

    Initialize-ACMEVault
    New-ACMERegistration -Contacts mailto:$mail -AcceptTos
    New-ACMEIdentifier -Dns $dns -Alias certsrv-test

    # ACMESharp issue 243 (https://github.com/ebekker/ACMESharp/issues/243)
    c:\windows\system32\inetsrv\appcmd.exe unlock config -section:system.webServer/handlers

    Complete-ACMEChallenge certsrv-test -ChallengeType http-01 -Handler iis -HandlerParameters @{ WebSiteRef = 'Default Web Site' }
    Submit-ACMEChallenge certsrv-test -ChallengeType http-01

    DO {
        Write-Warning "Waitning for the ACME challenge to be verified"
        $status = ((Update-ACMEIdentifier certsrv-test -ChallengeType http-01).Challenges | Where-Object {$_.Type -eq "http-01"}).status
        if ($status -eq "invalid") {
            throw "The ACME challenge failed"
        }
    } While ($status -ne "valid")

    New-ACMECertificate certsrv-test -Generate -Alias certsrv-cert
    Submit-ACMECertificate certsrv-cert
    Update-ACMECertificate certsrv-cert

    $certPath = "$([System.IO.Path]::GetTempFileName()).pkcs12"

    Get-ACMECertificate certsrv-cert -ExportPkcs12 $certPath

    New-WebBinding -Name "Default Web Site" -IP "*" -Port 443 -Protocol https
    Import-PfxCertificate -FilePath $certPath -CertStoreLocation Cert:\LocalMachine\My | New-Item IIS:\SslBindings\0.0.0.0!443
}


if (!((Get-WindowsFeature AD-Domain-Services).Installed)) {
    "Installing Active Directory Domain Services"
    Install-ADDS
} else {
    "Installing Active Directory Certificate Services"
    Install-ADCS
    "Installing Let's Encrypt certificate"
    Install-ACMECertificate $Email $DnsName
    "Done. Remember to create the WebServer_Manual template"
}
