function Install-ADDS {
    Add-WindowsFeature AD-Domain-Services

    Import-Module ADDSDeployment
    $password = ConvertTo-SecureString "SuperSikkertPassord123" -AsPlainText -Force
    Install-ADDSForest -DomainName certsrvtest.local -SafeModeAdministratorPassword $password -Force
}

function main {
    "Installing Active Directory Domain Services"
    Install-ADDS
    Restart-Computer
    Start-Sleep -Seconds 120
}

main
