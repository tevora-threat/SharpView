# SharpView
.NET port of [PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/PowerView.ps1)

#### Usage:
```
C:\>SharpView.exe Get-DomainController -Domain test.local -Server dc.test.local -Credential admin@test.local/password  
```
```
C:\>SharpView.exe Get-DomainController -Help
Get-DomainController -Domain <String> -Server <String> -DomainController <String> -LDAP <Boolean> -Credential <NetworkCredential>
```

#### Available methods
```
Get-DomainGPOUserLocalGroupMapping
Find-GPOLocation
Get-DomainGPOComputerLocalGroupMapping
Find-GPOComputerAdmin
Get-DomainObjectAcl
Get-ObjectAcl
Add-DomainObjectAcl
Add-ObjectAcl
Remove-DomainObjectAcl
Get-RegLoggedOn
Get-LoggedOnLocal
Get-NetRDPSession
Test-AdminAccess
Invoke-CheckLocalAdminAccess
Get-WMIProcess
Get-NetProcess
Get-WMIRegProxy
Get-Proxy
Get-WMIRegLastLoggedOn
Get-LastLoggedOn
Get-WMIRegCachedRDPConnection
Get-CachedRDPConnection
Get-WMIRegMountedDrive
Get-RegistryMountedDrive
Find-InterestingDomainAcl
Invoke-ACLScanner
Get-NetShare
Get-NetLoggedon
Get-NetLocalGroup
Get-NetLocalGroupMember
Get-NetSession
Get-PathAcl
ConvertFrom-UACValue
Get-PrincipalContext
New-DomainGroup
New-DomainUser
Add-DomainGroupMember
Set-DomainUserPassword
Invoke-Kerberoast
Export-PowerViewCSV
Find-LocalAdminAccess
Find-DomainLocalGroupMember
Find-DomainShare
Find-DomainUserEvent
Find-DomainProcess
Find-DomainUserLocation
Find-InterestingFile
Find-InterestingDomainShareFile
Find-DomainObjectPropertyOutlier
TestMethod
Get-Domain
Get-NetDomain
Get-DomainComputer
Get-NetComputer
Get-DomainController
Get-NetDomainController
Get-DomainFileServer
Get-NetFileServer
Convert-ADName
Get-DomainObject
Get-ADObject
Get-DomainUser
Get-NetUser
Get-DomainGroup
Get-NetGroup
Get-DomainDFSShare
Get-DFSshare
Get-DomainDNSRecord
Get-DNSRecord
Get-DomainDNSZone
Get-DNSZone
Get-DomainForeignGroupMember
Find-ForeignGroup
Get-DomainForeignUser
Find-ForeignUser
ConvertFrom-SID
Convert-SidToName
Get-DomainGroupMember
Get-NetGroupMember
Get-DomainManagedSecurityGroup
Find-ManagedSecurityGroups
Get-DomainOU
Get-NetOU
Get-DomainSID
Get-Forest
Get-NetForest
Get-ForestTrust
Get-NetForestTrust
Get-DomainTrust
Get-NetDomainTrust
Get-ForestDomain
Get-NetForestDomain
Get-DomainSite
Get-NetSite
Get-DomainSubnet
Get-NetSubnet
Get-DomainTrustMapping
Invoke-MapDomainTrust
Get-ForestGlobalCatalog
Get-NetForestCatalog
Get-DomainUserEvent
Get-UserEvent
Get-DomainGUIDMap
Get-GUIDMap
Resolve-IPAddress
Get-IPAddress
ConvertTo-SID
Invoke-UserImpersonation
Invoke-RevertToSelf
Get-DomainSPNTicket
Request-SPNTicket
Get-NetComputerSiteName
Get-SiteName
Get-DomainGPO
Get-NetGPO
Set-DomainObject
Set-ADObject
Add-RemoteConnection
Remove-RemoteConnection
Get-IniContent
Get-GptTmpl
Get-GroupsXML
Get-DomainPolicyData
Get-DomainPolicy
Get-DomainGPOLocalGroup
Get-NetGPOGroup
```

Blog [Here](https://threat.tevora.com/a-sharpview-and-more-aggressor)
Currently compiled for .NET 4.5.2 todo is support 3.0 (4.0 at minimum)

##### TODO
* Fix any broken issues
* Support .NET 3.0 (or 4.0 depending on CS execute-assembly)