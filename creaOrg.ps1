#Requires -Modules ActiveDirectory
#Requires -RunAsAdministrator
 
<#
.SYNOPSIS
Crée une structure basique d'OU de groupes pour une nouvelle organisation.
#>
""
Set-strictmode -Version 2

$dom = Get-ADDomain
$OrgGlabalName = 'Global'
$ProtectedFromAccidentalDeletion = $false
$domainAdministratorRole = 

$OrgGlobalObject = Get-ADOrganizationalUnit -Filter {name -eq $OrgGlabalName} -SearchBase $dom.DistinguishedName -SearchScope OneLevel

if ( $OrgGlobalObject -eq $null )
{
#--------------------------------------Création de l'arborscence de base et de la premiére organisation
    $OrgOU = New-ADOrganizationalUnit -Name $OrgGlabalName -Path $dom.DistinguishedName -Description "OU globale" -ProtectedFromAccidentalDeletion $ProtectedFromAccidentalDeletion -PassThru
    $RedirCmp = New-ADOrganizationalUnit -Name '_RedirCmp' -Path $OrgOU.DistinguishedName -Description "OU par défaut des ordinateurs" -PassThru
    $RedirUsr = New-ADOrganizationalUnit -Name '_RedirUsr' -Path $OrgOU.DistinguishedName -Description "OU par défaut des utilisateurs" -PassThru
    $SubOrg = New-ADOrganizationalUnit -Name 'Org00' -path $OrgOU.DistinguishedName -Description "Raison sociale de la société ou del'association" -PassThru
    ""
    "Une ouvelle arborescence avec "+$SubOrg.Name+" a été créée !"
    ""
    "Vous pouvez à présent positionner les OU de création par defaut."
    "RedirCmp '$($RedirCmp.DistinguishedName)'"
    "Redirusr '$($RedirUsr.DistinguishedName)'"
    ""
}
else 
{
#--------------------------------------Création d'une organisation supplémentaire
    [array]$SubOrgs = Get-ADOrganizationalUnit -Filter {name -like "Org*"} -SearchBase $OrgGlobalObject.DistinguishedName -SearchScope OneLevel
    $SubOrgNumber = 0

    foreach ( $SubOrg in $SubOrgs )
    {
        $SubOrgNumber = [math]::Max($SubOrgNumber,[int]($SubOrg.name).Substring(3))
    }

    if ( $SubOrgNumber -le 99 )
    {
       $SubOrg = New-ADOrganizationalUnit -Name ("Org{0,2}" -f ($SubOrgNumber+1) -replace ' ','0') -Path $OrgGlobalObject.DistinguishedName -Description "Nom de la société ou association" -PassThru
    }
    else
    {
        "Numéro maximum d'organisation : 99"
    }
    "La nouvelle organisation "+$SubOrg.Name+" est ajoutée !"
}

#--------------------------------------création des OU de l'organisation
$OUsers = New-ADOrganizationalUnit -Name 'Users' -Path $SubOrg.DistinguishedName -Description "Comptes des personels" -PassThru
New-ADOrganizationalUnit -Name '_Disabled' -Path $OUsers.DistinguishedName -Description "Comptes des personels désactivés"
$OUworkstations = New-ADOrganizationalUnit -Name 'Workstations' -Path $SubOrg.DistinguishedName -Description "Comptes des postes" -PassThru
New-ADOrganizationalUnit -Name '_Disabled' -Path $OUworkstations.DistinguishedName -Description "Comptes des postes désactivés"
$OUapplications = New-ADOrganizationalUnit -Name 'Applications' -Path $SubOrg.DistinguishedName -Description "OUs regroupant les objets des applications" -PassThru
New-ADOrganizationalUnit -Name '_Disabled' -Path $OUapplications.DistinguishedName -Description "OUs regroupant les objets des applications désactivées"
New-ADOrganizationalUnit -Name '_Others' -Path $OUapplications.DistinguishedName -Description "Autres applications"
$OUApp00 = New-ADOrganizationalUnit -Name 'App00' -Path $OUapplications.DistinguishedName -Description "Nom de l'application" -PassThru
$OUappADDS = New-ADOrganizationalUnit -Name '_ADDS' -Path $OUapplications.DistinguishedName -Description "Objets pour l'AD et GPO" -PassThru
"Les sous OU de l'organisation sont créées."

#création des groupes d'accés de l'organisation
New-ADGroup -Name ('Access-Administration_'+$SubOrg.name) -Path 'OU=_ADDS,OU=Applications,OU=Org00,OU=Global,DC=d0,DC=f0' -Description ("Administration de l'OU "+$SubOrg.name) -GroupScope DomainLocal
New-ADGroup -Name ('Access-Administration_'+$SubOrg.name+'_ADDS') -Path $OUappADDS.DistinguishedName -Description ("Administration de l'OU ADDS") -GroupScope DomainLocal
New-ADGroup -Name ('Access-Administration_'+$SubOrg.name+'_App00') -Path $OUappADDS.DistinguishedName -Description ("Administration de l'OU ADDS") -GroupScope DomainLocal
"Les premiers groupes d'accés sont créés."

#création des groupes de rôles de l'organisation

if ( $OrgGlobalObject -eq $null )
{
$adminRole = New-ADGroup -Name ('Role-Administrateurs_'+$dom.DNSRoot) -Path $OUsers.DistinguishedName -Description ("Administration de "+$dom.DNSRoot) -GroupScope Global -PassThru
Get-ADgroup -Filter {isCriticalSystemObject -eq $true} -Properties isCriticalSystemObject,description,sid | ?{ $_.sid -like "*-512" -or $_.sid -like "*-519" } | %{ Add-ADGroupMember -Identity $_ -Members $adminRole }
"Les premiers groupes de rôles sont créés."

$domAdmUser = New-ADUser -Name u00p -Path $OUsers.DistinguishedName -Description ("Compte d'administration") -PassThru
Add-ADGroupMember -Identity $adminRole -Members $domAdmUser
"Le compte Privilégié (administrateur) u00p est créé."

New-ADUser -Name u00c -Path $OUsers.DistinguishedName -Description ("Compte commun")
"Le compte commun u00c est créé."
}
""
read-host -prompt "Appuyez sur une touche pour Quitter"

