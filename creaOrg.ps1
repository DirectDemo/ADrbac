#Requires -Modules ActiveDirectory
#Requires -RunAsAdministrator
 
<#
.SYNOPSIS
Crée une structure basique d'OU de groupes pour une nouvelle organisation.
.NOTES
    Author         : Patrick MADROLLE
    Prerequisite   : PowerShell V3 over 2012r2 and upper.
    Copyright      : GPLv3
.LINK
    https://github.com/DirectDemo/ADrbac
.EXAMPLE
    .\creaOrg.ps1
    Crée la premiére organisation, et chaque lancement supplémentaire en crée une de plus.
#>
""
Set-strictmode -Version 2

#--------------------------------------Paramétres
$root = 'Global'    #OU racine UNIQUE
$adds = 'ADDS'        #OU dédiée à l'AD
$ProtectedFromAccidentalDeletion = $false
$accesGroupPatern = "Access-{0}-administration"
$roleGroupPatern = "Role-{0}-administrateur"
$compteAdministrateur = 'u00p'
$compteOrdinaire = 'u00o'


#--------------------------------------Début de script
$dom = Get-ADDomain
$rootObject = Get-ADOrganizationalUnit -Filter {name -eq $root} -SearchBase $dom.DistinguishedName -SearchScope OneLevel

if ( $rootObject -eq $null )
{
#--------------------------------------Création de l'arborscence de base et de la premiére organisation

    $OrgOU = New-ADOrganizationalUnit -Name $root -Path $dom.DistinguishedName -Description "OU racine" -ProtectedFromAccidentalDeletion $ProtectedFromAccidentalDeletion -PassThru
    $RedirCmp = New-ADOrganizationalUnit -Name 'RedirCmp' -Path $OrgOU.DistinguishedName -Description "OU par défaut des ordinateurs" -PassThru
    $RedirUsr = New-ADOrganizationalUnit -Name 'RedirUsr' -Path $OrgOU.DistinguishedName -Description "OU par défaut des utilisateurs" -PassThru
    $Org = New-ADOrganizationalUnit -Name 'Org00' -path $OrgOU.DistinguishedName -Description "Raison sociale de la société ou del'association" -PassThru
    ""
    "Une ouvelle arborescence avec "+$Org.Name+" a été créée !"
    ""
    "Vous pouvez à présent positionner les OU de création par defaut."
    "RedirCmp '$($RedirCmp.DistinguishedName)'"
    "Redirusr '$($RedirUsr.DistinguishedName)'"
    ""
}
else 
{
#--------------------------------------Création d'une organisation supplémentaire
    [array]$Orgs = Get-ADOrganizationalUnit -Filter {name -like "Org*"} -SearchBase $rootObject.DistinguishedName -SearchScope OneLevel
    $OrgNumber = 0

    foreach ( $Org in $Orgs )
    {
        $OrgNumber = [math]::Max($OrgNumber,[int]($Org.name).Substring(3))
    }

    if ( $OrgNumber -le 99 )
    {
       $Org = New-ADOrganizationalUnit -Name ("Org{0,2}" -f ($OrgNumber+1) -replace ' ','0') -Path $rootObject.DistinguishedName -Description "Nom de société ou d'association" -PassThru
    }
    else
    {
        "Numéro maximum d'organisation : 99"
        exit
    }
    "La nouvelle organisation "+$Org.Name+" est ajoutée !"
}

#--------------------------------------création des OU de l'organisation
$OUsers = New-ADOrganizationalUnit -Name 'Users' -Path $Org.DistinguishedName -Description "Comptes utilisateurs" -PassThru
New-ADOrganizationalUnit -Name '_Disabled' -Path $OUsers.DistinguishedName -Description "Comptes utilisateurs désactivés"
$OUworkstations = New-ADOrganizationalUnit -Name 'Workstations' -Path $Org.DistinguishedName -Description "Comptes des postes" -PassThru
New-ADOrganizationalUnit -Name '_Disabled' -Path $OUworkstations.DistinguishedName -Description "Comptes des postes désactivés"
$OUapplications = New-ADOrganizationalUnit -Name 'Applications' -Path $Org.DistinguishedName -Description "OUs regroupant les objets des applications" -PassThru
New-ADOrganizationalUnit -Name '_Disabled' -Path $OUapplications.DistinguishedName -Description "OUs regroupant les objets des applications désactivées"
New-ADOrganizationalUnit -Name '_Others' -Path $OUapplications.DistinguishedName -Description "Autres applications"
$OUApp00 = New-ADOrganizationalUnit -Name 'App00' -Path $OUapplications.DistinguishedName -Description "Nom de l'application" -PassThru
$OUappADDS = New-ADOrganizationalUnit -Name $adds -Path $OUapplications.DistinguishedName -Description "Objets pour l'AD et GPO" -PassThru
"Les sous OU de l'organisation sont créées."

#création des groupes d'accés de l'organisation
New-ADGroup -Name ($accesGroupPatern -f $Org.name) -Path $OUappADDS.DistinguishedName -Description ("Administration de l'OU "+$Org.name) -GroupScope DomainLocal
New-ADGroup -Name ($accesGroupPatern -f $Org.name+"-$adds") -Path $OUappADDS.DistinguishedName -Description ("Administration de l'OU $adds") -GroupScope DomainLocal
New-ADGroup -Name ($accesGroupPatern -f $Org.name+'-App00') -Path $OUappADDS.DistinguishedName -Description ("Administration de l'OU App00") -GroupScope DomainLocal
"Les premiers groupes d'accés sont créés."

#création des groupes de rôles de l'organisation

if ( $rootObject -eq $null )
{
$adminRole = New-ADGroup -Name ($roleGroupPatern -f $dom.DNSRoot) -Path $OUsers.DistinguishedName -Description ("Administration de "+$dom.DNSRoot) -GroupScope Global -PassThru
Get-ADgroup -filter * | ?{ $_.sid -eq "$($dom.DomainSID)-512" -or $_.sid -eq "$($dom.DomainSID)-519" } | %{ Add-ADGroupMember -Identity $_ -Members $adminRole }
"Les premiers groupes de rôles sont créés."

$domAdmUser = New-ADUser -Name $compteAdministrateur -Path $OUsers.DistinguishedName -Description ("Compte d'administration") -PassThru
Add-ADGroupMember -Identity $adminRole -Members $domAdmUser
"Votre compte privilégié administrateur du domaine $compteAdministrateur est créé."

New-ADUser -Name $compteOrdinaire -Path $OUsers.DistinguishedName -Description ("Compte commun")
"Votre compte ordinaire $compteOrdinaire est créé."
}
""
read-host -prompt "Appuyez sur une touche pour Quitter"
