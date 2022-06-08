#Requires -Modules ActiveDirectory
#Requires -RunAsAdministrator
 
<#
.SYNOPSIS
    Create a basic Active Directory set of object according to the RBAC model.
.DESCRIPTION
    Create a basic Active Directory set of object, OU, GPO, users, groups and computers, according to the RBAC model.
.NOTES
    Author         : Patrick MADROLLE
    Prerequisite   : PowerShell V3 over 2012r2 and upper.
    Copyright      : GPLv3
.LINK
    https://github.com/DirectDemo/ADrbac
.EXAMPLE
    .\new-org.ps1
#>

################################################################################
# Declarations
################################################################################

# Ensure that this script uses the strictest available version.
Set-StrictMode -Version 3

# Exit this script when an error occurred.
$ErrorActionPreference = 'Stop'

################################################################################
# Parameters
################################################################################

[string]$root = 'Org'    #OU racine UNIQUE
[bool]$Protected = $false
[int]$counterSize = 3
[int]$counter = 0

$OUlist = @(
"$root.MP0",
'MP0.AP0',
'MP0.AP0',
'MP0.AP1',
'MP0.AP1',
'MP0.TM0',
'MP0.TM1',
'MP0.TM2'
)

################################################################################
# Functions
################################################################################

#-------------------------------------- Test of existing objects

$dom = Get-ADDomain

    if (get-ADOrganizationalUnit -Identity ('OU=Org,'+$dom.DistinguishedName)) {
    remove-ADOrganizationalUnit -Identity ('OU=Org,'+$dom.DistinguishedName) -Recursive -Confirm:$false -ErrorAction SilentlyContinue
    get-gpo -All | ? DisplayName -like "Dom*" | Remove-GPO
    }

$rootObject = Get-ADOrganizationalUnit -Filter {name -eq $root} -SearchBase $dom.DistinguishedName -SearchScope OneLevel
 
#-------------------------------------- Key creations

    if ( $rootObject -eq $null ) {

        Function countUP () {
        [int]$script:counter = $script:counter+1
        ("0"*($script:counterSize-([string]$script:counter).Length)+[string]$script:counter)
        }

        Function newOU ($OUN, $OUP, $OUD) { #Création de l'OU
        $OU = New-ADOrganizationalUnit -Path $OUP -Name $OUN -Description $OUD -PassThru -ProtectedFromAccidentalDeletion $Protected
        if ( $OUP -ne "OU=$root,$($dom.DistinguishedName)" ) { newGA $OU.name }
        }

        Function newGA ($OUN) { #Création du GA d'administration
        if ($OUN -like "MP*" -or $OUN -like $root) { $PC = 9 } else { $PC = [regex]::matches("$OUN", "\d")[0].Value }
        [string]$serial = "$PC"+(countUP)
        New-ADGroup -Name ("ga$serial.$OUN.administration") -Path $ADGgr.DistinguishedName -Description ("Administration de "+$dom.DNSRoot) -GroupScope Global
        newGPO $OU.DistinguishedName 
        }

        Function newGPO ($OUD) { #Création du squelette de la GPO
        $OUlist = ($OUD -replace 'CN=' -replace 'OU=' -replace ($dom).DistinguishedName).trim(',') -split ','
        $GPOname = ''
            for ($i = 1; $i -le $OUlist.Length ; $i++)
            { 
                $GPOname = $GPOname+'/'+$OUlist[-$i]
            }
        $GPOname = ('Dom0'+$GPOname).TrimEnd('/')
        New-GPO $GPOname | New-GPLink -Target "$OUD" -LinkEnabled Yes -Order 1 | Out-Null
        $GPOname
        }

    "Création d'une nouvelle Organisation."

    newGPO $dom.DistinguishedName
    newGPO ('OU=Domain Controllers,'+$dom.DistinguishedName)

    $Org = New-ADOrganizationalUnit -Name $root -Path $dom.DistinguishedName -Description "OU racine" -ProtectedFromAccidentalDeletion $Protected -PassThru
    New-GPO ('Dom0/'+$root) | New-GPLink -Target $Org -LinkEnabled Yes | Out-Null

    $ADGgr = New-ADOrganizationalUnit -Name 'ADGgr' -path $Org.DistinguishedName -Description "OU par défaut des groupes" -ProtectedFromAccidentalDeletion $Protected -PassThru
    New-GPO ('Dom0/'+$root+'/ADGgr') | New-GPLink -Target $ADGgr -LinkEnabled Yes | Out-Null

    $RedirCmp = New-ADOrganizationalUnit -Name 'RedirCmp' -Path $Org.DistinguishedName -Description "OU par défaut des ordinateurs" -ProtectedFromAccidentalDeletion $Protected -PassThru
    New-GPO ('Dom0/'+$root+'/RedirCmp') | New-GPLink -Target $RedirCmp -LinkEnabled Yes | Out-Null

    $RedirUsr = New-ADOrganizationalUnit -Name 'RedirUsr' -Path $Org.DistinguishedName -Description "OU par défaut des utilisateurs" -ProtectedFromAccidentalDeletion $Protected -PassThru
    New-GPO ('Dom0/'+$root+'/RedirUsr') | New-GPLink -Target $RedirUsr -LinkEnabled Yes | Out-Null

    foreach ($ouModel in $OUlist) {
    $OUA = $ouModel.Split('.')
        if ($OUA[1] -like "MP*") { 
        [string]$name = $OUA[1]
        } else {
        [string]$name = $OUA[1]+(countUP)
        }
    $OUP = Get-ADOrganizationalUnit -Filter "Name -eq '$($OUA[0])'"
    newOU $name $OUP.DistinguishedName "OU $name"
    }
 
    ""
    [array]$TM0 = (Get-ADOrganizationalUnit -LDAPFilter '(name=TM0*)' | Sort-Object Name)
    if ($TM0[0] -ne $null) {

    [array]$adminDomList = Get-ADGroup -LDAPFilter '(name=*TM0*)' | Sort-Object Name
    $adminDom = $adminDomList[0]
    Get-ADgroup -filter * | Where-object {
        $_.sid -eq "$($dom.DomainSID)-512" -or $_.sid -eq "$($dom.DomainSID)-519"
    } | Foreach-Object {
        Add-ADGroupMember -Identity $_ -Members $adminDom
    }
 
    $pass = Read-Host -Prompt "Type one time the password for accounts created by that script: " -AsSecureString

    [string]$name = 'up0'+(countUP)
    $domAdmUser = New-ADUser -Name $name -Path $TM0[0].DistinguishedName -AccountPassword $pass -Description ("domain priviledged account") -PassThru
    Set-ADUser -Identity $domAdmUser -Enabled $true -AccountNotDelegated $true -UserPrincipalName ($domAdmUser.name+"@"+$dom.DNSRoot)
    Add-ADGroupMember -Identity $adminDom -Members $domAdmUser
    "Your domain administrator account $name is ceated."

    [string]$name = 'cd0'+(countUP)
    $domAdmCpt = New-ADComputer -Name $name -SamAccountName $name -Path $TM0[0].DistinguishedName -Description "PAW station"
    "Your PAW station account $name is created."
    }

  #-------------------------------------- Optional creations

    [array]$AP0 = (Get-ADOrganizationalUnit -LDAPFilter '(name=AP0*)' | Sort-Object Name)
    if ($AP0[0] -ne $null) {

    [string]$name = 'cs0'+(countUP)
    $AP0Cmp0 = New-ADComputer -Name $name -Path $AP0[0].DistinguishedName -Description ("T0 WSUS server") -PassThru

    [string]$serial = '0'+(countUP)
    New-ADGroup -Name ("ga$serial.$($AP0Cmp0.name).administration") -Path $AP0[0].DistinguishedName -Description "T0 WSUS server administration" -GroupScope Global

    [string]$serial = '0'+(countUP)
    New-ADGroup -Name ("ga$serial.$($AP0Cmp0.name).monitoring") -Path $AP0[0].DistinguishedName -Description "T0 WSUS server monitoring" -GroupScope Global
    }

    if ($AP0[1] -ne $null) {

    [string]$name = 'cs0'+(countUP)
    $AP0Cmp1 = New-ADComputer -Name $name -Path $AP0[1].DistinguishedName -Description ("T0 JUMP server") -PassThru

    [string]$name = 'us0'+(countUP)
    $AP0Usr1 = New-ADUser -Name $name -Path $AP0[1].DistinguishedName -AccountPassword $pass -Description ("Service account") -PassThru
    Set-ADUser -Identity $name -Enabled $true -UserPrincipalName ($AP0Usr1.name+"@"+$dom.DNSRoot)

    [string]$serial = '0'+(countUP)
    New-ADGroup -Name ("ga$serial.$($AP0Cmp1.name).administration") -Path $AP0[1].DistinguishedName -Description "T0 JUMP server administration" -GroupScope Global
    }


    [array]$TM1 = (Get-ADOrganizationalUnit -LDAPFilter '(name=TM1*)' | Sort-Object Name)
    if ($TM1[0] -ne $null) {

    [string]$name = 'ua1'+(countUP)
    $domAppUser = New-ADUser -Name $name -Path $TM1[0].DistinguishedName -AccountPassword $pass -Description ("Application account (BAD sécurity practice)") -PassThru
    Set-ADUser -Identity $name -Enabled $true -UserPrincipalName ($domAppUser.name+"@"+$dom.DNSRoot)

    [string]$serial = '1'+(countUP)
    New-ADGroup -Name ("gr$serial.DBA_administrators") -Path $TM1[0].DistinguishedName -Description "DBA Administrators" -GroupScope Global
    }


    [array]$TM2 = (Get-ADOrganizationalUnit -LDAPFilter '(name=TM2*)' | Sort-Object Name)
    if ($TM2[0] -ne $null) {
    [string]$name = 'ud2'+(countUP)
    $domOrdUser = New-ADUser -Name $name -Path $TM2[0].DistinguishedName -AccountPassword $pass -Description ("user desktop account") -PassThru
    Set-ADUser -Identity $name -Enabled $true -UserPrincipalName ($domOrdUser.name+"@"+$dom.DNSRoot)

    [string]$serial = '2'+(countUP)
    New-ADGroup -Name ("gr$serial.exp_acc") -Path $TM2[0].DistinguishedName -Description "Rôle of experts accountants" -GroupScope Global

    [string]$serial = '2'+(countUP)
    New-ADGroup -Name ("gr$serial.beg_acc") -Path $TM2[0].DistinguishedName -Description "Rôle of beginners accountants" -GroupScope Global
    }

    ""
    "Commande de déplacement des dossiers par défaut"
    "RedirCmp '$($RedirCmp.DistinguishedName)'"
    "Redirusr '$($RedirUsr.DistinguishedName)'"
 
    #read-host -prompt "Appuyez sur une touche pour Quitter"
 
  } else {
  #--------------------------------------Information
    "An organization still exists."
  }
 
