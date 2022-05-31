#Requires -Modules ActiveDirectory
#Requires -RunAsAdministrator
 
<#
.SYNOPSIS
Crée une structure basique d'OU et de groupes pour une nouvelle organisation AD.
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

Set-strictmode -Version 3

#--------------------------------------Paramétres
[string]$root = 'Org'    #OU racine UNIQUE
[bool]$ProtectedFromAccidentalDeletion = $false
[int]$counterSize = 2
[int]$counter = 0

$OUlist = @(
"$root.PM0",
"$root.PM1",
'PM0.APP0',
'PM0.APP1',
'PM0.EQU0',
'PM0.EQU1',
'PM0.EQU2',
'PM0.EQU2',
'PM1.APP0',
'PM1.EQU0'
)

$compteAdministrateur = 'cp'
$compteOrdinaire = 'co'

#--------------------------------------Test de présence d'une organisation
$dom = Get-ADDomain
remove-ADOrganizationalUnit -Identity 'OU=Org,DC=de,DC=fe' -Recursive -Confirm:$false
get-gpo -All | ? DisplayName -like "Dom*" | Remove-GPO

$rootObject = Get-ADOrganizationalUnit -Filter {name -eq $root} -SearchBase $dom.DistinguishedName -SearchScope OneLevel
 

#--------------------------------------Création des OUs et GPO
    if ( $rootObject -eq $null ) {    $Org = New-ADOrganizationalUnit -Name $root -Path $dom.DistinguishedName -Description "OU racine" -ProtectedFromAccidentalDeletion $ProtectedFromAccidentalDeletion -PassThru
    $RedirCmp = New-ADOrganizationalUnit -Name 'RedirCmp' -Path $Org.DistinguishedName -Description "OU par défaut des ordinateurs" -PassThru
    $RedirUsr = New-ADOrganizationalUnit -Name 'RedirUsr' -Path $Org.DistinguishedName -Description "OU par défaut des utilisateurs" -PassThru
    $ADDS = New-ADOrganizationalUnit -Name 'ADDS' -path $Org.DistinguishedName -Description "Objets pour l'AD et GPO" -PassThru
    New-GPO ('Dom0/'+$root) | New-GPLink -Target $Org -LinkEnabled Yes | Out-Null
    "Une nouvelle Organisation vient d'être créée !"

        Function countUP () {
        [int]$script:counter = $script:counter+1
        ("0"*($script:counterSize-([string]$script:counter).Length)+[string]$script:counter)
        }
        
        Function newOU ($OU) { #Création de l'OU
        $OUA = $OU.Split('.')
            if ($OUA[1] -like "PM*") { 
            [string]$name = $OUA[1]
            } else {
            [string]$name = $OUA[1]+(countUP)
            }
        $OUP = Get-ADOrganizationalUnit -Filter "Name -eq '$($OUA[0])'"
        $OUC = New-ADOrganizationalUnit -Path $OUP.DistinguishedName -Name "$name" -Description "OU $name" -PassThru
        newGA $OUC.name
        newGPO $OUC.DistinguishedName
        }

        Function newGA ($OU) { #Création du GA d'administration
        if ($OU -like "PM*") { $PC = 9 } else { $PC = [regex]::matches("$OU", "\d")[0].Value }
        [string]$serial = "$PC"+(countUP)
        New-ADGroup -Name ("ga$serial.administration."+$OU) -Path $ADDS.DistinguishedName -Description ("Administration de "+$dom.DNSRoot) -GroupScope Global 
        }

        Function newGPO ($OU) { #Création du squelette de la GPO
        $OUlist = ($OU -replace 'CN=' -replace 'OU=' -replace ($dom).DistinguishedName).trim(',') -split ','
        $GPOname = ''
            for ($i = 1; $i -le $OUlist.Length ; $i++)
            { 
                $GPOname = $GPOname+'/'+$OUlist[-$i]
            }

        New-GPO ('Dom0'+$GPOname) | New-GPLink -Target $OU -LinkEnabled Yes | Out-Null
        $GPOname
        }
        
    foreach ($ouModel in $OUlist) {
    newOU $ouModel
    }
 
  #--------------------------------------Création des deux 1ers utilisateurs
    
    $admEQU0 = (Get-ADOrganizationalUnit -LDAPFilter '(name=EQU0*)' | Sort-Object Name)[0]
    $admEQU2 = (Get-ADOrganizationalUnit -LDAPFilter '(name=EQU2*)' | Sort-Object Name)[0]

    if ($admEQU0 -ne $null) {

        $adminDom = (Get-ADGroup -LDAPFilter '(name=*EQU0*)' | Sort-Object Name)[0]
        Get-ADgroup -filter * | Where-object {
          $_.sid -eq "$($dom.DomainSID)-512" -or $_.sid -eq "$($dom.DomainSID)-519"
        } | Foreach-Object {
          Add-ADGroupMember -Identity $_ -Members $adminDom
        }
 
        $pass = Read-Host -Prompt "Saisir une 1ére fois le mot passe par défaut: " -AsSecureString
        [int]$script:counter = $script:counter+1
        $compteAdministrateur = $compteAdministrateur+'0'+(countUP)
        $domAdmUser = New-ADUser -Name $compteAdministrateur -Path $admEQU0.DistinguishedName -AccountPassword $pass -Description ("Compte d'administration du domaine") -PassThru
        Set-ADUser -Identity $domAdmUser -Enabled $true -AccountNotDelegated $true -UserPrincipalName ($domAdmUser.name+"@"+$dom.DNSRoot)
        Add-ADGroupMember -Identity $adminDom -Members $domAdmUser
        "Votre compte administrateur du domaine $compteAdministrateur est créé."
    
            if ($admEQU2 -ne $null) {
            [int]$script:counter = $script:counter+1
            $compteOrdinaire = $compteOrdinaire+'2'+(countUP)
            $domAdmOrdUser = New-ADUser -Name $compteOrdinaire -Path $admEQU2.DistinguishedName -AccountPassword $pass -Description ("Compte commun $compteOrdinaire") -PassThru
            Set-ADUser -Identity $compteOrdinaire -Enabled $true -UserPrincipalName ($domAdmOrdUser.name+"@"+$dom.DNSRoot)
            "Votre compte ordinaire $compteOrdinaire est créé."
            }
        }

    ""
    "Commande de déplacement des dossiers par défaut"
    "RedirCmp '$($RedirCmp.DistinguishedName)'"
    "Redirusr '$($RedirUsr.DistinguishedName)'"
 
    #read-host -prompt "Appuyez sur une touche pour Quitter"
 
  } else {
  #--------------------------------------Information
    "Une organisation avait déjà été créée."
  }
 
