function Get-PrincipalMap {
    $global:PrincipalMap = @{}
    Get-AzureADUser -All $True | % {
        $PrincipalMap.add($_.objectid, $_.OnPremisesSecurityIdentifier)
    }
    Get-AzureADGroup -All $True | % {
        $PrincipalMap.add($_.objectid, $_.OnPremisesSecurityIdentifier)
    }
    $PrincipalMap
}


##################################################################
##################################################################

$date = get-date -f yyyyMMddhhmmss
$OutputDirectory = "$env:USERPROFILE\bh2\"

function New-Output($Coll, $Type, $Directory) {
    $Count = $Coll.Count
    Write-Host "Writing output for $($Type)"
	if ($null -eq $Coll) {
        $Coll = New-Object System.Collections.ArrayList
    }
    $Output = New-Object PSObject
    $Meta = New-Object PSObject
    $Meta | Add-Member Noteproperty 'count' $Coll.Count
    $Meta | Add-Member Noteproperty 'type' "az$($Type)"
    $Meta | Add-Member Noteproperty 'version' 4
    $Output | Add-Member Noteproperty 'meta' $Meta
    $Output | Add-Member Noteproperty 'data' $Coll
    $FileName = $Directory + "\" + $((Get-Date).ToShortDateString()  -replace "/","-") + "-" + "az" + $($Type) + ".json"
    $Output | ConvertTo-Json | Out-File -Encoding "utf8" -FilePath $FileName  
}
# Build $CurrentUsers, Write azusers.json 
function AzEnumerateUsers ($OutputDirectory) {
	$global:AADUsers = Get-AzureADUser -All $True | Select UserPrincipalName,OnPremisesSecurityIdentifier,ObjectID,TenantId
    $TotalCount = $AADUsers.Count
    Write-Host "Done building users object, processing ${TotalCount} users"
    $Progress = 0
    $global:CurrentUsers = @()
    $AADUsers | ForEach-Object {
        $User = $_
        $DisplayName = ($User.UserPrincipalName).Split('@')[0]
        $Progress += 1
        $ProgressPercentage = (($Progress / $TotalCount) * 100) -As [Int]
        If ($Progress -eq $TotalCount) {
            Write-Host "Processing users: [${Progress}/${TotalCount}][${ProgressPercentage}%] Current user: ${DisplayName}"
        } else {
            If (($Progress % 1000) -eq 0) {
                Write-Host "Processing users: [${Progress}/${TotalCount}][${ProgressPercentage}%] Current user: ${DisplayName}"
            } 
        }
        $CurrentUserTenantID = $null
        If ($User.UserPrincipalName -NotMatch "#EXT#") {
            $CurrentUserTenantID = $TenantID
        }
        $CurrentUser = [PSCustomObject]@{
            DisplayName                     =   $User.displayname
            UserPrincipalName               =   $User.UserPrincipalName
            OnPremisesSecurityIdentifier    =   $User.OnPremisesSecurityIdentifier
            ObjectID                        =   $User.ObjectID
            TenantID                        =   $CurrentUserTenantID
        }
        $CurrentUsers += $CurrentUser
    } 
    New-Output -Coll $CurrentUsers -Type "users" -Directory $OutputDirectory
    Write-Host "Built `$CurrentUsers"
    Write-Host "Wrote azusers.json"
}
# Build $CurrentGroups, Write azgroups.json
function AzEnumerateGroups ($OutputDirectory){
    $global:AADGroups = Get-AzureADGroup -All $True -Filter "securityEnabled eq true"
    $TotalCount = $AADGroups.Count
    Write-Host "Done building groups object, processing ${TotalCount} groups"
    $Progress = 0
    $global:CurrentGroups = @()
    $AADGroups | ForEach-Object {
        $Group = $_
        $DisplayName = $Group.displayname
        $Progress += 1
        $ProgressPercentage = (($Progress / $TotalCount) * 100) -As [Int]
        If ($Progress -eq $TotalCount) {
            Write-Host "Processing groups: [${Progress}/${TotalCount}][${ProgressPercentage}%] Current group: ${DisplayName}"
        } else {
            If (($Progress % 100) -eq 0) {
                Write-Host "Processing groups: [${Progress}/${TotalCount}][${ProgressPercentage}%] Current group: ${DisplayName}"
            } 
        }
        $CurrentGroup = [PSCustomObject]@{
            DisplayName                    =  $Group.displayname
            OnPremisesSecurityIdentifier   =  $Group.OnPremisesSecurityIdentifier
            ObjectID                       =  $Group.ObjectID
            TenantID                       =  $TenantID
        }
        $CurrentGroups += $CurrentGroup
    }
    New-Output -Coll $CurrentGroups -Type "groups" -Directory $OutputDirectory
    Write-Host "Built `$CurrentGroups"
    Write-Host "Wrote azgroups.json"
}
# Build $CurrentTenants
function AzEnumerateTenants ($OutputDirectory){
    $AADTenants = Get-AzureADTenantDetail
    $TotalCount = $AADTenants.Count
    If ($TotalCount -gt 1) {
        Write-Host "Done building tenant object, processing ${TotalCount} tenant"
    } else {
        Write-Host "Done building tenants object, processing ${TotalCount} tenants"
    }
    $Progress = 0
    $global:CurrentTenants = @()
    $AADTenants | ForEach-Object {
        $Tenant = $_
        $DisplayName = $Tenant.DisplayName
        $Progress += 1
        $ProgressPercentage = (($Progress / $TotalCount) * 100) -As [Int]

        If ($Progress -eq $TotalCount) {
            Write-Host "Processing tenants: [${Progress}/${TotalCount}][${ProgressPercentage}%] Current tenant: ${DisplayName}"
        } else {
            If (($Progress % 100) -eq 0) {
                Write-Host "Processing tenants: [${Progress}/${TotalCount}][${ProgressPercentage}%] Current tenant: ${DisplayName}"
            } 
        }
        $Current = [PSCustomObject]@{
            ObjectID    = $Tenant.ObjectId
            DisplayName = $Tenant.DisplayName
        }
        $CurrentTenants += $Current
    }
    New-Output -Coll $CurrentTenants -Type "tenants" -Directory $OutputDirectory
    Write-Host "Built `$CurrentTenants"
    Write-Host "Wrote aztenants.json"
}


######################
# Need Subscriptions #
######################

function AzEnumerateSubscriptions ($OutputDirectory) {
    $global:AADSubscriptions = Get-AzSubscription
    $TotalCount = $AADSubscriptions.Count
    If ($TotalCount -gt 1) {
        Write-Host "Done building subscription object, processing ${TotalCount} subscription"
    } else {
        Write-Host "Done building subscriptions object, processing ${TotalCount} subscriptions"
    }
    $Progress = 0
    $global:CurrentSubs = @()
    $AADSubscriptions | ForEach-Object {
        $Subscription = $_
        $DisplayName = $Subscription.Name
        $Progress += 1
        $ProgressPercentage = (($Progress / $TotalCount) * 100) -As [Int]
        If ($Progress -eq $TotalCount) {
            Write-Host "Processing subscriptions: [${Progress}/${TotalCount}][${ProgressPercentage}%] Current subscription: ${DisplayName}"
        } else {
            If (($Progress % 100) -eq 0) {
                Write-Host "Processing subscriptions: [${Progress}/${TotalCount}][${ProgressPercentage}%] Current subscription: ${DisplayName}"
            } 
        }
        $Current = [PSCustomObject]@{
            Name            = $Subscription.Name
            SubscriptionId  = $Subscription.SubscriptionId
            TenantId        = $Subscription.TenantId
        }
        $CurrentSubs += $Current
    }
    New-Output -Coll $CurrentSubs -Type "subscriptions" -Directory $OutputDirectory
    Write-Host "Built `$CurrentSubs"
    Write-Host "Wrote azsubscriptions.json"
} 
function AzEnumerateResourceGroups ($OutputDirectory){
    $global:CurrentResourceGroups = @()
    $AADSubscriptions | ForEach-Object {
        $SubDisplayName = $_.Name
        Select-AzSubscription -SubscriptionID $_.Id | Out-Null
        Write-Host "Building resource groups object for subscription ${SubDisplayName}"
        $AADResourceGroups = Get-AzResourceGroup
        $TotalCount = $AADResourceGroups.Count
        If ($TotalCount -gt 1) {
            Write-Host "Done building resource group object, processing ${TotalCount} resource group"
        } else {
            Write-Host "Done building resource groups object, processing ${TotalCount} resource groups"
        }
        $Progress = 0
        $AADResourceGroups | ForEach-Object {
            $RG = $_
            $DisplayName = $RG.ResourceGroupName
            $Progress += 1
            $ProgressPercentage = (($Progress / $TotalCount) * 100) -As [Int]
            If ($Progress -eq $TotalCount) {
                Write-Host "Processing resource groups: [${Progress}/${TotalCount}][${ProgressPercentage}%] Current resource group: ${DisplayName}"
            } else {
                If (($Progress % 100) -eq 0) {
                    Write-Host "Processing resource groups: [${Progress}/${TotalCount}][${ProgressPercentage}%] Current resource group: ${DisplayName}"
                } 
            }
            $id = $RG.resourceid
            $resourceSub = "$id".split("/", 4)[2]
            $ResourceGroup = [PSCustomObject]@{
                ResourceGroupName   = $RG.ResourceGroupName
                SubscriptionID      = $resourceSub
                ResourceGroupID     = $RG.ResourceId
            }
            $CurrentResourceGroups += $ResourceGroup
        }
    }
    New-Output -Coll $CurrentResourceGroups -Type "resourcegroups" -Directory $OutputDirectory
    Write-Host "Built `$CurrentResourceGroups"
    Write-Host "Wrote aztenants.json"
}
function AzGetVMs ($OutputDirectory){
    $global:CurrentVms = @()
    $AADSubscriptions | ForEach-Object {
        $SubDisplayName = $_.Name
        Select-AzSubscription -SubscriptionID $_.Id | Out-Null
        Write-Host "Building VMs object for subscription ${SubDisplayName}"
        $AADVirtualMachines = Get-AzVM
        $TotalCount = $AADVirtualMachines.Count
        If ($TotalCount -gt 1) {
            Write-Host "Done building VM object, processing ${TotalCount} virtual machine"
        } else {
            Write-Host "Done building VMs object, processing ${TotalCount} virtual machines"
        }
        $Progress = 0
        $AADVirtualMachines | ForEach-Object {
            $VM = $_
            $DisplayName = $VM.Name
            $Progress += 1
            $ProgressPercentage = (($Progress / $TotalCount) * 100) -As [Int]
            If ($Progress -eq $TotalCount) {
                Write-Host "Processing virtual machines: [${Progress}/${TotalCount}][${ProgressPercentage}%] Current virtual machine: ${DisplayName}"
            } else {
                If (($Progress % 100) -eq 0) {
                    Write-Host "Processing virtual machines: [${Progress}/${TotalCount}][${ProgressPercentage}%] Current virtual machine: ${DisplayName}"
                } 
            }
            $RGName = $VM.ResourceGroupName
            $RGID = (Get-AzResourceGroup "$RGName").ResourceID
            $id = $VM.id
            $resourceSub = "$id".split("/", 4)[2]
            $AzVM = [PSCustomObject]@{
                AzVMName = $VM.Name
                AZID = $VM.VmId
                ResourceGroupName = $RGName
                ResoucreGroupSub = $resourceSub
                ResourceGroupID = $RGID
            }
            $CurrentVms += $AzVM
        }
    }
    New-Output -Coll $CurrentVms -Type "vms" -Directory $OutputDirectory
    Write-Host "Built `$CurrentVms"
    Write-Host "Wrote azvms.json"
}
function AzGetKeyVaults ($OutputDirectory){
    $CurrentAzKeyVaults = @()
    $AADSubscriptions | ForEach-Object {
        $SubDisplayName = $_.Name
        Select-AzSubscription -SubscriptionID $_.Id | Out-Null
        Write-Host "Building key vaults object for subscription ${SubDisplayName}"
        $AADKeyVaults = Get-AzKeyVault
        $TotalCount = $AADKeyVaults.Count
        If ($TotalCount -gt 1) {
            Write-Host "Done building key vaults object, processing ${TotalCount} key vaults"
        } else {
            Write-Host "Done building key vault object, processing ${TotalCount} key vault"
        }
        $Progress = 0
        $AADKeyVaults | ForEach-Object {
            $KeyVault = $_
            $DisplayName = $KeyVault.Name
            $Progress += 1
            $ProgressPercentage = (($Progress / $TotalCount) * 100) -As [Int]
            If ($Progress -eq $TotalCount) {
                Write-Host "Processing key vaults: [${Progress}/${TotalCount}][${ProgressPercentage}%] Current key vault: ${DisplayName}"
            } else {
                If (($Progress % 100) -eq 0) {
                    Write-Host "Processing key vaults: [${Progress}/${TotalCount}][${ProgressPercentage}%] Current key vault: ${DisplayName}"
                } 
            }
            $RGName = $KeyVault.ResourceGroupName
            $RGID = (Get-AzResourceGroup "$RGName").ResourceID
            $id = $KeyVault.ResourceId
            $resourceSub = "$id".split("/", 4)[2]
            $AzKeyVault = [PSCustomObject]@{
                AzKeyVaultName      = $KeyVault.VaultName
                AzKeyVaultID        = $KeyVault.ResourceId
                ResourceGroupName   = $RGName
                ResoucreGroupSub    = $resourceSub
                ResourceGroupID     = $RGID
            }
            $CurrentAzKeyVaults += $AzKeyVault
        }
    }
    New-Output -Coll $CurrentAzKeyVaults -Type "keyvaults" -Directory $OutputDirectory
    Write-Host "Built `$CurrentAzKeyVaults"
    Write-Host "Wrote azkeyvaults.json"
}
function AzGetInboundPermissionsAgainstVMs ($OutputDirectory) {
    $CurrentVMPermissions = @()
    $AADSubscriptions | ForEach-Object {
        $SubDisplayName = $_.Name
        Select-AzSubscription -SubscriptionID $_.Id | Out-Null
        Write-Host "Building VMs object for subscription ${SubDisplayName}"
        $AADVMs = Get-AzVm
        $TotalCount = $AADVMs.Count
        If ($TotalCount -gt 1) {
            Write-Host "Done building VMs object, processing ${TotalCount} VMs"
        } else {
            Write-Host "Done building VM object, processing ${TotalCount} VM"
        }
        $Progress = 0
        $AADVMs | ForEach-Object {
            $VM = $_
            $DisplayName = $VM.Name
            $Progress += 1
            $ProgressPercentage = (($Progress / $TotalCount) * 100) -As [Int]
            If ($Progress -eq $TotalCount) {
                Write-Host "Processing virtual machines: [${Progress}/${TotalCount}][${ProgressPercentage}%] Current VM: ${DisplayName}"
            } else {
                If (($Progress % 100) -eq 0) {
                    Write-Host "Processing virtual machines: [${Progress}/${TotalCount}][${ProgressPercentage}%] Current VM: ${DisplayName}"
                } 
            }
            $VMID = $VM.id
            $VMGuid = $VM.VmId
            $Roles = Get-AzRoleAssignment -scope $VMID
            ForEach ($Role in $Roles) {
                $ControllerType = $Role.ObjectType
                If ($ControllerType -eq "User") {
                    $Controller = Get-AzureADUser -ObjectID $Role.ObjectID
                    $OnPremID = $Controller.OnPremisesSecurityIdentifier
                }
                If ($ControllerType -eq "Group") {
                    $Controller = Get-AzureADGroup -ObjectID $Role.ObjectID
                    $OnPremID = $Controller.OnPremisesSecurityIdentifier
                }
				If ($ControllerType -eq "ServicePrincipal") {
                    $Controller = Get-AzureADServicePrincipal -ObjectID $Role.ObjectID
                    $OnPremID = $null
                }
                $VMPrivilege = New-Object PSObject
                $VMPrivilege = [PSCustomObject]@{
                    VMID                = $VMGuid
                    ControllerName      = $Role.DisplayName
                    ControllerID        = $Role.ObjectID
                    ControllerType      = $Role.ObjectType
                    ControllerOnPremID  = $OnPremID
                    RoleName            = $Role.RoleDefinitionName
                    RoleDefinitionId    = $Role.RoleDefinitionId
                }
                $CurrentVMPermissions += $VMPrivilege
            }
        }
    }
    New-Output -Coll $Coll -Type "vmpermissions" -Directory $OutputDirectory
    Write-Host "Built `$CurrentVMPermissions"
    Write-Host "Wrote azvmpermissions.json"
}
function AzGetInboundPermissionsAgainstResourceGroups ($OutputDirectory){
    $AADSubscriptions | ForEach-Object {
        $SubDisplayName = $_.Name
        Select-AzSubscription -SubscriptionID $_.Id | Out-Null
        Write-Host "Building resource groups object for subscription ${SubDisplayName}"
        $AADResourceGroups = Get-AzResourceGroup
        $TotalCount = $AADResourceGroups.Count
        If ($TotalCount -gt 1) {
            Write-Host "Done building resource groups object, processing ${TotalCount} resource groups"
        } else {
            Write-Host "Done building resource group object, processing ${TotalCount} resource group"
        }
        $Progress = 0
        
        $AADResourceGroups | ForEach-Object {

            $RG = $_
            $DisplayName = $RG.DisplayName

            $Progress += 1
            $ProgressPercentage = (($Progress / $TotalCount) * 100) -As [Int]

            If ($Progress -eq $TotalCount) {
                Write-Host "Processing resource groups: [${Progress}/${TotalCount}][${ProgressPercentage}%] Current resource group: ${DisplayName}"
            } else {
                If (($Progress % 100) -eq 0) {
                    Write-Host "Processing resource groups: [${Progress}/${TotalCount}][${ProgressPercentage}%] Current resource group: ${DisplayName}"
                } 
            }
            
            $RGID = $RG.ResourceId
            
            $Roles = Get-AzRoleAssignment -scope $RGID
            
            ForEach ($Role in $Roles) {
            
                $ControllerType = $Role.ObjectType
                
                If ($ControllerType -eq "User") {
                    $Controller = Get-AzureADUser -ObjectID $Role.ObjectID
                    $OnPremID = $Controller.OnPremisesSecurityIdentifier
                }
                
                If ($ControllerType -eq "Group") {
                    $Controller = Get-AzureADGroup -ObjectID $Role.ObjectID
                    $OnPremID = $Controller.OnPremisesSecurityIdentifier
                }

                $RGPrivilege = [PSCustomObject]@{
                    RGID = $RGID
                    ControllerName = $Role.DisplayName
                    ControllerID = $Role.ObjectID
                    ControllerType = $Role.ObjectType
                    ControllerOnPremID = $OnPremID
                    RoleName = $Role.RoleDefinitionName
                    RoleDefinitionId = $Role.RoleDefinitionId
                } 
                $null = $Coll.Add($RGPrivilege)
            }
        }
    }
    New-Output -Coll $Coll -Type "rgpermissions" -Directory $OutputDirectory
    Write-Host "Built `$CurrentVMPermissions"
    Write-Host "Wrote azvmpermissions.json"
}
function AzGetInboundPermissionsAgainstKeyVaults ($OutputDirectory){
    $Coll = New-Object System.Collections.ArrayList
    $AADSubscriptions | ForEach-Object {
        $SubDisplayName = $_.Name
        Select-AzSubscription -SubscriptionID $_.Id | Out-Null
        Write-Host "Building key vaults object for subscription ${SubDisplayName}"
        $AADKeyVaults = Get-AzKeyVault
        $TotalCount = $AADKeyVaults.Count
        If ($TotalCount -gt 1) {
            Write-Host "Done building key vaults object, processing ${TotalCount} key vaults"
        } else {
            Write-Host "Done building key vault object, processing ${TotalCount} key vault"
        }
        $Progress = 0
        $AADKeyVaults | ForEach-Object {
            $KeyVault = $_
            $DisplayName = $KeyVault.DisplayName
            $Progress += 1
            $ProgressPercentage = (($Progress / $TotalCount) * 100) -As [Int]
            If ($Progress -eq $TotalCount) {
                Write-Host "Processing key vaults: [${Progress}/${TotalCount}][${ProgressPercentage}%] Current key vault: ${DisplayName}"
            } else {
                If (($Progress % 100) -eq 0) {
                    Write-Host "Processing key vaults: [${Progress}/${TotalCount}][${ProgressPercentage}%] Current key vault: ${DisplayName}"
                } 
            }
            $KVID = $KeyVault.ResourceId
            $Roles = Get-AzRoleAssignment -scope $KVID
            ForEach ($Role in $Roles) {
                $ControllerType = $Role.ObjectType
                If ($ControllerType -eq "User") {
                    $Controller = Get-AzureADUser -ObjectID $Role.ObjectID
                    $OnPremID = $Controller.OnPremisesSecurityIdentifier
                }
                
                If ($ControllerType -eq "Group") {
                    $Controller = Get-AzureADGroup -ObjectID $Role.ObjectID
                    $OnPremID = $Controller.OnPremisesSecurityIdentifier
                }
                $KVPrivilege = [PSCustomObject]@{
                    KVID = $KVID
                    ControllerName = $Role.DisplayName
                    ControllerID = $Role.ObjectID
                    ControllerType = $Role.ObjectType
                    ControllerOnPremID = $OnPremID
                    RoleName = $Role.RoleDefinitionName
                    RoleDefinitionId = $Role.RoleDefinitionId
                }
                $null = $Coll.Add($KVPrivilege)
            }
        }
    }
    New-Output -Coll $Coll -Type "kvpermissions" -Directory $OutputDirectory
    Write-Host "Built `$CurrentVMPermissions"
    Write-Host "Wrote azvmpermissions.json"
}



# Build $AADDevices and write azdevices.json 
function AzGetDevices ($OutputDirectory){
    if (!$AADDevices){
        $global:AADDevices =  Get-AzureADDevice -All $true | ?{$_.DeviceOSType -Match "Windows" -Or $_.DeviceOSType -Match "Mac"}
    }
    $TotalCount = $AADDevices.Count
    Write-Host "Done building devices object, processing ${TotalCount} devices"
    $Progress = 0
    $global:CurrentDevices = @()
    $AADDevices | ForEach-Object {
        $Device = $_
        $DisplayName = $Device.DisplayName
        $Progress += 1
        $ProgressPercentage = (($Progress / $TotalCount) * 100) -As [Int]
        If ($Progress -eq $TotalCount) {
            Write-Host "Processing devices: [${Progress}/${TotalCount}][${ProgressPercentage}%] Current device: ${DisplayName}"
        } else {
            If (($Progress % 100) -eq 0) {
                Write-Host "Processing devices: [${Progress}/${TotalCount}][${ProgressPercentage}%] Current device: ${DisplayName}"
            } 
        }
        $Owner = Get-AzureADDeviceRegisteredOwner -ObjectID $Device.ObjectID
        $AzureDeviceOwner = [PSCustomObject]@{
            DeviceDisplayname   = $Device.Displayname
            DeviceID            = $Device.ObjectID
            DeviceOS            = $Device.DeviceOSType
            OwnerDisplayName    = $Owner.Displayname
            OwnerID             = $Owner.ObjectID
            OwnerType           = $Owner.ObjectType
            OwnerOnPremID       = $Owner.OnPremisesSecurityIdentifier
        }
        $CurrentDevices += $AzureDeviceOwner
    }
    New-Output -Coll $CurrentDevices -Type "devices" -Directory $OutputDirectory
    Write-Host "Built `$CurrentDevices"
    Write-Host "Wrote azdevices.json"
}
# Build $AZGroupOwners and write azgroupowners.json 
function AzGetGroupOwners ($OutputDirectory) {
    If ($AADGroups.Count -eq 0) {
        Write-Host "Creating groups object, this may take a few minutes."
        $AADGroups = Get-AzureADGroup -All $True -Filter "securityEnabled eq true"
    }
    $TargetGroups = $AADGroups | ?{$_.OnPremisesSecurityIdentifier -eq $null}
    $TotalCount = $TargetGroups.Count
    Write-Host "Done building target groups object, processing ${TotalCount} groups"
    $Progress = 0
    $global:AZGroupOwners = @()
    $TargetGroups | ForEach-Object {
        $Group = $_
        $DisplayName = $Group.DisplayName
        $Progress += 1
        $ProgressPercentage = (($Progress / $TotalCount) * 100) -As [Int]
        If ($Progress -eq $TotalCount) {
            Write-Host "Processing group ownerships: [${Progress}/${TotalCount}][${ProgressPercentage}%] Current group: ${DisplayName}"
        } else {
            If (($Progress % 100) -eq 0) {
                Write-Host "Processing group ownerships: [${Progress}/${TotalCount}][${ProgressPercentage}%] Current group: ${DisplayName}"
            } 
        }
        $GroupID = $_.ObjectID
        $Owners = Get-AzureADGroupOwner -ObjectId "$GroupID"
        ForEach ($Owner in $Owners) {
            $AZGroupOwner = [PSCustomObject]@{
                GroupName       = $Group.DisplayName
                GroupID         = $GroupID
                OwnerName       = $Owner.DisplayName
                OwnerID         = $Owner.ObjectID
                OwnerType       = $Owner.ObjectType
                OwnerOnPremID   = $Owner.OnPremisesSecurityIdentifier
            }
            $AZGroupOwners += $AZGroupOwner   
        }   
    }
    New-Output -Coll $AZGroupOwners -Type "groupowners" -Directory $OutputDirectory
    Write-Host "Built `$AZGroupOwners"
    Write-Host "Wrote azgroupowners.json"
}
# Build $AZGroupMembers and write azgroupmembers.json
function AzEnumerateGroupMembers ($OutputDirectory) {
    If ($AADGroups.Count -eq 0) {
        Write-Host "Creating groups object, this may take a few minutes."
        $AADGroups = Get-AzureADGroup -All $True -Filter "securityEnabled eq true"
    }
    $TotalCount = $AADGroups.Count
    Write-Host "Done building groups object, processing ${TotalCount} groups"
    $Progress = 0
    $global:AZGroupMembers = @()
    $AADGroups | ForEach-Object {
        $Group = $_
        $DisplayName = $Group.DisplayName
        $Progress += 1
        $ProgressPercentage = (($Progress / $TotalCount) * 100) -As [Int]
        If ($Progress -eq $TotalCount) {
            Write-Host "Processing group memberships: [${Progress}/${TotalCount}][${ProgressPercentage}%] Current group: ${DisplayName}"
        } else {
            If (($Progress % 100) -eq 0) {
                Write-Host "Processing group memberships: [${Progress}/${TotalCount}][${ProgressPercentage}%] Current group: ${DisplayName}"
            } 
        }
        $GroupID = $_.ObjectID
        $Members = Get-AzureADGroupMember -All $True -ObjectId "$GroupID"
        ForEach ($Member in $Members) {
            $AZGroupMember = [PSCustomObject]@{
                GroupName = $Group.DisplayName
                GroupID = $GroupID
                GroupOnPremID = $Group.OnPremisesSecurityIdentifier
                MemberName = $Member.DisplayName
                MemberID = $Member.ObjectID
                MemberType = $Member.ObjectType
                MemberOnPremID = $Member.OnPremisesSecurityIdentifier
            }
            $AZGroupMembers += $AZGroupMember
        }
    }
    New-Output -Coll $AZGroupMembers -Type "groupmembers" -Directory $OutputDirectory
    Write-Host "Built `$AZGroupMembers"
    Write-Host "Wrote azgroupmembers.json"
}
# Build $UserRoles, $UsersWithRoles, $UsersWithoutRoles
function AzBuildUserRoleObjects {
    $global:Results = Get-AzureADDirectoryRole | ForEach-Object {
        $Role = $_
        $RoleMembers = Get-AzureADDirectoryRoleMember -ObjectID $Role.ObjectID
        ForEach ($Member in $RoleMembers) {
            $RoleMembership = [PSCustomObject]@{
                MemberName      = $Member.DisplayName
                MemberID        = $Member.ObjectID
                MemberOnPremID  = $Member.OnPremisesSecurityIdentifier
                MemberUPN       = $Member.UserPrincipalName
                MemberType      = $Member.ObjectType
                RoleID          = $Role.RoleTemplateId
            }
            $RoleMembership
        }
    }
    Write-Host "Built `$Results"

    $global:UsersAndRoles = ForEach ($User in $Results) {
        $CurrentUser = $User.MemberID
		$CurrentObjectType = $User.MemberType
        $CurrentUserName = $User.MemberName
        $CurrentUserRoles = ($Results | ? { $_.MemberID -eq $CurrentUser }).RoleID
        $CurrentUserUPN = $User.MemberUPN
        $CurrentUserOnPremID = $User.MemberOnPremID

        $UserAndRoles = [PSCustomObject]@{
            UserName        = $CurrentUserName
			ObjectType      = $CurrentObjectType
            UserID          = $CurrentUser
            UserOnPremID    = $CurrentUserOnPremID
            UserUPN         = $CurrentUserUPN
            RoleID          = $CurrentUserRoles
        }
        $UserAndRoles
    }
    $global:UserRoles = $UsersAndRoles | Sort-Object -Unique -Property UserName
    $global:UsersWithRoles = $UserRoles.UserID
    $global:UsersWithoutRoles = $AADUsers | ? { $_.ObjectID -NotIn $UsersWithRoles }
    Write-Host "Built `$UsersAndRoles, `$UserRoles, `$UsersWithRoles, and `$UsersWithoutRoles"

    $global:AuthAdminsList = @(
        'c4e39bd9-1100-46d3-8c65-fb160da0071f',
        '88d8e3e3-8f55-4a1e-953a-9b9898b8876b',
        '95e79109-95c0-4d8e-aee3-d01accf2d47b',
        '729827e3-9c14-49f7-bb1b-9608f156bbb8',
        '790c1fb9-7f7d-4f88-86a1-ef1f95c05c1b',
        '4a5d8f65-41da-4de4-8968-e035b65339cf'
    )
    $global:HelpdeskAdminsList = @(
        'c4e39bd9-1100-46d3-8c65-fb160da0071f',
        '88d8e3e3-8f55-4a1e-953a-9b9898b8876b',
        '95e79109-95c0-4d8e-aee3-d01accf2d47b',
        '729827e3-9c14-49f7-bb1b-9608f156bbb8',
        '790c1fb9-7f7d-4f88-86a1-ef1f95c05c1b',
        '4a5d8f65-41da-4de4-8968-e035b65339cf'
    ) 
    $global:PasswordAdminList = @(
        '88d8e3e3-8f55-4a1e-953a-9b9898b8876b',
        '95e79109-95c0-4d8e-aee3-d01accf2d47b',
        '966707d0-3269-4727-9be2-8c3a10f19b9d'
    )
    $global:UserAdminList = @(
        '88d8e3e3-8f55-4a1e-953a-9b9898b8876b',
        '95e79109-95c0-4d8e-aee3-d01accf2d47b',
        '729827e3-9c14-49f7-bb1b-9608f156bbb8',
        '790c1fb9-7f7d-4f88-86a1-ef1f95c05c1b',
        '4a5d8f65-41da-4de4-8968-e035b65339cf',
        'fe930be7-5e62-47db-91af-98c3a49a38b1'
    )
    Write-Host "Built `$AuthAdminsList, `$HelpDeskAdminList, `$PasswordAdminList and `$UserAdminList"
}
# Build $AZAppOwners 
function AzGetAppOwners ($OutputDirectory) {
    $global:AZAppOwners = @()
    Get-AzureADApplication -All $True | ForEach-Object {
        $AppId = $_.AppId
        $ObjectId = $_.ObjectId
        $AppName = $_.DisplayName
        $AppOwners = Get-AzureADApplicationOwner -ObjectId $ObjectId
        
        $AzureAppOwners = ForEach ($Owner in $AppOwners) {
            $AzureAppOwner = [PSCustomObject]@{
                AppId           = $AppId
                AppObjectId     = $ObjectId
                AppName         = $AppName
                OwnerID         = $Owner.ObjectId
                OwnerType       = $Owner.ObjectType
                OwnerOnPremID   = $Owner.OnPremisesSecurityIdentifier
            }
            $AZAppOwners += $AzureAppOwner
        }
    }
    New-Output -Coll $Coll -Type "applicationowners" -Directory $OutputDirectory
    Write-Host "Built `$AZAppOwners"
    Write-Host "Wrote azapplicationowners.json"
}
# Build $ServicePrincipals - App to SP relations
function AzGetAppToServicePrincipalRelations ($OutputDirectory) {
   $SPOS = Get-AzADApplication | Get-AzADServicePrincipal | %{
        $global:ServicePrincipals = [PSCustomObject]@{
            AppId                   = $_.ApplicationId
            AppName                 = $_.DisplayName
            ServicePrincipalId      = $_.Id
            ServicePrincipalType    = $_.ObjectType
        }
        $null = $Coll.Add($ServicePrincipals)
    }
    New-Output -Coll $Coll -Type "applicationtosp" -Directory $OutputDirectory
    Write-Host "Built `$ServicePrincipals"
    Write-Host "Wrote azapplicationtosp.json"
}


$global:CloudGroups = $AADGroups | ? { $_.OnPremisesSecurityIdentifier -eq $null } | Select DisplayName, ObjectID


function Do-UserRoles {
    if (!$UserRoles) {
        $global:UserRoles = (Get-Content "$env:USERPROFILE\bh2\20210201111308-azusers.json" | ConvertFrom-Json).data
    }
    $global:PrivilegedAuthenticationAdmins  = $UserRoles | ? { $_.RoleID -Contains '7be44c8a-adaf-4e2a-84d6-ab2649e08a13' }
    $global:AuthenticationAdmins            = $UserRoles | ? { $_.RoleID -Contains 'c4e39bd9-1100-46d3-8c65-fb160da0071f' }
    $global:HelpdeskAdmins                  = $UserRoles | ? { $_.RoleID -Contains '729827e3-9c14-49f7-bb1b-9608f156bbb8' }
    $global:PasswordAdmins                  = $UserRoles | ? { $_.RoleID -Contains '966707d0-3269-4727-9be2-8c3a10f19b9d' }
    $global:UserAccountAdmins               = $UserRoles | ? { $_.RoleID -Contains 'fe930be7-5e62-47db-91af-98c3a49a38b1' }
    $global:IntuneAdmins                    = $UserRoles | ? { $_.RoleID -Contains '3a2c62db-5318-420d-8d74-23affee5d9d5' }
    $global:GroupsAdmins                    = $UserRoles | ? { $_.RoleID -Contains 'fdd7a751-b60b-444a-984c-02652fe8fa1c' }
    $global:GlobalAdmins                    = $UserRoles | ? { $_.RoleID -Contains '62e90394-69f5-4237-9190-012177145e10' }
    $global:PrivilegedRoleAdmins            = $UserRoles | ? { $_.RoleID -Contains 'e8611ab8-c189-46e8-94e1-60213ab1f814' }
    $global:AppAdmins                       = $UserRoles | ? { $_.RoleID -Contains '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3' }
    $global:CloudAppAdmins                  = $UserRoles | ? { $_.RoleID -Contains '158c047a-c907-4556-b7ef-446551a6b5f7' }
    $global:AppsWithAppAdminRole            = ForEach ($SP in $SPsWithAzureAppAdminRole) {
                                                $AppWithRole = $SPOS | ?{$_.ServicePrincipalID -Match $SP.UserID}
                                                $AppWithRole
                                              }
    $global:SPsWithAzureAppAdminRole        = $UserRoles | ? { ($_.RoleID -match '158c047a-c907-4556-b7ef-446551a6b5f7' -or $_.RoleID -match '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3' ) -and ($_.UserType -match 'serviceprincipal') }


    if ($PrivilegedAuthenticationAdmins){
        AzGetPrivilegedAuthenticationAdministrator
    }
    if ($AuthenticationAdmins){
        AzGetAuthenticationAdminRole
    }
    if ($HelpdeskAdmins){
        AzGetHelpDeskAdminRole
    }
    if ($PasswordAdmins){
        AzGetPasswordAdminRole
    }
    if ($UserAccountAdmins){
        AzGetUserAccountAdminRole
    }
    if ($IntuneAdmins){
        AzGetHelpDeskAdminRole
    }
    if ($GroupsAdmins){
        AzGetGroupsAdminRole
    }
    if ($GlobalAdmins){
        AzGetGlobalAdminRole
    }    
    if ($PrivilegedRoleAdmins){
        AzGetPrivilegedAdminRole
    }
    if ($AppsWithAppAdminRole){
        AzGetApplicationAdmins
    }     
}

# Build $PrivilegedAuthenticationAdminRights - can reset ALL user passwords, including global admins
# Can't reset passwords for external users, which have "#EXT#" added to their UPN
function AzGetPrivilegedAuthenticationAdministrator {
    $TotalCount = $PrivilegedAuthenticationAdmins.Count
    Write-Host "Privileged authentication admins to process: ${TotalCount}"
    $global:PrivilegedAuthenticationAdminRights = ForEach ($User in $PrivilegedAuthenticationAdmins) {
        $TargetUsers = $UserRoles | ? { $_.UserUPN -NotMatch "#EXT#" } | ? {$_.ObjectType -Match "User"}
        ForEach ($TargetUser in $TargetUsers) {
            $PWResetRight = [PSCustomObject]@{
                UserName            = $User.UserName
				ObjectType          = $User.ObjectType
                UserID              = $User.UserID
                UserOnPremID        = $User.UserOnPremID
                TargetUserName      = $TargetUser.UserName
                TargetUserID        = $TargetUser.UserID
                TargetUserOnPremID  = $TargetUser.UserOnPremID
            }
        }   
        ForEach ($TargetUser in $UsersWithoutRoles) {
            $PWResetRight = [PSCustomObject]@{
                UserName            = $User.UserName
				ObjectType          = $User.ObjectType
                UserID              = $User.UserID
                UserOnPremID        = $User.UserOnPremID
                TargetUserName      = $TargetUser.DisplayName
                TargetUserID        = $TargetUser.ObjectId
                TargetUserOnPremID  = $TargetUser.OnPremisesSecurityIdentifier
            }     
            $PWResetRight
        }
    }
    Write-Host "Built `$PrivilegedAuthenticationAdminRights"
}
# Build $AuthAdminsRights - can reset ALL user passwords, including global admins
# Can't reset passwords for external users, which have "#EXT#" added to their UPN
function AzGetAuthenticationAdminRole {
    $TotalCount = $AuthenticationAdmins.Count
    Write-Host "Authentication admins to process: ${TotalCount}"
    $global:AuthAdminsRights = ForEach ($User in $AuthenticationAdmins) {
        $TargetUsers = $UserRoles | ? { $AuthAdminsList -Contains $_.RoleID } | ? { $_.UserUPN -NotMatch "#EXT#" } | ? {$_.ObjectType -Match "User"}
        ForEach ($TargetUser in $TargetUsers) {
            $PWResetRight = [PSCustomObject]@{
                UserName            = $User.UserName
				ObjectType          = $User.ObjectType
                UserID              = $User.UserID
                UserOnPremID        = $User.UserOnPremID
                TargetUserName      = $TargetUser.UserName
                TargetUserID        = $TargetUser.UserID
                TargetUserOnPremID  = $TargetUser.UserOnPremID
            }
            $PWResetRight
        }
        ForEach ($TargetUser in $UsersWithoutRoles) {

            $PWResetRight = [PSCustomObject]@{
                UserName            = $User.UserName
				ObjectType          = $User.ObjectType
                UserID              = $User.UserID
                UserOnPremID        = $User.UserOnPremID
                TargetUserName      = $TargetUser.DisplayName
                TargetUserID        = $TargetUser.ObjectId
                TargetUserOnPremID  = $TargetUser.OnPremisesSecurityIdentifier
            } 
            $PWResetRight
        }
    }
    Write-Host "Built `$AuthAdminsRights"
}
# Build $HelpdeskAdminRights
function AzGetHelpDeskAdminRole {
    $TotalCount = $HelpdeskAdmins.Count
    Write-Host "Help desk admins to process: ${TotalCount}"
    $global:HelpdeskAdminsRights = ForEach ($User in $HelpdeskAdmins) {
        $TargetUsers = $UserRoles | ? { $HelpdeskAdminsList -Contains $_.RoleID } | ? { $_.UserUPN -NotMatch "#EXT#" } | ? {$_.ObjectType -Match "User"}
        ForEach ($TargetUser in $TargetUsers) {
            $PWResetRight = [PSCustomObject]@{
                UserName            = $User.UserName
				ObjectType          = $User.ObjectType
                UserID              = $User.UserID
                UserOnPremID        = $User.UserOnPremID
                TargetUserName      = $TargetUser.UserName
                TargetUserID        = $TargetUser.UserID
                TargetUserOnPremID  = $TargetUser.UserOnPremID
            }
            $PWResetRight
        }
        ForEach ($TargetUser in $UsersWithoutRoles) {
            $PWResetRight = [PSCustomObject]@{
                UserName            = $User.UserName
				ObjectType          = $User.ObjectType
                UserID              = $User.UserID
                UserOnPremID        = $User.UserOnPremID
                TargetUserName      = $TargetUser.DisplayName
                TargetUserID        = $TargetUser.ObjectId
                TargetUserOnPremID  = $TargetUser.OnPremisesSecurityIdentifier
            }
            $PWResetRight
        }
    }
    Write-Host "Built `$HelpdeskAdminsRights"
}
# Build  $PasswordAdminsRights 
function AzGetPasswordAdminRole {
    $TotalCount = $PasswordAdmins.Count
    Write-Host "Password admins to process: ${TotalCount}"
    $global:PasswordAdminsRights = ForEach ($User in $PasswordAdmins) {
        $TargetUsers = $UserRoles | ? { $PasswordAdminList -Contains $_.RoleID } | ? { $_.UserUPN -NotMatch "#EXT#" } | ? {$_.ObjectType -Match "User"}
        ForEach ($TargetUser in $TargetUsers) {
            $PWResetRight = [PSCustomObject]@{
                UserName            = $User.UserName
				ObjectType          = $User.ObjectType
                UserID              = $User.UserID
                UserOnPremID        = $User.UserOnPremID
                TargetUserName      = $TargetUser.UserName
                TargetUserID        = $TargetUser.UserID
                TargetUserOnPremID  = $TargetUser.UserOnPremID
            }
            $PWResetRight
        }
        ForEach ($TargetUser in $UsersWithoutRoles) {
            $PWResetRight = [PSCustomObject]@{
                UserName            = $User.UserName
				ObjectType          = $User.ObjectType
                UserID              = $User.UserID
                UserOnPremID        = $User.UserOnPremID
                TargetUserName      = $TargetUser.DisplayName
                TargetUserID        = $TargetUser.ObjectId
                TargetUserOnPremID  = $TargetUser.OnPremisesSecurityIdentifier
            }
            $PWResetRight
        }
    }
    Write-Host "Built `$PasswordAdminsRights"
}
# Build $UserAccountAdminsRights 
function AzGetUserAccountAdminRole {
    $TotalCount = $UserAccountAdmins.Count
    Write-Host "User account admins to process: ${TotalCount}"
    $Progress = 0
    $global:UserAccountAdminsRights = ForEach ($User in $UserAccountAdmins) {
        $DisplayName = $User.UserName
        $Progress += 1
            $ProgressPercentage = (($Progress / $TotalCount) * 100) -As [Int]
            If ($Progress -eq $TotalCount) {
                Write-Host "Processing user account admins: [${Progress}/${TotalCount}][${ProgressPercentage}%] Current user account admin: ${DisplayName}"
            } else {
                Write-Host "Processing user account admins: [${Progress}/${TotalCount}][${ProgressPercentage}%] Current user account admin: ${DisplayName}" 
            }
        $TargetUsers = $UserRoles | ? { $UserAdminList -Contains $_.RoleID } | ? { $_.UserUPN -NotMatch "#EXT#" } | ? {$_.ObjectType -Match "User"}
        ForEach ($TargetUser in $TargetUsers) {
            $PWResetRight = [PSCustomObject]@{
                UserName            = $User.UserName
				ObjectType          = $User.ObjectType
                UserID              = $User.UserID
                UserOnPremID        = $User.UserOnPremID
                TargetUserName      = $TargetUser.UserName
                TargetUserID        = $TargetUser.UserID
                TargetUserOnPremID  = $TargetUser.UserOnPremID
            }	
			$PWResetRight
        }
        $TargetUsers = $UsersWithoutRoles | ?{$_.OnPremisesSecurityIdentifier -eq $null} | ? { $_.UserUPN -NotMatch "#EXT#" }
        ForEach ($TargetUser in $TargetUsers) {
            $PWResetRight = [PSCustomObject]@{
                UserName            = $User.UserName
				ObjectType          = $User.ObjectType
                UserID              = $User.UserID
                UserOnPremID        = $User.UserOnPremID
                TargetUserName      = $TargetUser.DisplayName
                TargetUserID        = $TargetUser.ObjectId
                TargetUserOnPremID  = $TargetUser.OnPremisesSecurityIdentifier
            }
            $PWResetRight
        }   
    }
    Write-Host "Built `$UserAccountAdminsRights"
}
# Build $IntuneAdminsRights - can add principals to cloud-resident security groups
function AzIntuneAdminRole {
    $global:IntuneAdminsRights = ForEach ($User in $IntuneAdmins) {
        ForEach ($TargetGroup in $CloudGroups) {
            $GroupRight = [PSCustomObject]@{
                UserName        = $User.UserName
				ObjectType      = $User.ObjectType
                UserID          = $User.UserID
                UserOnPremID    = $User.UserOnPremID
                TargetGroupName = $TargetGroup.DisplayName
                TargetGroupID   = $TargetGroup.ObjectID
            }
            $GroupRight
        }
    }
    Write-Host "Built `$IntuneAdminsRights"
}
# Build $GroupsAdminsRights - can add principals to cloud-resident security groups
function AzGetGroupsAdminRole {
    $global:GroupsAdminsRights = ForEach ($User in $GroupsAdmins) {
        ForEach ($TargetGroup in $CloudGroups) {
            $GroupRight = [PSCustomObject]@{
                UserName        = $User.UserName
				ObjectType      = $User.ObjectType
                UserID          = $User.UserID
                UserOnPremID    = $User.UserOnPremID
                TargetGroupName = $TargetGroup.DisplayName
                TargetGroupID   = $TargetGroup.ObjectID
            }
            $GroupRight
        }
    }
    Write-Host "Built `$GroupsAdminsRights"
}
# Build $GlobalAdminsRights - has full control of everything in the tenant
function AzGetGlobalAdminRole {
    $TenantDetails = Get-AzureADTenantDetail
    $global:GlobalAdminsRights = ForEach ($User in $GlobalAdmins) {    

        $GlobalAdminRight = [PSCustomObject]@{
            UserName            = $User.UserName
			ObjectType          = $User.ObjectType
            UserID              = $User.UserID
            UserOnPremID        = $User.UserOnPremID
            TenantDisplayName   = $TenantDetails.DisplayName
            TenantID            = $TenantDetails.ObjectID
        }
        $GlobalAdminRight
    }
    Write-Host "Built `$GlobalAdminsRights"
}
# Build $PrivilegedRoleAdminRights - can add role assignments to any other user including themselves
function AzGetPrivilegedAdminRole {
    $global:PrivilegedRoleAdminRights = ForEach ($User in $PrivilegedRoleAdmins) { 
        $PrivilegedRoleAdminRight = [PSCustomObject]@{
            UserName            = $User.UserName
			ObjectType          = $User.ObjectType
            UserID              = $User.UserID
            UserOnPremID        = $User.UserOnPremID
            TenantDisplayName   = $TenantDetails.DisplayName
            TenantID            = $TenantDetails.ObjectID
        }
    }
    Write-Host "Built `$PrivilegedRoleAdminRights"
}
# Build $AppAdminsRights - can create new secrets for application service principals
function AzGetApplicationAdmins ($OutputDirectory){
    $global:AppAdminsRights = ForEach ($Principal in $AppAdmins) {
        $TargetApps = $AppsWithAppAdminRole
        ForEach ($TargetApp in $TargetApps) {
            $AppRight = [PSCustomObject]@{
                AppAdminID          = $Principal.UserID
                AppAdminType        = $Principal.UserType
                AppAdminOnPremID    = $Principal.UserOnPremID
                TargetAppID         = $TargetApp.AppID
            }
            $AppRight
        }
        ForEach ($TargetApp in $SPswithoutRoles) {
            $AppRight = [PSCustomObject]@{
                AppAdminID          = $Principal.UserID
                AppAdminType        = $Principal.UserType
                AppAdminOnPremID    = $Principal.UserOnPremID
                TargetAppID         = $TargetApp.AppID
            }
            $AppRight
        }
    }
    New-Output -Coll $Coll -Type "applicationadmins" -Directory $OutputDirectory
    Write-Host "Built `$AppAdminsRights"
    Write-Host "Wrote azapplicationadmins.json"
}
# Build $SPswithoutRoles - SPs without roles
function AzGetServicePrincipalsWithoutRoles {
    $PrincipalRoles = ForEach ($User in $Results){
        $SPRoles = New-Object PSObject
        If ($User.MemberType -match 'servicePrincipal')
        {
        $SPRoles = [PSCustomObject]@{
            RoleID  = $User.RoleID
            SPId    = $User.MemberID
        }
        $SPRoles
        }
    }
    $global:SPswithoutRoles = $SPOS | Where-Object {$_.ServicePrincipalID -notin $PrincipalRoles.SPId}
    Write-Host "Built `$SPswithoutRoles"
}



# Get Admin Rights 
# Write pwresetrights, groupsrights, globaladminrights, privroleadminrights
function AzGetPriviligedAuthenticationAdminRights ($OutputDirectory){
    $PrivilegedAuthenticationAdminRights | ForEach-Object {
        $null = $Coll.Add($_)
    }
    $AuthAdminsRights | ForEach-Object {
        $null = $Coll.Add($_)
    }
    $HelpdeskAdminsRights | ForEach-Object {
        $null = $Coll.Add($_)
    }
    $PasswordAdminsRights | ForEach-Object {
        $null = $Coll.Add($_)
    }
    $UserAccountAdminsRights | ForEach-Object {
        $null = $Coll.Add($_)
    }
    New-Output -Coll $Coll -Type "pwresetrights" -Directory $OutputDirectory  

    $Coll = New-Object System.Collections.ArrayList
    $IntuneAdminsRights | ForEach-Object {
        $null = $Coll.Add($_)
    }
    $GroupsAdminsRights | ForEach-Object {
        $null = $Coll.Add($_)
    }
    New-Output -Coll $Coll -Type "groupsrights" -Directory $OutputDirectory
    New-Output -Coll $GlobalAdminsRights -Type "globaladminrights" -Directory $OutputDirectory
    New-Output -Coll $PrivRoleColl -Type "privroleadminrights" -Directory $OutputDirectory
}
# Build $CloudAppAdminRights - can create new secrets for application service principals
function AzGetCloudApplicationAdmins ($OutputDirectory) {
    $global:CloudAppAdminRights = ForEach ($Principal in $AppAdmins) {   
        $TargetApps = $AppsWithAppAdminRole  
        ForEach ($TargetApp in $TargetApps) {
            $AppRight = [PSCustomObject]@{
                AppAdminID          = $Principal.UserID
                AppAdminType        = $Principal.UserType
                AppAdminOnPremID    = $Principal.UserOnPremID
                TargetAppID         = $TargetApp.AppID
            }
            $AppRight
        }
        ForEach ($TargetApp in $SPswithoutRoles) {
            $AppRight = [PSCustomObject]@{
                AppAdminID          = $Principal.UserID
                AppAdminType        = $Principal.UserType
                AppAdminOnPremID    = $Principal.UserOnPremID
                TargetAppID         = $TargetApp.AppID
            }
            $AppRight
        }
    }
    New-Output -Coll $Coll -Type "cloudappadmins" -Directory $OutputDirectory
	Write-Host "Done processing Cloud Application Admins"
}







function AzGetProcessedData {
    Write-Host "Compressing files"
    $location = Get-Location
    $name = $date + "-azurecollection"
    If($OutputDirectory.path -eq $location.path){
        $jsonpath = $OutputDirectory.Path + [IO.Path]::DirectorySeparatorChar + "$date-*.json"
        $destinationpath = $OutputDirectory.Path + [IO.Path]::DirectorySeparatorChar + "$name.zip"
    }
    else{
        $jsonpath = $OutputDirectory + [IO.Path]::DirectorySeparatorChar + "$date-*.json"
        $destinationpath = $OutputDirectory + [IO.Path]::DirectorySeparatorChar + "$name.zip"
    }

    $error.Clear()
    try {
        Compress-Archive $jsonpath -DestinationPath $destinationpath
    }
    catch {
        Write-Host "Zip file creation failed, JSON files may still be importable."
    }
    if (!$error) {
        Write-Host "Zip file created: $destinationpath"
        rm $jsonpath
        Write-Host "Done! Drag and drop the zip into the BloodHound GUI to import data."
    }
}