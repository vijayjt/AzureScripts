<#

.SYNOPSIS
    Applies a set of AD group and Azure RBAC roles to a subscription

.DESCRIPTION
    Applies a set of AD group and Azure RBAC roles to a subscription
             
.PARAMETER RoleAssigmentsCSVFile
    A CSV file containing AD groups or users and the corresponding Azure RBAC role to be assigned.
    
@"
ADObjectDisplayNameOrUPN,ADObjectType,RoleDefinition,ScopeLevel,TargetScope
bob.smith@acme.com,User,Reader,subscription,
MyADGroup1,Group,Owner,subscription,
MyADGroup2,Group,Contributor,resourcegroup,RG-Test
"@ | out-file example-role-assingments.csv

    The ADObjectDisplayNameOrUPN field should contain the UPN if it's a user account and the display name if it is an AD group.
    The ScopeLeveL field currently only supports:
        - subscription: meaning the role will be scoped to the subscription specified by the SubscriptionName parameter or;
        - resourcegroup: meaning the role will be scoped to a particular resouce group or set of resource groups

    The TargetScope is left blank if the role is to be applied at the subscription level. If it the ScopeLevel is resourcegroup then:
        - For single resource groups enter the resource group name
        - For multiple resource groups enter a comma separated and quoted list of resource groups e.g. "rg1,rg2,rg3"

.PARAMETER SubscriptionName
    The name of the subscription where the role assignments are to be made.


.EXAMPLE
    
    .\Set-AAMAzureRoleAssignments.ps1 -RoleAssigmentsCSVFile C:\example-role-assingments.csv -SubscriptionName TestSubscription
    
.NOTES
    To Do:
        1. Add errror checking so that if the role assignment already exists we do not attempt to duplicate it (as it will fail)
    
#>
[Cmdletbinding()]
Param(
    [Parameter(Mandatory=$true,HelpMessage='The CSV file containing the role assignments')]
        [ValidateScript({ Test-Path $_ })]
        [String]$RoleAssigmentsCSVFile,
    [Parameter(Mandatory=$true,HelpMessage='The name of the subscription where the role assignments are to be applied')]
        [String]$SubscriptionName
)

#region --- MODULE IMPORTS ---

#endregion


#region --- VARIABLES ---
$RoleAssigmentsCSVFileName = Split-Path -Path $RoleAssigmentsCSVFile -Resolve -Leaf
$FileExtension = ($RoleAssigmentsCSVFileName -split '\.')[1]

#endregion



#region --- General Functions ---

#endregion


#region --- Azure Functions ---

Function Test-IsAuthenticatedRmAPI
{
<# 
   .SYNOPSIS 
        This function checks if the user exeucting this script is authenticated against Azure AD
   .DESCRIPTION 
        This function checks if the user exeucting this script is authenticated against Azure AD
   .EXAMPLE 
        Test-IsAuthenticatedRmAPI
   .NOTES
        Requirements: Copy this module to any location found in $env:PSModulePath
        This module depends on the Azure Resource Manager PowerShell modules
   
#>
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    Param()

    try
    {
        Write-Debug 'Checking if you have been authenticated against Azure using Login-AzureRmAccount.'        
        $AuthCheck1 = Get-AzureRmContext -ErrorAction Stop
    }
    catch
    {
        $ErrorIndex = $Error.Count - 1
        If ( ($Error[$Error.Count-1].Exception | Out-String).Trim() -eq 'Run Login-AzureRmAccount to login.' ) 
        { 
            Write-Error 'Your Windows Azure credential in the Windows PowerShell session has expired. Please use Login-AzureRmAccount to login again.'            
        }
        else
        {
            Write-Error "An error occurred please try again. Displaying last `$Error variable contents: $($Error[$ErrorIndex-1])"
        }
        return $false 
    }

    $UserID = ($AuthCheck1 | Select-Object Account).Account
    Write-Debug "Authenticated as $UserID (ARM Mode)"
    return $true

}#EndFunction Test-IsAuthenticatedRMAPI

Function Test-AzureSubscriptionExist
{
<# 
   .SYNOPSIS 
        This function checks if the specified subscription exists
   .DESCRIPTION 
        This function checks if the specified subscription exists. If the user does not have access to the subscription then the subscription will not be visible, and in this case this function will still return false.
   .EXAMPLE 
        Test-AzureSubscriptionExist -SubscriptionName myAzureSubscription
   .NOTES
        Requirements: Copy this module to any location found in $env:PSModulePath
        This module depends on the Azure Resource Manager PowerShell modules
   
#>
[CmdletBinding()]
[OutputType([System.Boolean])]
Param(
    [Parameter(Mandatory=$true,HelpMessage='Please enter the subscription name.')]
    [ValidateNotNullOrEmpty()]
    [String]$SubscriptionName
)

 return (Get-AzureRmSubscription | Select-Object -ExpandProperty SubscriptionName) -contains $SubscriptionName

}#EndFunction Test-AzureSubscriptionExist


#endregion

#region --- MAIN PROGRAM ---


Write-Output "Validating that the role assignments file is a CSV file"

# Check the file has a .csv extension
If( $FileExtension.ToLower() -ne "csv" )
{
   throw "Error, the provided role assignments file $($RoleAssigmentsCSVFile) does not have a .csv extension. Please verify this is a valid CSV file."
}

# Check if we can pipe the file contents to ConvertFrom-Csv without error
Try
{
    $ConvertedCSV = Get-Content $RoleAssigmentsCSVFile | ConvertFrom-Csv
    
}
Catch 
{
    throw "Error, unable to parse the provided role assignments file $($RoleAssigmentsCSVFile) as CSV. Please verify this is a valid CSV file."
}

# Check if the CSV file has the expected properties
$ExpectedProperties = @('ADObjectDisplayNameOrUPN','ADObjectType','RoleDefinition','ScopeLevel','TargetScope')

ForEach ( $Property in ($ConvertedCSV | Get-Member -MemberType NoteProperty).Name )
{
    If( $ExpectedProperties -notcontains $Property )
    {
        throw "Error, the provided role assignments file $($RoleAssigmentsCSVFile) does not contain the expected fields"
    }
}


Write-Output 'Checking if you are authenticated against the ARM API.'
Write-Output ''

If ( Test-IsAuthenticatedRmAPI )
{
    # Only proceed if the user has access to the subscription
    If( Test-AzureSubscriptionExist $SubscriptionName )
    {
        #Change the current subscription
        $SubscriptionContext = Set-AzureRmContext -SubscriptionName $SubscriptionName
        ForEach( $Line in $ConvertedCSV )
        {

            # Determine scope
            If( $Line.ScopeLevel -eq "subscription" )
            {
                $Scopes = "/subscriptions/{0}" -f $SubscriptionContext.Subscription.SubscriptionId
            }
            ElseIf( $Line.ScopeLevel -eq "resourcegroup" )
            {
                $ResourceGroups = $Line.TargetScope -split ','
                If( $ResourceGroups.count -gt 1 )
                {
                    $Scopes = @()
                    ForEach( $ResourceGroup in $ResourceGroups)
                    {
                        $Scopes += "/subscriptions/{0}/resourceGroups/{1}" -f $SubscriptionContext.Subscription.SubscriptionId,$ResourceGroup
                    }
                }            
            }


            #Check the user/group exists in Azure AD
            If( $Line.ADObjectType -eq "User" -and (Test-AzureADUserExist -Username $Line.ADObjectDisplayNameOrUPN)  )
            {
                #Check the RoleDefinition exists in the subscription
                If( Test-AzureRmRoleDefinitionExist -RoleDefinitionName $Line.RoleDefinition )
                {
                    ForEach($ScopeToApply in $Scopes)
                    {
                        $UserObject = Get-AzureRmADUser -UserPrincipalName $Line.ADObjectDisplayNameOrUPN
                        Write-Output "Granting role $($Line.RoleDefinition) to user $($UserObject.DisplayName) at the scope $ScopeToApply"
                        New-AzureRmRoleAssignment -ObjectId $UserObject.Id.Guid -RoleDefinitionName $Line.RoleDefinition -Scope $ScopeToApply
                    }
                }
                Else
                {
                    Write-Error "Unable to grant role $($Line.RoleDefinition) to user $($UserObject.DisplayName) at the scope $ScopeToApply - the role definition does not exist in this subscription."
                }
            }
            ElseIf( $Line.ADObjectType -eq "Group" -and (Test-AzureADGroupExist -ADGroup $Line.ADObjectDisplayNameOrUPN) )
            {
                #Check the RoleDefinition exists in the subscription
                If( Test-AzureRmRoleDefinitionExist -RoleDefinitionName $Line.RoleDefinition )
                {
                    ForEach($ScopeToApply in $Scopes)
                    {
                        Write-Output "Granting role $($Line.RoleDefinition) to AD Group $($Line.ADObjectDisplayNameOrUPN) at the scope $ScopeToApply"
                        $ADSecurityGroupObject = Get-AzureRmADGroup -SearchString $Line.ADObjectDisplayNameOrUPN 
                        New-AzureRmRoleAssignment -ObjectId $ADSecurityGroupObject.Id.Guid -RoleDefinitionName $Line.RoleDefinition -Scope $ScopeToApply
                    }
                }            
                Else
                {
                    Write-Error "Unable to grant role $($Line.RoleDefinition) to user $($UserObject.DisplayName) at the scope $ScopeToApply - the role definition does not exist in this subscription."
                }
            }
            Else
            {
                Write-Error "The user/group $($Line.ADObjectDisplayNameOrUPN) does not exist in Azure AD"
            }        
        }
    }
    Else 
    {
        Throw "Error, the provided subscription $SubscriptionName does not exist or you do not have permissions to the subscription, exiting the script"
    }

}
Else
{
    Throw 'Error: You are not authenticated, unable to continue.'
}


#endregion