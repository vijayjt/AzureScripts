<#
    .SYNOPSIS
        This script audits the Azure RBAC role assignments across one or all subscriptions the user has access to.
        
    .DESCRIPTION
        This script audits the Azure RBAC role assignments across one or all subscriptions the user has access to.
        The user running the script must have permissions to read permissions e.g. 'Microsoft.Authorization/*/read' permissions

        The results are returned either as an object, or as a CSV file.

    .PARAMETER SubscriptionName
        If this parameter is specified then the script will only run against the specified subscription

    .PARAMETER AllSubscriptions
        If this parameter is specified then the script will run against all subscriptions that the user running the script has access to.

    .PARAMETER OutputCSV
        This option switch will cause the script to return CSV formatted data that can then be piped into a file.
    
    .PARAMETER AADTenantDomainName
        The domain associated with the Azure AD tenant e.g. acme.com

    .EXAMPLE
        
        .\Get-xAzureRBACRoleAssignments.ps1 -SubscriptionName 'MySubscriptionName' -AADTenantDomainName acme.com

        .\Get-xAzureRBACRoleAssignments.ps1 -SubscriptionName 'MySubscriptionName' -OutputCSV -AADTenantDomainName acme.com

        .\Get-xAzureRBACRoleAssignments.ps1 -AllSubscriptions -AADTenantDomainName acme.com

        .\Get-xAzureRBACRoleAssignments.ps1 -AllSubscriptions -OutputCSV -AADTenantDomainName acme.com

    .NOTES

#>
[CmdletBinding()]
Param(
    [Parameter(ParameterSetName='SingleSubscription',Mandatory=$true,HelpMessage='Enter the subscription name to report against')]
        [ValidateNotNullOrEmpty()]
        [String]$SubscriptionName,
    [Parameter(ParameterSetName='AllSubscriptions',Mandatory=$true,HelpMessage='Specify this switch to report against all subscriptions')]
        [ValidateNotNullOrEmpty()]
        [Switch]$AllSubscriptions,
    [Parameter(ParameterSetName='SingleSubscription',Mandatory=$false,HelpMessage='Specify this switch to output the results in CSV format')]
    [Parameter(ParameterSetName='AllSubscriptions')]
        [ValidateNotNullOrEmpty()]
        [Switch]$OutputCSV,
    [Parameter(ParameterSetName='SingleSubscription',Mandatory=$true,HelpMessage='Enter the domain associated with the Azure AD Tenant')]
    [Parameter(ParameterSetName='AllSubscriptions')]
        [ValidateNotNullOrEmpty()]
        [String]$AADTenantDomainName
)


#region --- MODULE IMPORTS ---

#endregion


#region --- VARIABLES ---
$AzureRoleAssignments = @()
#endregion


#region --- General Functions ---

#endregion


#region --- Azure Functions ---

#Source: http://spr.com/azure-arm-group-membership-recursively-part-1/
Function Get-RecursiveGroupMembership
{
  [CmdletBinding(SupportsShouldProcess=$true)]
  Param(  
    [Parameter(Mandatory=$true, ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true,Position=0)]
        [ValidateScript({Get-AzureRmADGroup -ObjectId $_})]$ObjectId,
    [parameter(Mandatory=$false)]
        [Switch]$Recursive
  )
  $topMembers = Get-AzureRmADGroupMember -GroupObjectId $ObjectId | Where-Object {$_.type -eq 'user'}
  If ($topMembers) {$toplist += $topmembers}
  $UserMembers = @()
  If ($PSBoundParameters['Recursive']) 
  {
    $GroupsMembers = Get-AzureRmADGroupMember -GroupObjectId $ObjectId| Where-Object {$_.type -eq 'group'}
    If ($GroupsMembers) 
    {
        $GroupsMembers | ForEach-Object -Process {
            $UserMembers += Get-RecursiveGroupMembership -Recursive -ObjectId $_.id -Verbose
        }
        $sublist += $UserMembers
    }
  }
  $userlist = (($sublist + $toplist) | Sort-Object -Property userprincipalname -Unique)
  return $userlist
}
#EndFunction Get-RecursiveGroupMembers

#endregion

#region --- MAIN PROGRAM ---

$Filter = '*'
If($SubscriptionName)
{
    Write-Verbose "Filtering on subscription $SubscriptionName"
    $Filter = $SubscriptionName
}
 
Get-AzureRmSubscription | Where-Object { $_.SubscriptionName -like $Filter } | ForEach-Object {
    $SubscriptionName = $_.SubscriptionName
    Set-AzureRmContext -SubscriptionName $SubscriptionName | Out-Null
    $RoleAssignmentList = Get-AzureRmRoleAssignment -IncludeClassicAdministrators | Select-Object DisplayName,SignInName,ObjectType,RoleDefinitionName,Scope
    
    ForEach( $RoleAssignment in $RoleAssignmentList)
    {
        $RoleAssignmentObject = New-Object System.Object
        $RoleAssignmentObject | Add-Member -type NoteProperty -name Subscription -Value $SubscriptionName
        $RoleAssignmentObject | Add-Member -type NoteProperty -name DisplayName -Value $RoleAssignment.DisplayName
        $RoleAssignmentObject | Add-Member -type NoteProperty -name SignInName -Value $RoleAssignment.SignInName
        $RoleAssignmentObject | Add-Member -type NoteProperty -name ObjectType -Value $RoleAssignment.ObjectType
        $RoleAssignmentObject | Add-Member -type NoteProperty -name RoleDefinitionName -Value $RoleAssignment.RoleDefinitionName
        $RoleAssignmentObject | Add-Member -type NoteProperty -name Scope -Value $RoleAssignment.Scope

        $GroupMembers = 'not applicable'
        $IsServiceAdministrator = 'No'
        $IsCoAdministrator = 'No'
        $IsAccountAdministrator = 'No'

        $IsRoleAppliedAtSubscriptionScope = 'No'
        If( ($RoleAssignment.RoleDefinitionName -notlike '*resourceGroups*') )
        {
            Write-Verbose "The user/group $($RoleAssignment.DisplayName) has been applied at the subscription level"
            $IsRoleAppliedAtSubscriptionScope = 'Yes'
        }

        $RoleAssignmentObject | Add-Member -type NoteProperty -name IsRoleAppliedAtSubscriptionScope -Value $IsRoleAppliedAtSubscriptionScope

        If( $RoleAssignment.ObjectType -eq 'Group')
        {
            $GroupMembers = (Get-RecursiveGroupMembership -ObjectId (Get-AzureRmADGroup -SearchString $RoleAssignment.DisplayName).Id.Guid | Select-Object -ExpandProperty DisplayName) -join ','
            $Source = "Azure AD Tenant $AADTenantDomainName"
        }
        
        If( $RoleAssignment.ObjectType -eq 'User' ) 
        {
          If( $RoleAssignment.RoleDefinitionName -like '*CoAdministrator*' )
          {
            $IsCoAdministrator = 'Yes'
          }
          ElseIf( $RoleAssignment.RoleDefinitionName -like '*ServiceAdministrator*' )
          {
            $IsServiceAdministrator = 'Yes'
          }
          ElseIf( $RoleAssignment.RoleDefinitionName -like '*AccountAdministrator*' )
          {
            $IsAccountAdministrator = 'Yes'
          }
          
          If( $RoleAssignment.SignInName -like "*@$AADTenantDomainName" )
          {
            Write-Verbose "OK: User sourced from Azure AD directory $($RoleAssignment.SignInName)"
            $Source = "Azure AD Tenant $AADTenantDomainName"
          }
          ElseIf( $RoleAssignment.SignInName -like '*#EXT#@*onmicrosoft.com' )
          {
            Write-Warning "User sourced from external directory $($RoleAssignment.SignInName), check this is an approved directory."
            $Source = 'External Directory to Subscription AD Tenant'
          }
          Else
          {
            Write-Warning "User account appears to be a personal or non-directory account $($RoleAssignment.SignInName), further investigation required"
            $Source = 'Personal or other type of external account'
          }                    
        }

        If( $RoleAssignment.ObjectType -eq 'ServicePrincipal' )
        {
            Write-Verbose "This is an Azure AD Service Principal $($RoleAssignment.DisplayName)"
            $Source = 'Azure AD Tenant used by the Subscription'
        }

        $RoleAssignmentObject | Add-Member -type NoteProperty -name Source -Value $Source
        $RoleAssignmentObject | Add-Member -type NoteProperty -name IsServiceAdministrator -Value $IsServiceAdministrator
        $RoleAssignmentObject | Add-Member -type NoteProperty -name IsCoAdministrator -Value $IsCoAdministrator
        $RoleAssignmentObject | Add-Member -type NoteProperty -name IsAccountAdministrator -Value $IsAccountAdministrator

        $RoleAssignmentObject | Add-Member -type NoteProperty -name GroupMembers -Value $GroupMembers
        $AzureRoleAssignments += $RoleAssignmentObject
    }    
}

If( $OutputCSV )
{
    $AzureRoleAssignments | ConvertTo-Csv -NoTypeInformation
}
Else
{
    $AzureRoleAssignments    
}

#endregion