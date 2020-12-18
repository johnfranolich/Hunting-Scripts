#Audit expiring soon Azure AD application credentials (keys/certificates) https://gallery.technet.microsoft.com/scriptcenter/Audit-expiring-soon-Azure-60dbbbcf
#Alert (AA20-352A) https://us-cert.cisa.gov/ncas/alerts/aa20-352a 
#Author tweaks John Franolich and Jamie Gambetta 
#run from AZ CLI 

Write-Host 'Gathering necessary information...'
$applications = Get-AzADApplication
$servicePrincipals = Get-AzADServicePrincipal

$appWithCredentials = @()
$appWithCredentials += $applications | Sort-Object -Property DisplayName | % {
    $application = $_
    $sp = $servicePrincipals | ? ApplicationId -eq $application.ApplicationId
    Write-Verbose ('Fetching information for application {0}' -f $application.DisplayName)
    $application | Get-AzADAppCredential -ErrorAction SilentlyContinue | Select-Object -Property @{Name='DisplayName'; Expression={$application.DisplayName}}, @{Name='ObjectId'; Expression={$application.Id}}, @{Name='ApplicationId'; Expression={$application.ApplicationId}}, @{Name='KeyId'; Expression={$_.KeyId}}, @{Name='Type'; Expression={$_.Type}},@{Name='StartDate'; Expression={$_.StartDate -as [datetime]}},@{Name='EndDate'; Expression={$_.EndDate -as [datetime]}}
  }

Write-Host 'Validating expiration data...'
$today = (Get-Date).ToUniversalTime()
$appWithCredentials | Sort-Object EndDate | % {
        if($_.EndDate -lt $today) {
            $_ | Add-Member -MemberType NoteProperty -Name 'Status' -Value 'Expired'
        } else {
            $_ | Add-Member -MemberType NoteProperty -Name 'Status' -Value 'Valid'
        }
		$Duration=NEW-TIMESPAN –Start $_.StartDate –End $_.EndDate 
		$_ | Add-Member -MemberType NoteProperty -Name 'DurationInDays' -Value $Duration.TotalDays 
}

$appWithCredentials 
Write-Host 'Done.'




