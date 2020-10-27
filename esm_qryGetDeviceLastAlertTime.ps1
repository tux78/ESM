
cls
add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

############################## 
# Change variables accordingly
##############################

$global:esmIP = '10.10.10.10'

########################### 
# Some Inits
###########################
$global:esmAPI = 'https://' + $global:esmIP + '/rs/esm/v2/'
$global:headers = $null
$global:cookie = $null

########################### 
# Main Function
###########################

Function main
{

  # Parameters

  # Interpret the returned "lastEvent" timestamp; depends on UserAgent/locale setting within PS
  $time_string = "MM/dd/yyyy HH:mm:ss" 
  # time range to identify idle data sources
  $time_window = 15 
  # do not display the following data source types
  $excludedTypes = @( 
    'McAfee Enterprise Log Manager'
    'McAfee Event Receiver'
    'McAfee Advanced Correlation Engine'
    'Correlation Engine'
    'NitroGuard IPS'
    'ePolicy Orchestrator'
  )

  login;
  $result = qryGetDeviceLastAlertTime | ConvertFrom-Json
  $days = @{l="Days";e={((Get-Date) - [datetime]::ParseExact($_.lastEvent, $time_string, [System.Globalization.CultureInfo]::CurrentCulture)).Days}}
  Write-Output (
    $result |
     where deviceType -NotIn $excludedTypes |
     Select deviceName, deviceType, lastEvent, createTime, $days|
     where Days -ge $time_window |
     select deviceName, deviceType, Days, lastEvent
  )
}


#################################################################################################
# ESM API IMPLEMENTATION
#################################################################################################

###########################
# Get DataSource Status
###########################

Function qryGetDeviceLastAlertTime()
{
  $params = @{}

  $response = CallEsmApi 'qryGetDeviceLastAlertTime' $params
  return $response.Content
}

#################################################################################################
# HELPER FUNCTIONS
#################################################################################################

########################### 
# Login
###########################
Function Login
{
  $esmhost = 'https://' + $global:esmIP + '/rs/esm/'
  $cred = Get-Credential
  $username = $cred.GetNetworkCredential().Username
  $passwd = $cred.GetNetworkCredential().Password
  $login_url = $esmhost + "login"
 
  $b64_user = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($username))
  $b64_passwd = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($passwd))


  $params = @{
        username = $b64_user
        password = $b64_passwd
        locale = 'en_US'
        os = 'Win32'};        
  $body = $params | ConvertTo-Json
 
  $global:headers = @{
    'Content-Type' = 'application/json'
  };
 
  $login_headers = $global:headers
  $login_headers.Add("Authorization", "Basic "+[System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($username+":"+$passwd )))
  $response = Invoke-WebRequest $login_url -Method Post -Headers $login_headers -Body $body -SessionVariable global:cookie
 
  $global:headers.Add('X-Xsrf-Token', $response.headers.Get_Item('Xsrf-Token'))

}

########################### 
# Call ESM API
###########################
Function CallEsmApi ([String]$method, $params)
{
  $url = -join($global:esmAPI, $method)
  $body = $params | ConvertTo-Json -depth 10

  $response = Invoke-WebRequest $url -Method Post -Headers $global:headers -WebSession $global:cookie -Body $body
  return $response
}

Main;
