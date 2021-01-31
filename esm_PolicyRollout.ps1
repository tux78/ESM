
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

# IP or FQDN of local ESM
$global:esmIP = '10.10.10.10'

# DS ID of any ERC/ACE to have policy rolled out
# if empty or comment (#), ALL data sources will have the policy rolled out
# $global:ercID = '144116287587483648'

########################### 
# Some Inits
###########################
$global:esmAPI = 'https://' + $global:esmIP + '/rs/esm/v2/'
$global:headers = $null
$global:cookie = $null

########################### 
# Main Function
###########################
Function Main
{
  Login;
  $response = ''
  if ($null -eq $global:ercID -or $global:ercID -eq '')
  {
    $response = devGetDeviceList @('RECEIVER')
    $response = $response | ConvertFrom-Json
  } else {
    $response = '{"id" : "' + $ercID + '"}' | convertfrom-json
  }
  Foreach ($erc in $response)
  {
    $datasources = dsGetDataSourceList $erc.id
    # Write-Host $datasources
    $datasources = $datasources | ConvertFrom-Json
    $dslist = @()
    Foreach ($ds in $datasources)
    {
      Write-Host 'Policy rollOut for data source: ' $ds.name ' (' $ds.id ')'
      $dslist += $ds.id
    }
    $rollout = plcyRollPolicy $dslist
  }
}

#################################################################################################
# ESM API IMPLEMENTATION
#################################################################################################

########################### 
# Get ESM Devices
###########################
Function devGetDeviceList ($deviceType)
{
  # must be one of the following:
  # [KID_CLUSTER, NSM_INTERFACE,EPO, ELM, IPS, THIRD_PARTY, DBM, ASSET, SEARCH_ELASTIC, 
  # ESM, NSM, BUCKET, VA, DBM_DB, SYSTEM, NSM_SENSOR, POLICY, LOCALESM, DBM_AGENT, RISKAGENT,
  # KID_NODE, APM, IPSVIPS, MVM, EPO_APP, RISK, RISKMANAGER, ELMREC, RECEIVER, APMVIPS, UNKNOWN]
  $params = @{types = $deviceType}
  $response = CallEsmApi 'devGetDeviceList?filterByRights=false' $params
  return $response.Content 
}

########################### 
# Get Data Sources per Device
###########################
Function dsGetDataSourceList ($receiverID)
{
  $params = @{
    receiverId = $receiverId
  }
  $response = CallEsmApi 'dsGetDataSourceList' $params
  return $response.Content 
}

########################### 
# Roll Out Policy
###########################
Function plcyRollPolicy ($dsID)
{
  $params = @{
    ids = $dsID
  };
  $response = CallEsmApi 'plcyRollPolicy' $params
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
  $body = $params | ConvertTo-Json

  $response = Invoke-WebRequest $url -Method Post -Headers $global:headers -WebSession $global:cookie -Body $body
  return $response
}

Main;
