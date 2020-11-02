
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
Function Main
{
  # Please enter Source and Target ID of the Event Receiver here
  $erc_source = '144112345678912345'
  $erc_target = '144112345678912346'

  Login;
  $datasources = (dsGetDataSourceList $erc_source) | ConvertFrom-Json
  $new_datasources = @()

  # Iterate through all data sources from old ERC
  Foreach ($ds in $datasources)
  {
    # Get Details per data source
    $detail = dsGetDataSourceDetail ($ds.id) | ConvertFrom-Json
    # in case this data source holds clients (child type = 2), get them
    if ($detail.childType -eq 2)
    {
      $detail | Add-Member -MemberType NoteProperty -Name 'client_ds' -Value (dsGetDataSourceClients $ds.id | ConvertFrom-Json)
    }
    $new_datasources += $detail
  }
  dsAddDataSources $erc_target $new_datasources
  Write-Output ('Done.')
}

#################################################################################################
# ESM API IMPLEMENTATION
#################################################################################################


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
# Get Data Source Details
###########################
Function dsGetDataSourceDetail ($dsId)
{
  $params = @{
    datasourceId = $dsId
  }
  $response = CallEsmApi 'dsGetDataSourceDetail' $params
  return $response.Content 
}

########################### 
# Get Data Source Clients
###########################
Function dsGetDataSourceClients ($dsId)
{
  $params = @{
    datasourceId = $dsId
  }
  $response = CallEsmApi 'dsGetDataSourceClients' $params
  return $response.Content 
}

########################### 
# Add Data Sources
###########################
Function dsAddDataSources ($erc, $datasources)
{
  $ds_all = @()
  $ds_single = @()
  foreach ($ds in $new_datasources)
  {
    if (-not ($ds.client_ds))
    {
      $ds_all += ($ds | select name, ipAddress, typeId, zoneId, enabled, url, parameters)
    } else {
      $ds_single += @{
        'ds' = $ds | select name, ipAddress, typeId, zoneId, enabled, url, parameters
        'client_ds' = $ds.client_ds
      }
    }
  }

  # Add all data sources that do not have clients at once
  $params = @{
    'receiverId' = $erc
    'datasources' = $ds_all
  }
  $jobId = ((CallEsmApi 'dsAddDataSources' $params).content | ConvertFrom-Json).value
  Write-Output('Creating parent data sources w/o client; jobID: ' + $jobId)
  $response = (jobStatus 'dsAddDataSourcesStatus' $jobId)
  Write-Output('Creating parent data sources w/o client; jobID: ' + $jobId + ' ...Done')

  # Add data sources with clients one by one
  foreach ($datasource in $ds_single)
  {
    # create parent Data Source
    $params = @{
      'receiverId' = $erc
      'datasources' = @($datasource.ds)
    }
    $jobId = ((CallEsmApi 'dsAddDataSources' $params).content | ConvertFrom-Json).value
    Write-Output('Creating parent data source that has clients; jobID: ' + $jobId)
    $parentId = (jobStatus 'dsAddDataSourcesStatus' $jobId).successfulDatasources[0]
    Write-Output('Creating parent data source that has clients; jobID: ' + $jobId + ' new parent: ' + $parentId + '...Done')

    # create client Data Sources
    dsAddDataSourceClients $parentId $datasource.client_ds
  }

  return 'Done dsAddDataSources.'
}

########################### 
# Add Data Source Clients
###########################
Function dsAddDataSourceClients ($parentId, $datasourceclients)
{
  Write-Output ('ParentID ' + $parentId + ': Creating clients...')
  $new_clients = @()
  foreach ($client in $datasourceclients)
  {
    $new_clients += ($client | select dateOrder, port, useTls, host, timezone, type, name, ipAddress)
  }
  $params = @{
    'parentId' = $parentId
    'clients' = $new_clients
  }
  $jobId = ((CallEsmApi 'dsAddDataSourceClients' $params).content | ConvertFrom-Json).value
  Write-Output ('ParentID ' + $parentId + ': Creating clients...Done')
  return $jobId
}

#################################################################################################
# HELPER FUNCTIONS
#################################################################################################

########################### 
# Job Status
###########################

Function jobStatus([String]$method, $jobId)
{
  do
  {
    $status = (CallEsmApi $method @{'jobId' = $jobId}).content | ConvertFrom-Json
  } until ($status.jobStatus -eq 'COMPLETE')
  return $status
}

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
