
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

  # Paramaters
  $fields = @(
    @{'name' = 'FirstTime'; 'id' = 0},
    @{'name' = 'LastTime'},
    @{'name' = 'UserIDSrc'},
    @{'name' = 'SrcIP'},
    @{'name' = 'Alert.AlertID'},
    @{'name' = 'DSIDSigID'},
    @{'name' = 'DSID'}
  )
  $filters = @(
    @{
      'type' = 'EsmFieldFilter'
      'field' = @{'name' = 'DSID'}
      'operator' = 'NOT_IN'
      'values' = @(
        @{
          'type' = 'EsmBasicValue'
          'value' = '0'
        }
      )
    }
  )
  $timerange = 'CURRENT_YEAR'
  $num = '10'

  # Login
  Login;

  # Initiate Query
  $queryID = qryExecuteDetail $fields $filters $timerange| ConvertFrom-Json | select -ExpandProperty resultID

  # Wait for query to finish on ESM
  do{
    $result = qryGetStatus $queryID
  }
  while (($result | ConvertFrom-Json | select -ExpandProperty percentComplete) -ne 100)

  # Collect Results
  Write-Output (qryGetResults $queryID $num)
}

#################################################################################################
# ESM API IMPLEMENTATION
#################################################################################################

########################### 
# Get Correlated Events (Details)
########################### 

Function qryExecuteDetail($fields, $filters, $timerange)
{
  $params = @{
    'config' = @{
      'timeRange' = $timerange
      'fields' = $fields
      'filters' = $filters
      'limit' = 0
      'order' = @(
        @{
          'direction' = 'DESCENDING'
          'field' = @{'name' = 'LastTime'}
        }
      )
      'includeTotal' = 'False'
    }
  };

  $response = CallEsmApi 'qryExecuteDetail?type=EVENT&reverse=false' $params
  return $response.Content
}

###########################
# Get Query Status
###########################

Function qryGetStatus($resultID)
{
  $params = @{
    'resultID' = $resultID
  }
  $response = CallEsmApi 'qryGetStatus' $params
  return $response.Content
}

###########################
# Get Query Response
###########################

Function qryGetResults($resultID, $num_rows)
{
  $params = @{
    'resultID' = $resultID
  }
  $response = CallEsmApi ('qryGetResults?startPos=0&numRows=' + $num_rows) $params
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
