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

########################### 
# Some Inits
###########################

# IP or FQDN of local ePO
$global:ePOIP = '10.10.10.204'
# ePO Port
$global:ePOPort = '8443'
# ePO Credentials
$global:cred = Get-Credential


########################### 
# Main Function
###########################
Function Main
{
  $response = CallePOApi 'DxlBrokerMgmt.registerIpeDataCmd' @{packageLocation = "C:\temp\somefile.xml"}
  Write-Host $response
}

########################### 
# Call ePO API
###########################
Function CallePOApi ([String]$method, $body)
{
  $url = 'https://' + $global:ePOIP + ":" + $global:ePOPort + '/remote/' + $method

  $response = Invoke-WebRequest $url -Credential $global:cred -Method Post -Body $body
  return $response
}

Main;
