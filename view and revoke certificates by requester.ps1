import-module pspki

Function get-response{
Write-host "Revoke this certificate? (Default is No)"
    $Readhost = Read-Host " ( y / n ) " 
    Switch ($ReadHost) 
     { 
       Y {Write-host "Yes, Revoke certificate"; $response=1} 
       N {Write-Host "No, Keep Certificate"; $response=0} 
       Default {Write-Host "Default, Keep Certificate"; $response=0} 
     }
$response
}

clear-host
Write-host "Requester to search for (DOMAIN\SamAccountName)"
$requester = Read-Host

$certs = get-certificationauthority -computername tus-ica1.aaco.local | `
get-issuedrequest -filter "Request.RequesterName -eq $requester"

Foreach($cert in $certs){
$cert | fl
$yn = get-response

if($yn -eq 1){
revoke-certificate $cert
}
}
