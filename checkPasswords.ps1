[cmdletBinding()]
param (
    $LastPassCsvExportPath = "./passwords.csv"
)
function Get-StringHash([String] $String,$HashName = "SHA1"){ 
    $StringBuilder = New-Object System.Text.StringBuilder 
    [System.Security.Cryptography.HashAlgorithm]::Create($HashName).ComputeHash([System.Text.Encoding]::UTF8.GetBytes($String)) | ForEach-Object {
        [Void]$StringBuilder.Append($_.ToString("x2")) 
    } 
    $StringBuilder.ToString() 
}

# Enable TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Import the CSV data
$data = Import-CSV -Path $LastPassCsvExportPath

$problems = @()
$i = 0
forEach ($datum in $data){
    $i++
    Write-Host "Checking $($datum.name) ($($i) of $($data.count))" -ForegroundColor "Green"
    if ($datum.password){
        $hash = Get-StringHash $datum.password
        $params = @{
            Uri = "https://api.pwnedpasswords.com/range/$($hash.substring(0,5))"
            Method = "GET"
            UseBasicParsing = $true
        }
        $response = Invoke-RestMethod $params
        # Split the response into lines
        $results = $response.Split("`n")
        Write-Host "Found hash $($results.count) times"
        forEach ($result in $results){
            $foundHash = $hash.substring(0,5) + $result.split(":")[0]
            [int]$found = $result.split(":")[1]
            #Write-Host "Comparing $($hash) to $($foundHash)"
            if ($hash -eq $foundHash){
                Write-Host "Password $($datum.password) has been found $($found) times!" -ForegroundColor "Red"
                $problems += "Change password on $($datum.name) from $($datum.password)"
                break
            }
            else {
                # Password was not found
            }
        }
        # The API is rate limited, so ensure that we're not going to get locked-out
        Start-Sleep -Milliseconds 1500
    }
    else {
        Write-Host "No password defined on this object"
    }
}
$problems