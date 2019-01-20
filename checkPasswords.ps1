[cmdletBinding()]
param (
    $Path = "./passwords.csv"
)

$ErrorActionPreference = "Stop"

function Get-StringHash {
    param (
        [String]$String,
        $HashName = "SHA1"
    )
    $StringBuilder = New-Object -TypeName "System.Text.StringBuilder"
    [System.Security.Cryptography.CryptoConfig]::CreateFromName($Hashname).ComputeHash([System.Text.Encoding]::UTF8.GetBytes($String)) | ForEach-Object {
        [Void]$StringBuilder.Append($_.ToString("x2"))
    }
    $StringBuilder.ToString().trim()
}

# Enable TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Import the CSV data
$data = Import-CSV -Path $Path

$i = 0
forEach ($datum in ($data | Sort-Object -Property "Name")){
    $i++
    Write-Host "Checking $($datum.name) ($($i) of $($data.count))" -ForegroundColor "Green"
    if ($datum.password){
        $needsChanged = $false
        $hash = Get-StringHash -String $datum.password
        $substring = $hash.substring(0,5)
        $uri = "https://api.pwnedpasswords.com/range/$substring"
        $response = Invoke-RestMethod -Uri $uri -Method "GET" -UseBasicParsing
        # Split the response into lines
        $results = $response.Split("`n")
        Write-Host "Found hash $($results.count) times"
        forEach ($result in $results){
            $foundHash = $hash.substring(0,5) + $result.split(":")[0]
            [int]$found = $result.split(":")[1]
            #Write-Host "Comparing $($hash) to $($foundHash)"
            if ($hash -eq $foundHash){
                Write-Host "Password $($datum.password) has been found $($found) times!" -ForegroundColor "Red"
                $needsChanged = $true
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
        $needsChanged = $null
    }
    $datum | Add-Member -Type "Noteproperty" -Name "NeedsChanged" -Value $needsChanged
}
$data | Where-Object {$_.password -and $_.NeedsChanged} | Select-Object -Property "Name","grouping","NeedsChanged"