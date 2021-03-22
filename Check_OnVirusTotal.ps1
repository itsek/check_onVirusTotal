#Requires -Version 7.0
#Uploads Hashes and Files to VT for Checks

param(
    $FileToProcess
)

#please enter here your VT API Key, which you will get after Registering: https://support.virustotal.com/hc/en-us/articles/115002088769-Please-give-me-an-API-key
$APIKey = ""
$FileHash = (Get-FileHash -Algorithm SHA1 -Path $FileToProcess).Hash

Write-Host "$FileToProcess"
Write-Host "$FileHash"

#basic VT Accounts can only submit Files up to 32MB in size
function check_filesizelimit {
    If ((Get-Item $FileToProcess).length -ge 33554432) {
        Write-Host "Sorry, public VT API supports only up to 32MB :(" -ForegroundColor Magenta
        Read-Host "Any Key to close..."
        Exit 1
    }
}


function submit_hash {

    param(
        $Hash = $FileHash
    )

    $URL="https://www.virustotal.com/vtapi/v2/file/report"
    $postParams = @{
    apikey=$APIKey
    resource=$Hash
    }
    
    try {
        $Result = Invoke-WebRequest -Uri $URL -Method Post -Body $postParams
    }    
    catch {
        Write-Host "Something went wrong, Could not Check Hash with Virustotal DB, please check manually" -ForegroundColor Yellow
        Read-Host "Press any Key to close"
        Exit 1
    }
    
    $ResultAsJSON = $Result.Content| ConvertFrom-Json
    $ResultAsJSON

}



function submit_file {

    param(
        $FileToUpload
    )

    $URL="https://www.virustotal.com/vtapi/v2/file/scan"
    $postParams = @{
    apikey=$APIKey
    file=Get-Item -Path $FileToUpload
    }

    check_filesizelimit

    try {
        $Result = Invoke-RestMethod -Uri $URL -Method Post -Form $postParams
    }
    catch {
        Write-Host "Something went wrong, Could not Uplaod to Virustotal, please check manually" -ForegroundColor Yellow
        Read-Host "Press any Key to close"
        Exit 1
    }
    $Result
}


$HashResult = submit_hash

    if ($HashResult.response_code -eq 0) {
        $HashResult.verbose_msg
        Write-Host "This File(hash) is not in the VirusTotal Database, so no Scan Results for it" -ForegroundColor Green
        $Answer = Read-Host "Would you like to submmit it (WARNING: Uploads file to Google! please think before proceeding! (Y/N)"
            
            If ($Answer -like "Y") {
                $Submitresult = submit_file -FileToUpload $FileToProcess
                $Submitresult.verbose_msg
                $Hash = $Submitresult.sha1
                
                While ($Submitresult.verbose_msg -match 'queued' ) {
                    Write-Host "Waiting 60 seconds to fetch the Result"
                    Start-Sleep -Seconds 60
                    $Submitresult = submit_hash -Hash $Hash
                    Write-Host $Submitresult
                }
                
                Write-Host "Report for the Submitted File" -ForegroundColor Green
                $Submitresult
                Write-Host "Positives: $($Submitresult.positives)" -ForegroundColor Magenta
            }
    }

    else {
        Write-Host "Report for the File(hash):" -ForegroundColor Green
        $HashResult
        Write-Host "Positives: $($HashResult.positives)" -ForegroundColor Magenta
    }

Read-Host "Press Any Key to close"