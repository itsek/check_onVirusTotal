#Requires -Version 7.0
#Script uses now Virustotal API v3

param(
    $FileToProcess
)

#Enter your API Key here
$APIKey = ""
$FileHash = (Get-FileHash -Algorithm SHA256 -Path $FileToProcess).Hash

Write-Host "File: $FileToProcess"
Write-Host "SHA256 Hash: $FileHash"



function check_filesizeover32mb{
    If ((Get-Item $FileToProcess).length -ge 33554432) {
        return 0
    }
    else {
        return 1
    }
}



function submit_hash {

    param(
        $Hash = $FileHash
    )

    $URL="https://www.virustotal.com/api/v3/files/"
    $Headers = @{
        "x-apikey" = $APIKey
    }
    
    try {
        $Result = Invoke-RestMethod -Uri $URL$Hash -Headers $Headers
    }   
    
    catch [System.Net.Http.HttpRequestException] {
        If ($_.Exception.Response.StatusCode) {
            Write-Host "Hash not found in Virustotal DB"
            Return 2
        }
        else {
            Write-Host "Could not check hash with Virustotal DB, please check manually" -ForegroundColor Yellow
            Read-Host "Press any Key to close"
            Return 1
        }
    }
    $Result.data.attributes
}



function submit_file {

    param(
        $FileToUpload
    )

    $URL="https://www.virustotal.com/api/v3/files"
    $Headers = @{
        "x-apikey" = $APIKey
    }
    $postParams = @{
        file = Get-Item -Path $FileToUpload
    }

    $sizeflag = check_filesizeover32mb
    if ($sizeflag -eq 0) {
        $requestiurl = $URL+"/upload_url"
        $UploadURL = Invoke-RestMethod -Uri $requestiurl -Method GET -Headers $Headers
        $URL = $UploadURL.data
    }

    try {
        $Result = Invoke-RestMethod -Uri $URL -Method Post -Headers $Headers -Form $postParams
    }

    catch {
        Write-Host "Could not uplaod to Virustotal, please check manually" -ForegroundColor Yellow
        Read-Host "Press any Key to close"
        Exit 1
    }
    
    $Result.data.id
    Write-Host "File was submitted succesfully" -ForegroundColor Green
    Write-Host "Analysis ID: $($Result.data.id)"
}



function get_analysis_info {

    param(
        $ID = ""
    )

    $analyseURL="https://www.virustotal.com/api/v3/analyses/"
    $Headers = @{
        "x-apikey" = $APIKey
    }

    try {
        $Result = Invoke-RestMethod -Uri $analyseURL$ID -Headers $Headers
    }    
    catch {
        Write-Host "Seems like the analysis does not exist? this is rather strange, please submit manually!" -ForegroundColor Yellow
        Read-Host "Press any Key to close"
        Exit 1
    }

    while ($Result.data.attributes.status -notlike "completed") {
        Write-Host "Waiting for result, could take a few minutes... please be patient, the result will be fetched as soon its ready"
        Start-Sleep 30
        $Result = Invoke-RestMethod -Uri $analyseURL$ID -Headers $Headers
    }

    $Result.meta.file_info
    $Result.data.attributes.stats
}



$HashResult = submit_hash -Hash $FileHash

    if ($HashResult -eq 2) {
        $HashResult.verbose_msg
        Write-Host "This file(hash) is not in the VirusTotal DB, so no scan results for it" -ForegroundColor Green
        $Answer = Read-Host "Would you like to submit it (WARNING: Uploads file to Google! please think before proceeding! (Y/N)"
            
            If ($Answer -like "Y") {
                $AnalysisID = submit_file -FileToUpload $FileToProcess
                get_analysis_info -ID $AnalysisID
            }
    }

    else {
        Write-Host "Report for the file(hash):" -ForegroundColor Green
        $HashResult
        $HashResult.last_analysis_stats
    }

Read-Host "Press Any Key to close"
