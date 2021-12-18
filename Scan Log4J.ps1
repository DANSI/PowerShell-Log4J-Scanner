#
# Author: DanSi
# Date: 2021-12-18 Version: 1.0.0.0 beta
# 
# Skript: Finds Log4J files and try to find Version of it
#         It can also use "Workaround 3 from https://logging.apache.org/log4j/2.x/security.html
#              --> Otherwise, in any release other than 2.16.0, you may remove the JndiLookup class from the classpath: zip -q -d log4j-core-*.jar org/apache/logging/log4j/core/lookup/JndiLookup.class
#              In order to use this, you must have installed 7z in default location %ProgramFiles%\7-Zip or you put 7za.exe for standalone use in the same directory
#         Thanks to: https://github.com/mergebase/log4j-detector for how to find out the right version
#
#         Example use: Get-ChildItem -Path C:\ -Filter *.jar -File -Recurse | %{ Log4J-Jar -JARfile $_.FullName }
#         Example use: Get-ChildItem -Path C:\ -Filter *.jar -File -Recurse | %{ Log4J-Jar -JARfile $_.FullName -AutoPatch }
#
#         hint: you should also look in these files for log4J: *.jar *.zip *.ear *.war *.aar


Add-Type -Assembly 'System.IO.Compression.FileSystem'

# thanks to https://github.com/mergebase/log4j-detector
$FILE_OLD_LOG4J    = "*log4j/DailyRollingFileAppender.class"
$FILE_LOG4J_1      = "*core/LogEvent.class"
$FILE_LOG4J_2      = "*core/Appender.class"
$FILE_LOG4J_3      = "*core/Filter.class"
$FILE_LOG4J_4      = "*core/Layout.class"
$FILE_LOG4J_5      = "*core/LoggerContext.class"
$FILE_LOG4J_2_10   = "*appender/nosql/NoSqlAppender.class"

$FILE_LOG4J_VULN   = "*JndiLookup.class"
$FILE_LOG4J_SAFE_1 = "*JndiManager.class"

$ACT_FILE_LOG4J_2             = "*core/Appender.class"
$ACT_FILE_LOG4J_3             = "*core/Filter.class"
$ACT_FILE_LOG4J_4             = "*core/Layout.class"
$ACT_FILE_LOG4J_5             = "*core/LoggerContext.class"
$ACT_FILE_LOG4J_2_10          = "*core/appender/nosql/NoSqlAppender.class"
$ACT_FILE_LOG4J_JNDI_LOOKUP   = "*core/lookup/JndiLookup.class"
$ACT_FILE_LOG4J_JNDI_MANAGER  = "*core/net/JndiManager.class"

$IS_LOG4J_SAFE_2_15_0  = [System.Text.Encoding]::Default.GetBytes("Invalid JNDI URI - {}")
$IS_LOG4J_SAFE_2_16_0  = [System.Text.Encoding]::Default.GetBytes("log4j2.enableJndi")
$IS_LOG4J_NSAFE_2_12_2 = [System.Text.Encoding]::Default.GetBytes("Error looking up JNDI resource [{}].")

function Prompt-YesNo($title, $question, $default=0){
    $choices = New-Object Collections.ObjectModel.Collection[Management.Automation.Host.ChoiceDescription]
    $choices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&Yes'))
    $choices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&No'))

    return $Host.UI.PromptForChoice($title, $question, $choices, $default)
}
function ReadText_FromStream([IO.Stream]$stream){
    $reader = New-Object IO.StreamReader($stream)
    return $reader.ReadToEnd()
    $reader.Close()
    $stream.Close()
}
function ReadBytes_FromStream([IO.Stream]$stream){
    $ms = New-Object IO.MemoryStream
    $stream.CopyTo($ms)
    return $ms.ToArray()
}
function FindBytes_InBytes([Byte[]]$source,[Byte[]]$pattern){
    $_done=$false
    0..($source.Length-1) | %{
        if($source[$_] -eq $pattern[0]){
            $skip = $_
            $ok = $true
            0..($pattern.Length-1) | %{
                $s = $skip + $_
                if ($s -gt $source.Length-1){ return $false }
                if ($source[$s] -ne $pattern[$_]){ $ok = $false }
            }
            if ($ok -eq $true){ $_done = $true; return $true}
        }
    }
    if ($_done -eq $false){ return $false }
}

function ZipArchiveEntry_ContainsBytes(){
    [CmdletBinding()]
    param(
        [System.IO.Compression.ZipArchiveEntry]$ZipEntry,
        [Byte[]]$BytePattern
    )
    try{
        Write-Verbose "open $($ZipEntry.FullName)"
        $entryStream = $ZipEntry.Open()
        Write-Verbose "reading Bytes from $($ZipEntry.FullName)"
        $entryContent = ReadBytes_FromStream -stream $entryStream
        Write-Verbose "find Bytes in $($ZipEntry.FullName)"
        $foundPattern = FindBytes_InBytes -source $entryContent -pattern $BytePattern
        if ($foundPattern -eq $true){
            Write-Verbose "found pattern in $($ZipEntry.FullName)"
        } else {
            Write-Verbose "nothing found in $($ZipEntry.FullName)"
        }
        return $foundPattern
    } catch {
        return $null
    }
}
function Log4J-Jar(){
    [CmdletBinding()]
    param(
        [IO.FileInfo]$JARfile,
        [switch]$AutoPatch,
        [switch]$prompt
    )
    $zipFile   = [System.IO.Compression.ZipFile]::OpenRead($JARfile.FullName)

    # new Detector
    $isLog4J_OLD    = $zipFile.Entries | ?{ $_.FullName -like $FILE_OLD_LOG4J }
    $isLog4J_2x     = $zipFile.Entries | ?{ $_.FullName -like $FILE_LOG4J_1 -or
                                            $_.FullName -like $FILE_LOG4J_2 -or
                                            $_.FullName -like $FILE_LOG4J_3 -or
                                            $_.FullName -like $FILE_LOG4J_4 -or
                                            $_.FullName -like $FILE_LOG4J_5 }
    $isLog4J_2_10   = $zipFile.Entries | ?{ $_.FullName -like $FILE_LOG4J_2_10 }
    $hasJndiLookup  = $zipFile.Entries | ?{ $_.FullName -like $FILE_LOG4J_VULN }
    $hasJndiManager = $zipFile.Entries | ?{ $_.FullName -like $FILE_LOG4J_SAFE_1 }
    
    $isLog4J_2_12_2_override = $false
    $isLog4J_2_12_2 = $false
    if ($hasJndiLookup){
        $isLog4J_2_12_2_override = (ZipArchiveEntry_ContainsBytes -ZipEntry $hasJndiLookup -BytePattern $IS_LOG4J_NSAFE_2_12_2)
        $isLog4J_2_12_2 = -not $isLog4J_2_12_2_override
    }

    $isLog4J_2_15_override = $false
    $isLog4J_2_15          = $false
    $isLog4J_2_16          = $false
    if ($hasJndiManager){
        $isLog4J_2_15 = (ZipArchiveEntry_ContainsBytes -ZipEntry $hasJndiManager -BytePattern $IS_LOG4J_SAFE_2_15_0)
        $isLog4J_2_15_override = -not $isLog4J_2_15
    }
    if ($isLog4J_2_15){
        $isLog4J_2_16 = (ZipArchiveEntry_ContainsBytes -ZipEntry $hasJndiManager -BytePattern $IS_LOG4J_SAFE_2_16_0)
        $foundHits    = -not $isLog4J_2_16
    }

    
    $isSafe = $isLog4J_2x -and $hasJndiLookup -and $isLog4J_2_10 -and $hasJndiManager -and ($isLog4J_2_15 -or $isLog4J_2_12_2)
    $isSafe = $isSafe -or $isLog4J_2_16

    $zipFile.Dispose()

    if ($isLog4J_OLD -or $isLog4J_2x){

        # wenn Autopatch und JAR nicht gepatched
        if ($AutoPatch.IsPresent -and -not $isSafe){
            if (-not $prompt.IsPresent -or ((Prompt-YesNo -title "patch Log4J" -question "Do you want to patch $($JARfile.FullName)?") -eq 0)){
                Write-Verbose "File has log4J and is not patched - Autopatching..."
                $done = 7z-Remove-FromArchive -Archive $JARfile.FullName -ArchiveType "-tzip" -internalFilePath $hasJndiLookup.FullName
                Write-Verbose "delete $($hasJndiLookup.FullName) from $($JARFile.Name) was $done"
                return Log4J-Jar -JARfile $JARfile
            } else {
                Write-Verbose "User cancled patching"
            }

        }

        # wenn kein Autopatch
        Write-Verbose "found log4J in $($JARfile.FullName)"
        $Log4J_Version = "unknown"
        if     ($isLog4J_2_16)  { $Log4J_Version = "2.16" }
        elseif ($isLog4J_2_15)  { $Log4J_Version = "2.15" }
        elseif ($isLog4J_2_12_2){ $Log4J_Version = "2.12.2" }
        elseif ($isLog4J_2_10)  { $Log4J_Version = "2.10 - 2.15" }
        elseif ($isLog4J_2x)    { $Log4J_Version = "2.0-beta9 - 2.10" }
        elseif ($isLog4J_OLD)   { $Log4J_Version = "<= 2.0-beta8" }


        return [PSCustomObject]@{
            File = $JARfile.FullName
            Log4J = -not -not $isLog4J_OLD
            Log4J2 = -not -not $isLog4J_2x
            Log4J2_10 = -not -not $isLog4J_2_10
            Log4J2_12_2 = $isLog4J_2_12_2
            Log4J2_15 = $isLog4J_2_15
            Log4J2_16 = $isLog4J_2_16
            Log4J_Version = $Log4J_Version
            JndiLookup = $hasJndiLookup
            JndiManager = $hasJndiManager
            isSafe = $isSafe
        }

    }
}
function 7z-Remove-FromArchive(){
    [CmdletBinding()]
    param(
        [IO.FileInfo]$Archive,
        [string]$ArchiveType="",
        [string]$internalFilePath
    )

    [IO.FileInfo]$7zExe = "$($env:PROGRAMFILES)\7-Zip\7z.exe"
    if (-not $7zExe.Exists){ [IO.FileInfo]$7zExe = "$([environment]::CurrentDirectory)\7za.exe" }
    if (-not $7zExe.Exists){ Write-Warning "cannot find 7z" }
    else {
        $7zArgs = 'd {0} "{1}" "{2}"' -f ($ArchiveType, $Archive,$internalFilePath)
        $p = Start-Process -FilePath $7zExe -ArgumentList $7zArgs -WindowStyle Hidden -Wait -PassThru
        if ($p.ExitCode -eq 2){ Write-Warning "File $($Archive) is maybe in use!"}
        if ($p.ExitCode -eq 0){ return $true } else {
            Write-Verbose "commandline was: $($p.StartInfo.FileName) $($p.StartInfo.Arguments)"
            Write-Verbose "returnlevel was: $($p.ExitCode)"
        }
    }
    return $false
}
