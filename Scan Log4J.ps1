#
# Author: DanSi
# Date: 2021-12-20 Version: 1.1.0.0 beta
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

# global Log4J files in jar
$Log4J_detect     = "^org/(apache/log4j/DailyRollingFileAppender.class|apache/logging/log4j/core/Logger.class)" # global find Log4J
$Log4J_JndiLookup = "^org/apache/logging/log4j/core/lookup/JndiLookup.class" # JndiLookup.class
$Log4J_JndiManager= "^org/apache/logging/log4j/core/net/JndiManager.class"    # JndiManager.class<

# latest SAFE version
$Log4J_SAFE_Hashes = @(
                            @{h="DDF868BC458A7732EC3E63673A331D04-102CAC5B7726457244AF1F44E54FF468" ;v="2.12.2"    }, # latest SAFE version for Java 7 - Log4J 2.12.2
                            @{h="719B34335646F58D0CA2A9B5CC7712A3-3DC5CF97546007BE53B2F3D44028FA58" ;v="2.17.0"    }  # latest SAFE version            - Log4J 2.17.0
                     )

# Hash Version combinations from JndiLookup.class and JndiManager.class
$Log4J_Version_Hashes = @(
                            @{h="-"                                                                 ;v="1.2.9"     },
                            @{h="-"                                                                 ;v="1.2.11"    },
                            @{h="-"                                                                 ;v="1.2.12"    },
                            @{h="-"                                                                 ;v="1.3-alpha7"},
                            @{h="-"                                                                 ;v="1.2.13"    },
                            @{h="-"                                                                 ;v="1.3-alpha8"},
                            @{h="-"                                                                 ;v="1.3-alpha8"},
                            @{h="-"                                                                 ;v="1.2.14"    },
                            @{h="-"                                                                 ;v="1.2.15"    },
                            @{h="-"                                                                 ;v="1.2.16"    },
                            @{h="-"                                                                 ;v="1.2.17"    },
                            @{h="-"                                                                 ;v="2.0-alpha1"},
                            @{h="-"                                                                 ;v="2.0-alpha2"},
                            @{h="-"                                                                 ;v="2.0-beta1" },
                            @{h="-"                                                                 ;v="2.0-beta2" },
                            @{h="-"                                                                 ;v="2.0-beta3" },
                            @{h="-"                                                                 ;v="2.0-beta4" },
                            @{h="-"                                                                 ;v="2.0-beta5" },
                            @{h="-"                                                                 ;v="2.0-beta6" },
                            @{h="-"                                                                 ;v="2.0-beta8" },
                            @{h="662118846C452C4973ECA1057859AD61-"                                 ;v="2.0-beta9" },
                            @{h="1DAF21D95A208CFCE994704824F46FAE-"                                 ;v="2.0"       },
                            @{h="62C82AD7C1EC273A683DE928C93ABBE9-"                                 ;v="2.0"       },
                            @{h="2365C12B4A7C5FA5D7903DD90CA9E463-"                                 ;v="2.0.1"     },
                            @{h="5C727238E74FFAC28315C36DF27EF7CC-"                                 ;v="2.0.2"     },
                            @{h="8EDEDBB1646C1A4DD6CDB93D9A01F43C-6B15F42C333AC39ABACFEEEB18852A44" ;v="2.1"       },
                            @{h="8EDEDBB1646C1A4DD6CDB93D9A01F43C-6B15F42C333AC39ABACFEEEB18852A44" ;v="2.2"       },
                            @{h="8EDEDBB1646C1A4DD6CDB93D9A01F43C-6B15F42C333AC39ABACFEEEB18852A44" ;v="2.3"       },
                            @{h="DA195A29E34E02E9E4C6663CE0B8F243-8B2260B1CCE64144F6310876F94B1638" ;v="2.4"       },
                            @{h="DA195A29E34E02E9E4C6663CE0B8F243-8B2260B1CCE64144F6310876F94B1638" ;v="2.4.1"     },
                            @{h="DA195A29E34E02E9E4C6663CE0B8F243-8B2260B1CCE64144F6310876F94B1638" ;v="2.5"       },
                            @{h="766BF6B755ADEE673838FDF968C15079-3BD9F41B89CE4FE8CCBF73E43195A5CE" ;v="2.6"       },
                            @{h="766BF6B755ADEE673838FDF968C15079-3BD9F41B89CE4FE8CCBF73E43195A5CE" ;v="2.6.1"     },
                            @{h="766BF6B755ADEE673838FDF968C15079-3BD9F41B89CE4FE8CCBF73E43195A5CE" ;v="2.6.2"     },
                            @{h="4618C4BEA52A4E2E2693B7D91B019C71-415C13E7C8505FB056D540EAC29B72FA" ;v="2.7"       },
                            @{h="FE963DEFC63D2DF86D3D4E2F160939AB-415C13E7C8505FB056D540EAC29B72FA" ;v="2.8"       },
                            @{h="FE963DEFC63D2DF86D3D4E2F160939AB-415C13E7C8505FB056D540EAC29B72FA" ;v="2.8.1"     },
                            @{h="641FD7AE76E95B35F02C55FFBF430E6B-A193703904A3F18FB3C90A877EB5C8A7" ;v="2.8.2"     },
                            @{h="88568653545359ACE753F19A72B18208-04FDD701809D17465C17C7E603B1B202" ;v="2.9.0"     },
                            @{h="88568653545359ACE753F19A72B18208-04FDD701809D17465C17C7E603B1B202" ;v="2.9.1"     },
                            @{h="88568653545359ACE753F19A72B18208-04FDD701809D17465C17C7E603B1B202" ;v="2.10.0"    },
                            @{h="88568653545359ACE753F19A72B18208-04FDD701809D17465C17C7E603B1B202" ;v="2.11.0"    },
                            @{h="88568653545359ACE753F19A72B18208-04FDD701809D17465C17C7E603B1B202" ;v="2.11.1"    },
                            @{h="88568653545359ACE753F19A72B18208-04FDD701809D17465C17C7E603B1B202" ;v="2.11.2"    },
                            @{h="4CB3A0271F77C02FD2DE3144A729AB70-5824711D6C68162EB535CC4DBF7485D3" ;v="2.12.0"    },
                            @{h="4CB3A0271F77C02FD2DE3144A729AB70-5824711D6C68162EB535CC4DBF7485D3" ;v="2.12.1"    },
                            @{h="7B2CF8F2E9D85014884ADD490878A600-21F055B62C15453F0D7970A9D994CAB7" ;v="2.13.0"    },
                            @{h="7B2CF8F2E9D85014884ADD490878A600-21F055B62C15453F0D7970A9D994CAB7" ;v="2.13.1"    },
                            @{h="7B2CF8F2E9D85014884ADD490878A600-21F055B62C15453F0D7970A9D994CAB7" ;v="2.13.2"    },
                            @{h="7B2CF8F2E9D85014884ADD490878A600-21F055B62C15453F0D7970A9D994CAB7" ;v="2.13.3"    },
                            @{h="737B430FAC6CAEF7C485C9C47F0F9104-F1D630C48928096A484E4B95CCB162A0" ;v="2.14.0"    },
                            @{h="737B430FAC6CAEF7C485C9C47F0F9104-F1D630C48928096A484E4B95CCB162A0" ;v="2.14.1"    },
                            @{h="737B430FAC6CAEF7C485C9C47F0F9104-5D253E53FA993E122FF012221AA49EC3" ;v="2.15.0"    },
                            @{h="737B430FAC6CAEF7C485C9C47F0F9104-BA1CF8F81E7B31C709768561BA8AB558" ;v="2.16.0"    },

                            @{h="DDF868BC458A7732EC3E63673A331D04-102CAC5B7726457244AF1F44E54FF468" ;v="2.12.2"    }, #fixed CVE-2021-(44228, 45046)        for Java 7
                            @{h="XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX" ;v="2.12.3"    }, #fixed CVE-2021-(44228, 45046, 45105) for Java 7
                            @{h="719B34335646F58D0CA2A9B5CC7712A3-3DC5CF97546007BE53B2F3D44028FA58" ;v="2.17.0"    }, #fixed CVE-2021-(44228, 45046, 45105)
                            
                            @{h="D47E57DE48AC28AF9CD9FCF535781A97-71E7603A1F55254E20419FCD8AFA7AD7" ;v="3.0.0-SNAPSHOT"} # 3.0.0 SNAPSHOT

                         )

$Log4J_CVE_2021_44228__CVE_2021_45046 = @(
                            @{h="662118846C452C4973ECA1057859AD61-"                                 ;v="2.0-beta9" },
                            @{h="1DAF21D95A208CFCE994704824F46FAE-"                                 ;v="2.0"       },
                            @{h="62C82AD7C1EC273A683DE928C93ABBE9-"                                 ;v="2.0"       },
                            @{h="2365C12B4A7C5FA5D7903DD90CA9E463-"                                 ;v="2.0.1"     },
                            @{h="5C727238E74FFAC28315C36DF27EF7CC-"                                 ;v="2.0.2"     },
                            @{h="8EDEDBB1646C1A4DD6CDB93D9A01F43C-6B15F42C333AC39ABACFEEEB18852A44" ;v="2.1"       },
                            @{h="8EDEDBB1646C1A4DD6CDB93D9A01F43C-6B15F42C333AC39ABACFEEEB18852A44" ;v="2.2"       },
                            @{h="8EDEDBB1646C1A4DD6CDB93D9A01F43C-6B15F42C333AC39ABACFEEEB18852A44" ;v="2.3"       },
                            @{h="DA195A29E34E02E9E4C6663CE0B8F243-8B2260B1CCE64144F6310876F94B1638" ;v="2.4"       },
                            @{h="DA195A29E34E02E9E4C6663CE0B8F243-8B2260B1CCE64144F6310876F94B1638" ;v="2.4.1"     },
                            @{h="DA195A29E34E02E9E4C6663CE0B8F243-8B2260B1CCE64144F6310876F94B1638" ;v="2.5"       },
                            @{h="766BF6B755ADEE673838FDF968C15079-3BD9F41B89CE4FE8CCBF73E43195A5CE" ;v="2.6"       },
                            @{h="766BF6B755ADEE673838FDF968C15079-3BD9F41B89CE4FE8CCBF73E43195A5CE" ;v="2.6.1"     },
                            @{h="766BF6B755ADEE673838FDF968C15079-3BD9F41B89CE4FE8CCBF73E43195A5CE" ;v="2.6.2"     },
                            @{h="4618C4BEA52A4E2E2693B7D91B019C71-415C13E7C8505FB056D540EAC29B72FA" ;v="2.7"       },
                            @{h="FE963DEFC63D2DF86D3D4E2F160939AB-415C13E7C8505FB056D540EAC29B72FA" ;v="2.8"       },
                            @{h="FE963DEFC63D2DF86D3D4E2F160939AB-415C13E7C8505FB056D540EAC29B72FA" ;v="2.8.1"     },
                            @{h="641FD7AE76E95B35F02C55FFBF430E6B-A193703904A3F18FB3C90A877EB5C8A7" ;v="2.8.2"     },
                            @{h="88568653545359ACE753F19A72B18208-04FDD701809D17465C17C7E603B1B202" ;v="2.9.0"     },
                            @{h="88568653545359ACE753F19A72B18208-04FDD701809D17465C17C7E603B1B202" ;v="2.9.1"     },
                            @{h="88568653545359ACE753F19A72B18208-04FDD701809D17465C17C7E603B1B202" ;v="2.10.0"    },
                            @{h="88568653545359ACE753F19A72B18208-04FDD701809D17465C17C7E603B1B202" ;v="2.11.0"    },
                            @{h="88568653545359ACE753F19A72B18208-04FDD701809D17465C17C7E603B1B202" ;v="2.11.1"    },
                            @{h="88568653545359ACE753F19A72B18208-04FDD701809D17465C17C7E603B1B202" ;v="2.11.2"    },
                            @{h="4CB3A0271F77C02FD2DE3144A729AB70-5824711D6C68162EB535CC4DBF7485D3" ;v="2.12.0"    },
                            @{h="4CB3A0271F77C02FD2DE3144A729AB70-5824711D6C68162EB535CC4DBF7485D3" ;v="2.12.1"    },
                            @{h="7B2CF8F2E9D85014884ADD490878A600-21F055B62C15453F0D7970A9D994CAB7" ;v="2.13.0"    },
                            @{h="7B2CF8F2E9D85014884ADD490878A600-21F055B62C15453F0D7970A9D994CAB7" ;v="2.13.1"    },
                            @{h="7B2CF8F2E9D85014884ADD490878A600-21F055B62C15453F0D7970A9D994CAB7" ;v="2.13.2"    },
                            @{h="7B2CF8F2E9D85014884ADD490878A600-21F055B62C15453F0D7970A9D994CAB7" ;v="2.13.3"    },
                            @{h="737B430FAC6CAEF7C485C9C47F0F9104-F1D630C48928096A484E4B95CCB162A0" ;v="2.14.0"    },
                            @{h="737B430FAC6CAEF7C485C9C47F0F9104-F1D630C48928096A484E4B95CCB162A0" ;v="2.14.1"    },
                            @{h="737B430FAC6CAEF7C485C9C47F0F9104-5D253E53FA993E122FF012221AA49EC3" ;v="2.15.0"    }
                         )

$Log4J_CVE_2021_45105 = @(
                            @{h="-"                                                                 ;v="2.0-alpha1"},
                            @{h="-"                                                                 ;v="2.0-alpha2"},
                            @{h="-"                                                                 ;v="2.0-beta1" },
                            @{h="-"                                                                 ;v="2.0-beta2" },
                            @{h="-"                                                                 ;v="2.0-beta3" },
                            @{h="-"                                                                 ;v="2.0-beta4" },
                            @{h="-"                                                                 ;v="2.0-beta5" },
                            @{h="-"                                                                 ;v="2.0-beta6" },
                            @{h="-"                                                                 ;v="2.0-beta8" },
                            @{h="662118846C452C4973ECA1057859AD61-"                                 ;v="2.0-beta9" },
                            @{h="1DAF21D95A208CFCE994704824F46FAE-"                                 ;v="2.0"       },
                            @{h="62C82AD7C1EC273A683DE928C93ABBE9-"                                 ;v="2.0"       },
                            @{h="2365C12B4A7C5FA5D7903DD90CA9E463-"                                 ;v="2.0.1"     },
                            @{h="5C727238E74FFAC28315C36DF27EF7CC-"                                 ;v="2.0.2"     },
                            @{h="8EDEDBB1646C1A4DD6CDB93D9A01F43C-6B15F42C333AC39ABACFEEEB18852A44" ;v="2.1"       },
                            @{h="8EDEDBB1646C1A4DD6CDB93D9A01F43C-6B15F42C333AC39ABACFEEEB18852A44" ;v="2.2"       },
                            @{h="8EDEDBB1646C1A4DD6CDB93D9A01F43C-6B15F42C333AC39ABACFEEEB18852A44" ;v="2.3"       },
                            @{h="DA195A29E34E02E9E4C6663CE0B8F243-8B2260B1CCE64144F6310876F94B1638" ;v="2.4"       },
                            @{h="DA195A29E34E02E9E4C6663CE0B8F243-8B2260B1CCE64144F6310876F94B1638" ;v="2.4.1"     },
                            @{h="DA195A29E34E02E9E4C6663CE0B8F243-8B2260B1CCE64144F6310876F94B1638" ;v="2.5"       },
                            @{h="766BF6B755ADEE673838FDF968C15079-3BD9F41B89CE4FE8CCBF73E43195A5CE" ;v="2.6"       },
                            @{h="766BF6B755ADEE673838FDF968C15079-3BD9F41B89CE4FE8CCBF73E43195A5CE" ;v="2.6.1"     },
                            @{h="766BF6B755ADEE673838FDF968C15079-3BD9F41B89CE4FE8CCBF73E43195A5CE" ;v="2.6.2"     },
                            @{h="4618C4BEA52A4E2E2693B7D91B019C71-415C13E7C8505FB056D540EAC29B72FA" ;v="2.7"       },
                            @{h="FE963DEFC63D2DF86D3D4E2F160939AB-415C13E7C8505FB056D540EAC29B72FA" ;v="2.8"       },
                            @{h="FE963DEFC63D2DF86D3D4E2F160939AB-415C13E7C8505FB056D540EAC29B72FA" ;v="2.8.1"     },
                            @{h="641FD7AE76E95B35F02C55FFBF430E6B-A193703904A3F18FB3C90A877EB5C8A7" ;v="2.8.2"     },
                            @{h="88568653545359ACE753F19A72B18208-04FDD701809D17465C17C7E603B1B202" ;v="2.9.0"     },
                            @{h="88568653545359ACE753F19A72B18208-04FDD701809D17465C17C7E603B1B202" ;v="2.9.1"     },
                            @{h="88568653545359ACE753F19A72B18208-04FDD701809D17465C17C7E603B1B202" ;v="2.10.0"    },
                            @{h="88568653545359ACE753F19A72B18208-04FDD701809D17465C17C7E603B1B202" ;v="2.11.0"    },
                            @{h="88568653545359ACE753F19A72B18208-04FDD701809D17465C17C7E603B1B202" ;v="2.11.1"    },
                            @{h="88568653545359ACE753F19A72B18208-04FDD701809D17465C17C7E603B1B202" ;v="2.11.2"    },
                            @{h="4CB3A0271F77C02FD2DE3144A729AB70-5824711D6C68162EB535CC4DBF7485D3" ;v="2.12.0"    },
                            @{h="4CB3A0271F77C02FD2DE3144A729AB70-5824711D6C68162EB535CC4DBF7485D3" ;v="2.12.1"    },
                            @{h="7B2CF8F2E9D85014884ADD490878A600-21F055B62C15453F0D7970A9D994CAB7" ;v="2.13.0"    },
                            @{h="7B2CF8F2E9D85014884ADD490878A600-21F055B62C15453F0D7970A9D994CAB7" ;v="2.13.1"    },
                            @{h="7B2CF8F2E9D85014884ADD490878A600-21F055B62C15453F0D7970A9D994CAB7" ;v="2.13.2"    },
                            @{h="7B2CF8F2E9D85014884ADD490878A600-21F055B62C15453F0D7970A9D994CAB7" ;v="2.13.3"    },
                            @{h="737B430FAC6CAEF7C485C9C47F0F9104-F1D630C48928096A484E4B95CCB162A0" ;v="2.14.0"    },
                            @{h="737B430FAC6CAEF7C485C9C47F0F9104-F1D630C48928096A484E4B95CCB162A0" ;v="2.14.1"    },
                            @{h="737B430FAC6CAEF7C485C9C47F0F9104-5D253E53FA993E122FF012221AA49EC3" ;v="2.15.0"    },
                            @{h="737B430FAC6CAEF7C485C9C47F0F9104-BA1CF8F81E7B31C709768561BA8AB558" ;v="2.16.0"    },
                            @{h="DDF868BC458A7732EC3E63673A331D04-102CAC5B7726457244AF1F44E54FF468" ;v="2.12.2"    }
                         )


function Get-Log4JVersion_FromHashCombination($HashTable,$HashPattern){
    $all_possible_versions = ($HashTable | ?{ $_.h -eq $HashPattern } | %{ $_.v }) #-join ", "
    if ($all_possible_versions.count -gt 1){ return "$($all_possible_versions[0]) - $($all_possible_versions[-1])" }
    else                                   { return $all_possible_versions }
}
function Get-HashCombination-FromJndi-Hashes($JndiLookupHash,$JndiManagerHash){
    return "{0}-{1}" -f ($JndiLookupHash,$JndiManagerHash)
}
                        
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
function GetHash_FromStream([IO.Stream]$stream,[string]$Algorithm="MD5"){
    $fh = Get-FileHash -InputStream $stream -Algorithm $Algorithm
    return $fh.Hash
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
function Log4J-Jar(){
    [CmdletBinding()]
    param(
        [IO.FileInfo]$JARfile,
        [switch]$AutoPatch,
        [switch]$prompt
    )
    $zipFile   = [System.IO.Compression.ZipFile]::OpenRead($JARfile.FullName)

    # Detect Log4J
    $hasLog4J       = $zipFile.Entries | ?{ $_.FullName -match $Log4J_detect }
    
    if ($hasLog4J){

        $hasJndiLookup  = $zipFile.Entries | ?{ $_.FullName -match $Log4J_JndiLookup  }
        $hasJndiManager = $zipFile.Entries | ?{ $_.FullName -match $Log4J_JndiManager }

        $JndiLookupHash  = $null
        $JndiManagerHash = $null
        if ($hasJndiLookup) { $JndiLookupHash   = GetHash_FromStream $hasJndiLookup.Open()  }
        if ($hasJndiManager){ $JndiManagerHash  = GetHash_FromStream $hasJndiManager.Open() }
        $JndiHashCombination = Get-HashCombination-FromJndi-Hashes -JndiLookupHash $JndiLookupHash -JndiManagerHash $JndiManagerHash
        $Log4J_Version = Get-Log4JVersion_FromHashCombination -HashTable $Log4J_Version_Hashes -HashPattern $JndiHashCombination
    
        $isSafe = -not -not (Get-Log4JVersion_FromHashCombination -HashTable $Log4J_SAFE_Hashes -HashPattern $JndiHashCombination)

        $CVE_2021_44228 = Get-Log4JVersion_FromHashCombination -HashTable $Log4J_CVE_2021_44228__CVE_2021_45046 -HashPattern $JndiHashCombination
        $CVE_2021_45105 = Get-Log4JVersion_FromHashCombination -HashTable $Log4J_CVE_2021_45105                 -HashPattern $JndiHashCombination

        # wenn Autopatch und JAR nicht gepatched
        if ($AutoPatch.IsPresent -and -not $isSafe){
            if (-not $prompt.IsPresent -or ((Prompt-YesNo -title "patch Log4J" -question "Do you want to patch $($JARfile.FullName)?") -eq 0)){
                Write-Verbose "File has log4J and is not patched - Autopatching..."
                $done = 7z-Remove-FromArchive -Archive $JARfile.FullName -ArchiveType "-tzip" -internalFilePath $hasJndiLookup.FullName
                Write-Verbose "delete $($hasJndiLookup.FullName) from $($JARFile.Name) was $done"
                return Log4J-Jar -JARfile $JARfile
            } else {
                Write-Verbose "User canceled patching"
            }

        }

        # wenn kein Autopatch
        Write-Verbose "found log4J in $($JARfile.FullName)"
        return [PSCustomObject]@{
            File = $JARfile.FullName
            Log4J_Version = $Log4J_Version
            JndiLookup = $hasJndiLookup
            JndiManager = $hasJndiManager
            JndiHashCombination = $JndiHashCombination
            CVE_2021_44228 = -not -not $CVE_2021_44228
            CVE_2021_45105 = -not -not $CVE_2021_45105
            isSafe = $isSafe
        }

    } #else { Write-Warning "$($_.FullName)"; break }
    $zipFile.Dispose()
}
