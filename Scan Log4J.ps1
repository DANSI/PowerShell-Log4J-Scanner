#
# Author: DanSi
# Date: 2021-12-20 Version: 1.1.0.1 beta
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
$Log4J_JndiManager= "^org/apache/logging/log4j/core/net/JndiManager.class"   # JndiManager.class
$Log4J_LoggerClass= "*/Logger.class"                                         # Logger.class

# latest SAFE version
$Log4J_SAFE_Hashes = @(
                            #@{h="??????????????????????????????????????????????????????????????????????????????????????????????????" ;v="2.12.4"    }, # latest SAFE Version for Java 7
                            @{h="8AF5B1FCE5CF9684375ACC3B298199B4-719B34335646F58D0CA2A9B5CC7712A3-3C3A43AF0930A658716B870E66DB1569" ;v="2.17.1"    }  # latest SAFE Version
                     )

# Hash Version combinations from JndiLookup.class and JndiManager.class
$Log4J_Version_Hashes = @(
                            @{h="BF2352B5948C97CFB999D283100EDF3D--"                                                                 ;v="1.2.9"     },
                            @{h="3FDFE3A60814356965121D4665A4DB94--"                                                                 ;v="1.2.11"    },
                            @{h="E5F375698535B63074CCD328937C80D8--"                                                                 ;v="1.2.12"    },
                            @{h="A7F58C4D565C0AEEDB83CFD6DDFBB136--"                                                                 ;v="1.3-alpha7"},
                            @{h="D3B8F9B48948DDE44D68A7C712C0B747--"                                                                 ;v="1.2.13"    },
                            @{h="6AE6FC8BF1398FDF615ABC6DF02C884E--"                                                                 ;v="1.3-alpha8"},
                            @{h="D3B8F9B48948DDE44D68A7C712C0B747--"                                                                 ;v="1.2.14"    },
                            @{h="A26BE8B0712743831816777A73F5CA1F--"                                                                 ;v="1.2.15"    },
                            @{h="370945D3C458D3826294EFF5EA0A10CB--"                                                                 ;v="1.2.16"    },
                            @{h="D09731A6DA1DE7E0969F5FE070D6AD7E--"                                                                 ;v="1.2.17"    },
                            @{h="68A14EC3F9AA9B9F97DBCC4964577ADB--"                                                                 ;v="2.0-alpha1"},
                            @{h="68A14EC3F9AA9B9F97DBCC4964577ADB--"                                                                 ;v="2.0-alpha2"},
                            @{h="C71F5A1A11D92E365368A6C0D4C26645--"                                                                 ;v="2.0-beta1" },
                            @{h="D98CACF9E93F6F56FBEDAC93CDE5EEBA--"                                                                 ;v="2.0-beta2" },
                            @{h="5D03C5D9BD4AAD857B4E8504837AF21D--"                                                                 ;v="2.0-beta3" },
                            @{h="BD7FF609C3D7227124BAE6B1CD6A7862--"                                                                 ;v="2.0-beta4" },
                            @{h="A4D21FD78AD33B4DC0E15F01BD5231E5--"                                                                 ;v="2.0-beta5" },
                            @{h="39926B25F7F452F5DAB9C79A0A0B2D71--"                                                                 ;v="2.0-beta6" },
                            @{h="39926B25F7F452F5DAB9C79A0A0B2D71--"                                                                 ;v="2.0-beta8" },
                            @{h="941648ACE2BB9AECED97B2463CF5AACE-662118846C452C4973ECA1057859AD61-"                                 ;v="2.0-beta9" },
                            @{h="F2E00268D425F7BFF247EA521B29BCCC-1DAF21D95A208CFCE994704824F46FAE-"                                 ;v="2.0"       },
                            @{h="F2E00268D425F7BFF247EA521B29BCCC-62C82AD7C1EC273A683DE928C93ABBE9-"                                 ;v="2.0"       },
                            @{h="F2E00268D425F7BFF247EA521B29BCCC-2365C12B4A7C5FA5D7903DD90CA9E463-"                                 ;v="2.0.1"     },
                            @{h="55139012C8B68C26C1E9BEE4160CE423-5C727238E74FFAC28315C36DF27EF7CC-"                                 ;v="2.0.2"     },
                            @{h="994231C0169FCA44859D44EE9CD0A11E-8EDEDBB1646C1A4DD6CDB93D9A01F43C-6B15F42C333AC39ABACFEEEB18852A44" ;v="2.1"       },
                            @{h="617D9A49203229FDC122F527203A176B-8EDEDBB1646C1A4DD6CDB93D9A01F43C-6B15F42C333AC39ABACFEEEB18852A44" ;v="2.2"       },
                            @{h="AE6627617D1AC8B2F9FCB9688AA9817E-8EDEDBB1646C1A4DD6CDB93D9A01F43C-6B15F42C333AC39ABACFEEEB18852A44" ;v="2.3"       },
                            @{h="0376B2957060008EB4C979AAB677811A-8D28B7BDF91EE2F18224CA0C17EE9442-2128ED66F0A5DBC8B5A81EC2376DFEA0" ;v="2.3.1"     },
                            #@{h="??????????????????????????????????????????????????????????????????????????????????????????????????" ;v="2.3.2"     }, # fix for CVE-2021-44832

                            @{h="C9BD7F62BF269D6E89806D2F52144842-DA195A29E34E02E9E4C6663CE0B8F243-8B2260B1CCE64144F6310876F94B1638" ;v="2.4"       },
                            @{h="B669D01F8ACD38F3C1DA286DCE55E251-DA195A29E34E02E9E4C6663CE0B8F243-8B2260B1CCE64144F6310876F94B1638" ;v="2.4.1"     },
                            @{h="EE293E766DEF37553600803C266F5E9E-DA195A29E34E02E9E4C6663CE0B8F243-8B2260B1CCE64144F6310876F94B1638" ;v="2.5"       },
                            @{h="22E5AED68D2B75012905CB40674F7DD5-766BF6B755ADEE673838FDF968C15079-3BD9F41B89CE4FE8CCBF73E43195A5CE" ;v="2.6"       },
                            @{h="22E5AED68D2B75012905CB40674F7DD5-766BF6B755ADEE673838FDF968C15079-3BD9F41B89CE4FE8CCBF73E43195A5CE" ;v="2.6.1"     },
                            @{h="22E5AED68D2B75012905CB40674F7DD5-766BF6B755ADEE673838FDF968C15079-3BD9F41B89CE4FE8CCBF73E43195A5CE" ;v="2.6.2"     },
                            @{h="22E5AED68D2B75012905CB40674F7DD5-4618C4BEA52A4E2E2693B7D91B019C71-415C13E7C8505FB056D540EAC29B72FA" ;v="2.7"       },
                            @{h="22E5AED68D2B75012905CB40674F7DD5-FE963DEFC63D2DF86D3D4E2F160939AB-415C13E7C8505FB056D540EAC29B72FA" ;v="2.8"       },
                            @{h="22E5AED68D2B75012905CB40674F7DD5-FE963DEFC63D2DF86D3D4E2F160939AB-415C13E7C8505FB056D540EAC29B72FA" ;v="2.8.1"     },
                            @{h="7156590920AEF6FA871B602B13B8D8F4-641FD7AE76E95B35F02C55FFBF430E6B-A193703904A3F18FB3C90A877EB5C8A7" ;v="2.8.2"     },
                            @{h="22E5AED68D2B75012905CB40674F7DD5-88568653545359ACE753F19A72B18208-04FDD701809D17465C17C7E603B1B202" ;v="2.9.0"     },
                            @{h="22E5AED68D2B75012905CB40674F7DD5-88568653545359ACE753F19A72B18208-04FDD701809D17465C17C7E603B1B202" ;v="2.9.1"     },
                            @{h="22E5AED68D2B75012905CB40674F7DD5-88568653545359ACE753F19A72B18208-04FDD701809D17465C17C7E603B1B202" ;v="2.10.0"    },
                            @{h="22E5AED68D2B75012905CB40674F7DD5-88568653545359ACE753F19A72B18208-04FDD701809D17465C17C7E603B1B202" ;v="2.11.0"    },
                            @{h="22E5AED68D2B75012905CB40674F7DD5-88568653545359ACE753F19A72B18208-04FDD701809D17465C17C7E603B1B202" ;v="2.11.1"    },
                            @{h="22E5AED68D2B75012905CB40674F7DD5-88568653545359ACE753F19A72B18208-04FDD701809D17465C17C7E603B1B202" ;v="2.11.2"    },
                            @{h="7156590920AEF6FA871B602B13B8D8F4-4CB3A0271F77C02FD2DE3144A729AB70-5824711D6C68162EB535CC4DBF7485D3" ;v="2.12.0"    },
                            @{h="BB3CB995A7BFADB536D2B491BAF4F9C4-4CB3A0271F77C02FD2DE3144A729AB70-5824711D6C68162EB535CC4DBF7485D3" ;v="2.12.1"    },
                            @{h="BB3CB995A7BFADB536D2B491BAF4F9C4-DDF868BC458A7732EC3E63673A331D04-102CAC5B7726457244AF1F44E54FF468" ;v="2.12.2"    }, #fixed CVE-2021-(44228, 45046) for Java 7
                            @{h="BB3CB995A7BFADB536D2B491BAF4F9C4-F54D88847EBCF0E2B7C7BFE03B91B69A-5D058C91E71038ED3BA66F29A071994C" ;v="2.12.3"    }, #fixed CVE-2021-45105          for Java 7
                            #@{h="??????????????????????????????????????????????????????????????????????????????????????????????????" ;v="2.12.4"    }, #fixed CVE-2021-44832          for Java 7

                            @{h="1AC815D89B2D897441B6C62C3982C044-7B2CF8F2E9D85014884ADD490878A600-21F055B62C15453F0D7970A9D994CAB7" ;v="2.13.0"    },
                            @{h="1AC815D89B2D897441B6C62C3982C044-7B2CF8F2E9D85014884ADD490878A600-21F055B62C15453F0D7970A9D994CAB7" ;v="2.13.1"    },
                            @{h="1AC815D89B2D897441B6C62C3982C044-7B2CF8F2E9D85014884ADD490878A600-21F055B62C15453F0D7970A9D994CAB7" ;v="2.13.2"    },
                            @{h="1AC815D89B2D897441B6C62C3982C044-7B2CF8F2E9D85014884ADD490878A600-21F055B62C15453F0D7970A9D994CAB7" ;v="2.13.3"    },
                            @{h="8AF5B1FCE5CF9684375ACC3B298199B4-737B430FAC6CAEF7C485C9C47F0F9104-F1D630C48928096A484E4B95CCB162A0" ;v="2.14.0"    },
                            @{h="8AF5B1FCE5CF9684375ACC3B298199B4-737B430FAC6CAEF7C485C9C47F0F9104-F1D630C48928096A484E4B95CCB162A0" ;v="2.14.1"    },
                            @{h="8AF5B1FCE5CF9684375ACC3B298199B4-737B430FAC6CAEF7C485C9C47F0F9104-5D253E53FA993E122FF012221AA49EC3" ;v="2.15.0"    }, #fixed CVE-2021-44228
                            @{h="8AF5B1FCE5CF9684375ACC3B298199B4-737B430FAC6CAEF7C485C9C47F0F9104-BA1CF8F81E7B31C709768561BA8AB558" ;v="2.16.0"    }, #fixed CVE-2021-45046
                            @{h="8AF5B1FCE5CF9684375ACC3B298199B4-719B34335646F58D0CA2A9B5CC7712A3-3DC5CF97546007BE53B2F3D44028FA58" ;v="2.17.0"    }  #fixed CVE-2021-45105
                            @{h="8AF5B1FCE5CF9684375ACC3B298199B4-719B34335646F58D0CA2A9B5CC7712A3-3C3A43AF0930A658716B870E66DB1569" ;v="2.17.1"    }  #fixed CVE-2021-44832

                         )

$Log4J_CVE_2021_44228__CVE_2021_45046 = @(
                            @{h="941648ACE2BB9AECED97B2463CF5AACE-662118846C452C4973ECA1057859AD61-"                                 ;v="2.0-beta9" },
                            @{h="F2E00268D425F7BFF247EA521B29BCCC-1DAF21D95A208CFCE994704824F46FAE-"                                 ;v="2.0"       },
                            @{h="F2E00268D425F7BFF247EA521B29BCCC-62C82AD7C1EC273A683DE928C93ABBE9-"                                 ;v="2.0"       },
                            @{h="F2E00268D425F7BFF247EA521B29BCCC-2365C12B4A7C5FA5D7903DD90CA9E463-"                                 ;v="2.0.1"     },
                            @{h="55139012C8B68C26C1E9BEE4160CE423-5C727238E74FFAC28315C36DF27EF7CC-"                                 ;v="2.0.2"     },
                            @{h="994231C0169FCA44859D44EE9CD0A11E-8EDEDBB1646C1A4DD6CDB93D9A01F43C-6B15F42C333AC39ABACFEEEB18852A44" ;v="2.1"       },
                            @{h="617D9A49203229FDC122F527203A176B-8EDEDBB1646C1A4DD6CDB93D9A01F43C-6B15F42C333AC39ABACFEEEB18852A44" ;v="2.2"       },
                            @{h="AE6627617D1AC8B2F9FCB9688AA9817E-8EDEDBB1646C1A4DD6CDB93D9A01F43C-6B15F42C333AC39ABACFEEEB18852A44" ;v="2.3"       },
                            @{h="C9BD7F62BF269D6E89806D2F52144842-DA195A29E34E02E9E4C6663CE0B8F243-8B2260B1CCE64144F6310876F94B1638" ;v="2.4"       },
                            @{h="B669D01F8ACD38F3C1DA286DCE55E251-DA195A29E34E02E9E4C6663CE0B8F243-8B2260B1CCE64144F6310876F94B1638" ;v="2.4.1"     },
                            @{h="EE293E766DEF37553600803C266F5E9E-DA195A29E34E02E9E4C6663CE0B8F243-8B2260B1CCE64144F6310876F94B1638" ;v="2.5"       },
                            @{h="22E5AED68D2B75012905CB40674F7DD5-766BF6B755ADEE673838FDF968C15079-3BD9F41B89CE4FE8CCBF73E43195A5CE" ;v="2.6"       },
                            @{h="22E5AED68D2B75012905CB40674F7DD5-766BF6B755ADEE673838FDF968C15079-3BD9F41B89CE4FE8CCBF73E43195A5CE" ;v="2.6.1"     },
                            @{h="22E5AED68D2B75012905CB40674F7DD5-766BF6B755ADEE673838FDF968C15079-3BD9F41B89CE4FE8CCBF73E43195A5CE" ;v="2.6.2"     },
                            @{h="22E5AED68D2B75012905CB40674F7DD5-4618C4BEA52A4E2E2693B7D91B019C71-415C13E7C8505FB056D540EAC29B72FA" ;v="2.7"       },
                            @{h="22E5AED68D2B75012905CB40674F7DD5-FE963DEFC63D2DF86D3D4E2F160939AB-415C13E7C8505FB056D540EAC29B72FA" ;v="2.8"       },
                            @{h="22E5AED68D2B75012905CB40674F7DD5-FE963DEFC63D2DF86D3D4E2F160939AB-415C13E7C8505FB056D540EAC29B72FA" ;v="2.8.1"     },
                            @{h="7156590920AEF6FA871B602B13B8D8F4-641FD7AE76E95B35F02C55FFBF430E6B-A193703904A3F18FB3C90A877EB5C8A7" ;v="2.8.2"     },
                            @{h="22E5AED68D2B75012905CB40674F7DD5-88568653545359ACE753F19A72B18208-04FDD701809D17465C17C7E603B1B202" ;v="2.9.0"     },
                            @{h="22E5AED68D2B75012905CB40674F7DD5-88568653545359ACE753F19A72B18208-04FDD701809D17465C17C7E603B1B202" ;v="2.9.1"     },
                            @{h="22E5AED68D2B75012905CB40674F7DD5-88568653545359ACE753F19A72B18208-04FDD701809D17465C17C7E603B1B202" ;v="2.10.0"    },
                            @{h="22E5AED68D2B75012905CB40674F7DD5-88568653545359ACE753F19A72B18208-04FDD701809D17465C17C7E603B1B202" ;v="2.11.0"    },
                            @{h="22E5AED68D2B75012905CB40674F7DD5-88568653545359ACE753F19A72B18208-04FDD701809D17465C17C7E603B1B202" ;v="2.11.1"    },
                            @{h="22E5AED68D2B75012905CB40674F7DD5-88568653545359ACE753F19A72B18208-04FDD701809D17465C17C7E603B1B202" ;v="2.11.2"    },
                            @{h="7156590920AEF6FA871B602B13B8D8F4-4CB3A0271F77C02FD2DE3144A729AB70-5824711D6C68162EB535CC4DBF7485D3" ;v="2.12.0"    },
                            @{h="BB3CB995A7BFADB536D2B491BAF4F9C4-4CB3A0271F77C02FD2DE3144A729AB70-5824711D6C68162EB535CC4DBF7485D3" ;v="2.12.1"    },
                            @{h="1AC815D89B2D897441B6C62C3982C044-7B2CF8F2E9D85014884ADD490878A600-21F055B62C15453F0D7970A9D994CAB7" ;v="2.13.0"    },
                            @{h="1AC815D89B2D897441B6C62C3982C044-7B2CF8F2E9D85014884ADD490878A600-21F055B62C15453F0D7970A9D994CAB7" ;v="2.13.1"    },
                            @{h="1AC815D89B2D897441B6C62C3982C044-7B2CF8F2E9D85014884ADD490878A600-21F055B62C15453F0D7970A9D994CAB7" ;v="2.13.2"    },
                            @{h="1AC815D89B2D897441B6C62C3982C044-7B2CF8F2E9D85014884ADD490878A600-21F055B62C15453F0D7970A9D994CAB7" ;v="2.13.3"    },
                            @{h="8AF5B1FCE5CF9684375ACC3B298199B4-737B430FAC6CAEF7C485C9C47F0F9104-F1D630C48928096A484E4B95CCB162A0" ;v="2.14.0"    },
                            @{h="8AF5B1FCE5CF9684375ACC3B298199B4-737B430FAC6CAEF7C485C9C47F0F9104-F1D630C48928096A484E4B95CCB162A0" ;v="2.14.1"    },
                            @{h="8AF5B1FCE5CF9684375ACC3B298199B4-737B430FAC6CAEF7C485C9C47F0F9104-5D253E53FA993E122FF012221AA49EC3" ;v="2.15.0"    } #fixed CVE-2021-44228
                            
                         )

$Log4J_CVE_2021_45105 = @(
                            @{h="68A14EC3F9AA9B9F97DBCC4964577ADB--"                                                                 ;v="2.0-alpha1"},
                            @{h="68A14EC3F9AA9B9F97DBCC4964577ADB--"                                                                 ;v="2.0-alpha2"},
                            @{h="C71F5A1A11D92E365368A6C0D4C26645--"                                                                 ;v="2.0-beta1" },
                            @{h="D98CACF9E93F6F56FBEDAC93CDE5EEBA--"                                                                 ;v="2.0-beta2" },
                            @{h="5D03C5D9BD4AAD857B4E8504837AF21D--"                                                                 ;v="2.0-beta3" },
                            @{h="BD7FF609C3D7227124BAE6B1CD6A7862--"                                                                 ;v="2.0-beta4" },
                            @{h="A4D21FD78AD33B4DC0E15F01BD5231E5--"                                                                 ;v="2.0-beta5" },
                            @{h="39926B25F7F452F5DAB9C79A0A0B2D71--"                                                                 ;v="2.0-beta6" },
                            @{h="39926B25F7F452F5DAB9C79A0A0B2D71--"                                                                 ;v="2.0-beta8" },
                            @{h="941648ACE2BB9AECED97B2463CF5AACE-662118846C452C4973ECA1057859AD61-"                                 ;v="2.0-beta9" },
                            @{h="F2E00268D425F7BFF247EA521B29BCCC-1DAF21D95A208CFCE994704824F46FAE-"                                 ;v="2.0"       },
                            @{h="F2E00268D425F7BFF247EA521B29BCCC-62C82AD7C1EC273A683DE928C93ABBE9-"                                 ;v="2.0"       },
                            @{h="F2E00268D425F7BFF247EA521B29BCCC-2365C12B4A7C5FA5D7903DD90CA9E463-"                                 ;v="2.0.1"     },
                            @{h="55139012C8B68C26C1E9BEE4160CE423-5C727238E74FFAC28315C36DF27EF7CC-"                                 ;v="2.0.2"     },
                            @{h="994231C0169FCA44859D44EE9CD0A11E-8EDEDBB1646C1A4DD6CDB93D9A01F43C-6B15F42C333AC39ABACFEEEB18852A44" ;v="2.1"       },
                            @{h="617D9A49203229FDC122F527203A176B-8EDEDBB1646C1A4DD6CDB93D9A01F43C-6B15F42C333AC39ABACFEEEB18852A44" ;v="2.2"       },
                            @{h="AE6627617D1AC8B2F9FCB9688AA9817E-8EDEDBB1646C1A4DD6CDB93D9A01F43C-6B15F42C333AC39ABACFEEEB18852A44" ;v="2.3"       },
                            @{h="C9BD7F62BF269D6E89806D2F52144842-DA195A29E34E02E9E4C6663CE0B8F243-8B2260B1CCE64144F6310876F94B1638" ;v="2.4"       },
                            @{h="B669D01F8ACD38F3C1DA286DCE55E251-DA195A29E34E02E9E4C6663CE0B8F243-8B2260B1CCE64144F6310876F94B1638" ;v="2.4.1"     },
                            @{h="EE293E766DEF37553600803C266F5E9E-DA195A29E34E02E9E4C6663CE0B8F243-8B2260B1CCE64144F6310876F94B1638" ;v="2.5"       },
                            @{h="22E5AED68D2B75012905CB40674F7DD5-766BF6B755ADEE673838FDF968C15079-3BD9F41B89CE4FE8CCBF73E43195A5CE" ;v="2.6"       },
                            @{h="22E5AED68D2B75012905CB40674F7DD5-766BF6B755ADEE673838FDF968C15079-3BD9F41B89CE4FE8CCBF73E43195A5CE" ;v="2.6.1"     },
                            @{h="22E5AED68D2B75012905CB40674F7DD5-766BF6B755ADEE673838FDF968C15079-3BD9F41B89CE4FE8CCBF73E43195A5CE" ;v="2.6.2"     },
                            @{h="22E5AED68D2B75012905CB40674F7DD5-4618C4BEA52A4E2E2693B7D91B019C71-415C13E7C8505FB056D540EAC29B72FA" ;v="2.7"       },
                            @{h="22E5AED68D2B75012905CB40674F7DD5-FE963DEFC63D2DF86D3D4E2F160939AB-415C13E7C8505FB056D540EAC29B72FA" ;v="2.8"       },
                            @{h="22E5AED68D2B75012905CB40674F7DD5-FE963DEFC63D2DF86D3D4E2F160939AB-415C13E7C8505FB056D540EAC29B72FA" ;v="2.8.1"     },
                            @{h="7156590920AEF6FA871B602B13B8D8F4-641FD7AE76E95B35F02C55FFBF430E6B-A193703904A3F18FB3C90A877EB5C8A7" ;v="2.8.2"     },
                            @{h="22E5AED68D2B75012905CB40674F7DD5-88568653545359ACE753F19A72B18208-04FDD701809D17465C17C7E603B1B202" ;v="2.9.0"     },
                            @{h="22E5AED68D2B75012905CB40674F7DD5-88568653545359ACE753F19A72B18208-04FDD701809D17465C17C7E603B1B202" ;v="2.9.1"     },
                            @{h="22E5AED68D2B75012905CB40674F7DD5-88568653545359ACE753F19A72B18208-04FDD701809D17465C17C7E603B1B202" ;v="2.10.0"    },
                            @{h="22E5AED68D2B75012905CB40674F7DD5-88568653545359ACE753F19A72B18208-04FDD701809D17465C17C7E603B1B202" ;v="2.11.0"    },
                            @{h="22E5AED68D2B75012905CB40674F7DD5-88568653545359ACE753F19A72B18208-04FDD701809D17465C17C7E603B1B202" ;v="2.11.1"    },
                            @{h="22E5AED68D2B75012905CB40674F7DD5-88568653545359ACE753F19A72B18208-04FDD701809D17465C17C7E603B1B202" ;v="2.11.2"    },
                            @{h="7156590920AEF6FA871B602B13B8D8F4-4CB3A0271F77C02FD2DE3144A729AB70-5824711D6C68162EB535CC4DBF7485D3" ;v="2.12.0"    },
                            @{h="BB3CB995A7BFADB536D2B491BAF4F9C4-4CB3A0271F77C02FD2DE3144A729AB70-5824711D6C68162EB535CC4DBF7485D3" ;v="2.12.1"    },
                            @{h="BB3CB995A7BFADB536D2B491BAF4F9C4-DDF868BC458A7732EC3E63673A331D04-102CAC5B7726457244AF1F44E54FF468" ;v="2.12.2"    },  #fixed CVE-2021-(44228, 45046) for Java 7
                            @{h="1AC815D89B2D897441B6C62C3982C044-7B2CF8F2E9D85014884ADD490878A600-21F055B62C15453F0D7970A9D994CAB7" ;v="2.13.0"    },
                            @{h="1AC815D89B2D897441B6C62C3982C044-7B2CF8F2E9D85014884ADD490878A600-21F055B62C15453F0D7970A9D994CAB7" ;v="2.13.1"    },
                            @{h="1AC815D89B2D897441B6C62C3982C044-7B2CF8F2E9D85014884ADD490878A600-21F055B62C15453F0D7970A9D994CAB7" ;v="2.13.2"    },
                            @{h="1AC815D89B2D897441B6C62C3982C044-7B2CF8F2E9D85014884ADD490878A600-21F055B62C15453F0D7970A9D994CAB7" ;v="2.13.3"    },
                            @{h="8AF5B1FCE5CF9684375ACC3B298199B4-737B430FAC6CAEF7C485C9C47F0F9104-F1D630C48928096A484E4B95CCB162A0" ;v="2.14.0"    },
                            @{h="8AF5B1FCE5CF9684375ACC3B298199B4-737B430FAC6CAEF7C485C9C47F0F9104-F1D630C48928096A484E4B95CCB162A0" ;v="2.14.1"    },
                            @{h="8AF5B1FCE5CF9684375ACC3B298199B4-737B430FAC6CAEF7C485C9C47F0F9104-5D253E53FA993E122FF012221AA49EC3" ;v="2.15.0"    }, #fixed CVE-2021-44228
                            @{h="8AF5B1FCE5CF9684375ACC3B298199B4-737B430FAC6CAEF7C485C9C47F0F9104-BA1CF8F81E7B31C709768561BA8AB558" ;v="2.16.0"    }  #fixed CVE-2021-45046
                         )


function Get-Log4JVersion_FromHashCombination($HashTable,$HashPattern){
    $all_possible_versions = ($HashTable | ?{ $_.h -like $HashPattern } | %{ $_.v }) #-join ", "
    if ($all_possible_versions.count -gt 1){ return "$($all_possible_versions[0]) - $($all_possible_versions[-1])" }
    else                                   { return $all_possible_versions }
}
function Get-HashCombination-FromJndi-Hashes($LoggerHash, $JndiLookupHash,$JndiManagerHash){
    if (-not $LoggerHash){ $LoggerHash = "*" }
    return $LoggerHash, $JndiLookupHash,$JndiManagerHash -join "-"
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
    $hasloggerClass = $zipFile.Entries | ?{ $_.FullName -like  $Log4J_LoggerClass }
    if ($hasloggerClass -and $hasloggerClass.Count -gt 1){ $hasloggerClass=$null; Write-Warning "more then one Logger.class found!" }
    
    if ($hasLog4J){

        $hasJndiLookup  = $zipFile.Entries | ?{ $_.FullName -match $Log4J_JndiLookup  } | Sort-Object LastWriteTime | Select-Object -First 1 # if more then one file, use oldest
        $hasJndiManager = $zipFile.Entries | ?{ $_.FullName -match $Log4J_JndiManager } | Sort-Object LastWriteTime | Select-Object -First 1 # if more then one file, use oldest

        $JndiLookupHash  = $null
        $JndiManagerHash = $null
        $loggerClassHash = $null

        if ($hasJndiLookup) { $JndiLookupHash   = GetHash_FromStream $hasJndiLookup.Open()  }
        if ($hasJndiManager){ $JndiManagerHash  = GetHash_FromStream $hasJndiManager.Open() }
        if ($hasloggerClass){ $loggerClassHash  = GetHash_FromStream $hasloggerClass.Open() }
        $JndiHashCombination = Get-HashCombination-FromJndi-Hashes -LoggerHash $loggerClassHash -JndiLookupHash $JndiLookupHash -JndiManagerHash $JndiManagerHash
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
            LoggerClass = $hasloggerClass
            JndiHashCombination = $JndiHashCombination
            CVE_2021_44228 = -not -not $CVE_2021_44228
            CVE_2021_45105 = -not -not $CVE_2021_45105
            isSafe = $isSafe
        }

    } #else { Write-Warning "$($_.FullName)"; break }
    $zipFile.Dispose()
}
