POST my_index/wineventlog/
{
          "@timestamp" : 1512728203071,
          "@version" : "1",
          "beat" : {
            "hostname" : "WIN-U1E6SADQQ7G",
            "name" : "WIN-U1E6SADQQ7G",
            "version" : "5.6.3"
          },
          "computer_name" : "WIN-U1E6SADQQ7G",
          "event_data" : {
            "CommandLine" : "7z  a -tzip archive.zip @listfile.txt",
            "CurrentDirectory" : "C:\\Users\\Administrator\\",
            "Hashes" : "SHA1=B0973B9290818A986C4DEF29DA3B9E2FCFAC601E",
            "Image" : "C:\\Program Files\\7-Zip\\7z.exe",
            "IntegrityLevel" : "High",
            "LogonGuid" : "{704248D8-4D8D-5A2A-0000-00202D861900}",
            "LogonId" : "0x19862d",
            "ParentCommandLine" : "\"C:\\Windows\\system32\\cmd.exe\" ",
            "ParentImage" : "C:\\Windows\\System32\\cmd.exe",
            "ParentProcessGuid" : "{704248D8-658E-5A2A-0000-0010BAFF6900}",
            "ParentProcessId" : "1520",
            "ProcessGuid" : "{704248D8-668B-5A2A-0000-0010D0E66E00}",
            "ProcessId" : "3508",
            "TerminalSessionId" : "1",
            "User" : "WIN-U1E6SADQQ7G\\Administrator",
            "UtcTime" : "2017-12-08 10:16:43.069"
          },
          "event_id" : 1,
          "host" : "WIN-U1E6SADQQ7G",
          "level" : "Information",
          "log_name" : "Microsoft-Windows-Sysmon/Operational",
          "message" : "Process Create:\nUtcTime: 2017-12-08 10:16:43.069\nProcessGuid: {704248D8-668B-5A2A-0000-0010D0E66E00}\nProcessId: 3508\nImage: C:\\Program Files\\7-Zip\\7z.exe\nCommandLine: 7z  a -tzip archive.zip @listfile.txt\nCurrentDirectory: C:\\Users\\Administrator\\\nUser: WIN-U1E6SADQQ7G\\Administrator\nLogonGuid: {704248D8-4D8D-5A2A-0000-00202D861900}\nLogonId: 0x19862D\nTerminalSessionId: 1\nIntegrityLevel: High\nHashes: SHA1=B0973B9290818A986C4DEF29DA3B9E2FCFAC601E\nParentProcessGuid: {704248D8-658E-5A2A-0000-0010BAFF6900}\nParentProcessId: 1520\nParentImage: C:\\Windows\\System32\\cmd.exe\nParentCommandLine: \"C:\\Windows\\system32\\cmd.exe\" ",
          "opcode" : "Info",
          "process_id" : 1984,
          "provider_guid" : "{5770385F-C22A-43E0-BF4C-06F5698FFBD9}",
          "record_number" : "5360",
          "source_name" : "Microsoft-Windows-Sysmon",
          "task" : "Process Create (rule: ProcessCreate)",
          "thread_id" : 2576,
          "type" : "wineventlog",
          "user" : {
            "domain" : "NT AUTHORITY",
            "identifier" : "S-1-5-18",
            "name" : "SYSTEM",
            "type" : "User"
          },
          "version" : 5,
          "Technique" : [
            "Masquerading"
          ],
          "Tactics" : [
            "Defense Evasion"
          ]
        }







PUT analytics
{
    "mappings": {
      "wineventlog": {
        "properties": {
          "@timestamp": {
            "type": "date"
          },
          "@version": {
            "type": "text",
            "fields": {
              "keyword": {
                "type": "keyword",
                "ignore_above": 256
              }
            }
          },
          "activity_id": {
            "type": "text",
            "fields": {
              "keyword": {
                "type": "keyword",
                "ignore_above": 256
              }
            }
          },
          "beat": {
            "properties": {
              "hostname": {
                "type": "text",
                "fields": {
                  "keyword": {
                    "type": "keyword",
                    "ignore_above": 256
                  }
                }
              },
              "name": {
                "type": "text",
                "fields": {
                  "keyword": {
                    "type": "keyword",
                    "ignore_above": 256
                  }
                }
              },
              "version": {
                "type": "text",
                "fields": {
                  "keyword": {
                    "type": "keyword",
                    "ignore_above": 256
                  }
                }
              }
            }
          },
          "computer_name": {
            "type": "text",
            "fields": {
              "keyword": {
                "type": "keyword",
                "ignore_above": 256
              }
            }
          },
          "event_data": {
            "properties": {
              "CommandLine": {
                "type": "text",
                "fields": {
                  "keyword": {
                    "type": "keyword",
                    "ignore_above": 256
                  }
                }
              },
              "CreationUtcTime": {
                "type": "text",
                "fields": {
                  "keyword": {
                    "type": "keyword",
                    "ignore_above": 256
                  }
                }
              },
              "CurrentDirectory": {
                "type": "text",
                "fields": {
                  "keyword": {
                    "type": "keyword",
                    "ignore_above": 256
                  }
                }
              },
              "DestinationHostname": {
                "type": "text",
                "fields": {
                  "keyword": {
                    "type": "keyword",
                    "ignore_above": 256
                  }
                }
              },
              "DestinationIp": {
                "type": "text",
                "fields": {
                  "keyword": {
                    "type": "keyword",
                    "ignore_above": 256
                  }
                }
              },
              "DestinationIsIpv6": {
                "type": "text",
                "fields": {
                  "keyword": {
                    "type": "keyword",
                    "ignore_above": 256
                  }
                }
              },
              "DestinationPort": {
                "type": "text",
                "fields": {
                  "keyword": {
                    "type": "keyword",
                    "ignore_above": 256
                  }
                }
              },
              "DestinationPortName": {
                "type": "text",
                "fields": {
                  "keyword": {
                    "type": "keyword",
                    "ignore_above": 256
                  }
                }
              },
              "Hashes": {
                "type": "text",
                "fields": {
                  "keyword": {
                    "type": "keyword",
                    "ignore_above": 256
                  }
                }
              },
              "Image": {
                "type": "text",
                "fields": {
                  "keyword": {
                    "type": "keyword",
                    "ignore_above": 256
                  }
                }
              },
              "Initiated": {
                "type": "text",
                "fields": {
                  "keyword": {
                    "type": "keyword",
                    "ignore_above": 256
                  }
                }
              },
              "IntegrityLevel": {
                "type": "text",
                "fields": {
                  "keyword": {
                    "type": "keyword",
                    "ignore_above": 256
                  }
                }
              },
              "Interface": {
                "type": "text",
                "fields": {
                  "keyword": {
                    "type": "keyword",
                    "ignore_above": 256
                  }
                }
              },
              "LogonGuid": {
                "type": "text",
                "fields": {
                  "keyword": {
                    "type": "keyword",
                    "ignore_above": 256
                  }
                }
              },
              "LogonId": {
                "type": "text",
                "fields": {
                  "keyword": {
                    "type": "keyword",
                    "ignore_above": 256
                  }
                }
              },
              "ParentCommandLine": {
                "type": "text",
                "fields": {
                  "keyword": {
                    "type": "keyword",
                    "ignore_above": 256
                  }
                }
              },
              "ParentImage": {
                "type": "text",
                "fields": {
                  "keyword": {
                    "type": "keyword",
                    "ignore_above": 256
                  }
                }
              },
              "ParentProcessGuid": {
                "type": "text",
                "fields": {
                  "keyword": {
                    "type": "keyword",
                    "ignore_above": 256
                  }
                }
              },
              "ParentProcessId": {
                "type": "text",
                "fields": {
                  "keyword": {
                    "type": "keyword",
                    "ignore_above": 256
                  }
                }
              },
              "PreviousCreationUtcTime": {
                "type": "text",
                "fields": {
                  "keyword": {
                    "type": "keyword",
                    "ignore_above": 256
                  }
                }
              },
              "ProcessGuid": {
                "type": "text",
                "fields": {
                  "keyword": {
                    "type": "keyword",
                    "ignore_above": 256
                  }
                }
              },
              "ProcessId": {
                "type": "text",
                "fields": {
                  "keyword": {
                    "type": "keyword",
                    "ignore_above": 256
                  }
                }
              },
              "Protocol": {
                "type": "text",
                "fields": {
                  "keyword": {
                    "type": "keyword",
                    "ignore_above": 256
                  }
                }
              },
              "ProtocolType": {
                "type": "text",
                "fields": {
                  "keyword": {
                    "type": "keyword",
                    "ignore_above": 256
                  }
                }
              },
              "SourceHostname": {
                "type": "text",
                "fields": {
                  "keyword": {
                    "type": "keyword",
                    "ignore_above": 256
                  }
                }
              },
              "SourceIp": {
                "type": "text",
                "fields": {
                  "keyword": {
                    "type": "keyword",
                    "ignore_above": 256
                  }
                }
              },
              "SourceIsIpv6": {
                "type": "text",
                "fields": {
                  "keyword": {
                    "type": "keyword",
                    "ignore_above": 256
                  }
                }
              },
              "SourcePort": {
                "type": "text",
                "fields": {
                  "keyword": {
                    "type": "keyword",
                    "ignore_above": 256
                  }
                }
              },
              "SourcePortName": {
                "type": "text",
                "fields": {
                  "keyword": {
                    "type": "keyword",
                    "ignore_above": 256
                  }
                }
              },
              "TargetFilename": {
                "type": "text",
                "fields": {
                  "keyword": {
                    "type": "keyword",
                    "ignore_above": 256
                  }
                }
              },
              "TerminalSessionId": {
                "type": "text",
                "fields": {
                  "keyword": {
                    "type": "keyword",
                    "ignore_above": 256
                  }
                }
              },
              "User": {
                "type": "text",
                "fields": {
                  "keyword": {
                    "type": "keyword",
                    "ignore_above": 256
                  }
                }
              },
              "UtcTime": {
                "type": "text",
                "fields": {
                  "keyword": {
                    "type": "keyword",
                    "ignore_above": 256
                  }
                }
              }
            }
          },
          "event_id": {
            "type": "long"
          },
          "host": {
            "type": "text",
            "fields": {
              "keyword": {
                "type": "keyword",
                "ignore_above": 256
              }
            }
          },
          "level": {
            "type": "text",
            "fields": {
              "keyword": {
                "type": "keyword",
                "ignore_above": 256
              }
            }
          },
          "log_name": {
            "type": "text",
            "fields": {
              "keyword": {
                "type": "keyword",
                "ignore_above": 256
              }
            }
          },
          "message": {
            "type": "text",
            "fields": {
              "keyword": {
                "type": "keyword",
                "ignore_above": 256
              }
            }
          },
          "opcode": {
            "type": "text",
            "fields": {
              "keyword": {
                "type": "keyword",
                "ignore_above": 256
              }
            }
          },
          "process_id": {
            "type": "long"
          },
          "provider_guid": {
            "type": "text",
            "fields": {
              "keyword": {
                "type": "keyword",
                "ignore_above": 256
              }
            }
          },
          "record_number": {
            "type": "text",
            "fields": {
              "keyword": {
                "type": "keyword",
                "ignore_above": 256
              }
            }
          },
          "source_name": {
            "type": "text",
            "fields": {
              "keyword": {
                "type": "keyword",
                "ignore_above": 256
              }
            }
          },
          "tags": {
            "type": "text",
            "fields": {
              "keyword": {
                "type": "keyword",
                "ignore_above": 256
              }
            }
          },
          "task": {
            "type": "text",
            "fields": {
              "keyword": {
                "type": "keyword",
                "ignore_above": 256
              }
            }
          },
          "thread_id": {
            "type": "long"
          },
          "type": {
            "type": "text",
            "fields": {
              "keyword": {
                "type": "keyword",
                "ignore_above": 256
              }
            }
          },
          "user": {
            "properties": {
              "domain": {
                "type": "text",
                "fields": {
                  "keyword": {
                    "type": "keyword",
                    "ignore_above": 256
                  }
                }
              },
              "identifier": {
                "type": "text",
                "fields": {
                  "keyword": {
                    "type": "keyword",
                    "ignore_above": 256
                  }
                }
              },
              "name": {
                "type": "text",
                "fields": {
                  "keyword": {
                    "type": "keyword",
                    "ignore_above": 256
                  }
                }
              },
              "type": {
                "type": "text",
                "fields": {
                  "keyword": {
                    "type": "keyword",
                    "ignore_above": 256
                  }
                }
              }
            }
          },
          "version": {
            "type": "long"
          }
        }
      }
    }
  }