# TSPersistentService

Proof-of-concept script for live analysis of persistent Windows Services [MITRE T1543.003] as presented in the 2021 SEC-T Conference.

## Usage

Get services
```
import-module .\TSPersistentService.psm1
Get-TSPersistentService 
```

Get timeline of service-related events and save it as a CSV file.  
```
import-module .\TSPersistentService.psm1
Get-TSPersistentService | ConvertTo-TSTimeline | Export-csv -NoTypeInformation -Encoding utf8 .\timeline.csv
```

