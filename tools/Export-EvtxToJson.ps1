<#
.SYNOPSIS
    Normalises 4688 and 4698 events from EVTX files into the Sigma taxonomy.

.DESCRIPTION
    This is, in practice, half of a Sigma backend: the part that translates field names.
    The other half, evaluating the rule logic, lives in sigma_eval.py.

    Mapping applied -- EVTX 4688 -> Sigma process_creation:

        Image            <- NewProcessName
        CommandLine      <- CommandLine
        ParentImage      <- ParentProcessName     (NOT present in every schema)
        User             <- SubjectDomainName\SubjectUserName
        ProcessId        <- NewProcessId
        ParentProcessId  <- ProcessId             <-- CAREFUL

    The last line is the trap. In EVTX, "ProcessId" is the CREATING process, not the created
    one. Mapping ProcessId -> ProcessId inverts the whole tree and raises no error at all.

    Event 4698 -- "a scheduled task was created" -- uses the windows/security logsource,
    where the correlating field is EventID itself. Fields emitted: TaskName, TaskContent.

    TaskContent is the task's full XML and easily exceeds 1600 characters. Truncating it to
    the normal limit would destroy detection, so it has its own limit (-MaxTaskContentLength).
    It is configuration XML, not payload text -- the reason for the general truncation does not apply.

    READ ONLY. It does not write to the Event Log, does not change audit policy,
    and does not execute anything from the event content.

.PARAMETER Path
    An .evtx file, or a folder containing .evtx files.

.PARAMETER OutFile
    JSON destination.

.PARAMETER MaxFieldLength
    Truncates long fields. It exists for a concrete reason: writing a payload's full
    command line to disk made the host antivirus block the write.
    See DAY-02-EVTX-CORRELATION.md, section 8.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$OutFile,
    [int]$MaxFieldLength = 400,
    [int]$MaxTaskContentLength = 20000
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-EventFields {
    param([System.Diagnostics.Eventing.Reader.EventRecord]$Event)

    $bag = @{}
    $xml = [xml]$Event.ToXml()
    foreach ($node in $xml.SelectNodes('//*[local-name()="Data"]')) {
        $name = $node.GetAttribute('Name')
        if ($name) { $bag[$name] = [string]$node.InnerText }
    }
    $bag
}

function Get-Field {
    param([hashtable]$Bag, [string]$Name, [int]$Limit)

    if (-not $Bag.ContainsKey($Name)) { return $null }
    $value = $Bag[$Name]
    if ($value -eq '' -or $value -eq '-') { return $null }
    if ($value.Length -gt $Limit) { $value = $value.Substring(0, $Limit) + '...[TRUNCADO]' }
    $value
}

$files = if (Test-Path -Path $Path -PathType Container) {
    Get-ChildItem -Path $Path -Filter *.evtx
} else {
    Get-Item -Path $Path
}

$records = New-Object System.Collections.Generic.List[object]

foreach ($file in $files) {
    $events = Get-WinEvent -Path $file.FullName -ErrorAction Stop |
              Where-Object { $_.Id -in @(4688, 4698) }

    foreach ($event in $events) {
        $bag = Get-EventFields -Event $event

        $domain = Get-Field -Bag $bag -Name 'SubjectDomainName' -Limit $MaxFieldLength
        $user   = Get-Field -Bag $bag -Name 'SubjectUserName'   -Limit $MaxFieldLength
        $account = if ($domain -and $user) { "$domain\$user" } else { $user }

        $records.Add([pscustomobject]@{
            SourceFile      = $file.Name
            EventID         = $event.Id
            Timestamp       = $event.TimeCreated.ToUniversalTime().ToString('o')
            Computer        = $event.MachineName
            Image           = Get-Field -Bag $bag -Name 'NewProcessName'    -Limit $MaxFieldLength
            CommandLine     = Get-Field -Bag $bag -Name 'CommandLine'       -Limit $MaxFieldLength
            ParentImage     = Get-Field -Bag $bag -Name 'ParentProcessName' -Limit $MaxFieldLength
            User            = $account
            UserSid         = Get-Field -Bag $bag -Name 'SubjectUserSid'    -Limit $MaxFieldLength
            LogonId         = Get-Field -Bag $bag -Name 'SubjectLogonId'    -Limit $MaxFieldLength
            ProcessId       = Get-Field -Bag $bag -Name 'NewProcessId'      -Limit $MaxFieldLength
            ParentProcessId = Get-Field -Bag $bag -Name 'ProcessId'         -Limit $MaxFieldLength
            TaskName        = Get-Field -Bag $bag -Name 'TaskName'          -Limit $MaxFieldLength
            TaskContent     = Get-Field -Bag $bag -Name 'TaskContent'       -Limit $MaxTaskContentLength
        })
    }
}

$records | ConvertTo-Json -Depth 4 | Set-Content -Path $OutFile -Encoding UTF8

Write-Output ("eventos normalizados      : {0}" -f $records.Count)
Write-Output ("  4688 process_creation   : {0}" -f @($records | Where-Object EventID -eq 4688).Count)
Write-Output ("  4698 scheduled task     : {0}" -f @($records | Where-Object EventID -eq 4698).Count)
Write-Output ("ficheiros lidos           : {0}" -f @($files).Count)
Write-Output ("sem ParentImage no schema : {0}" -f @($records | Where-Object { -not $_.ParentImage }).Count)
Write-Output ("destino                   : {0}" -f $OutFile)
