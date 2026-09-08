<#
.SYNOPSIS
    Normaliza eventos 4688 de ficheiros EVTX para a taxonomia Sigma "process_creation".

.DESCRIPTION
    Isto e, na pratica, meio backend de Sigma: a parte que traduz nomes de campo.
    A outra metade (avaliar a logica da regra) esta em sigma_eval.py.

    Mapeamento aplicado -- EVTX 4688 -> Sigma process_creation:

        Image            <- NewProcessName
        CommandLine      <- CommandLine
        ParentImage      <- ParentProcessName     (NAO existe em todos os schemas)
        User             <- SubjectDomainName\SubjectUserName
        ProcessId        <- NewProcessId
        ParentProcessId  <- ProcessId             <-- ATENCAO

    A ultima linha e a armadilha. No EVTX, "ProcessId" e o processo CRIADOR, nao o criado.
    Quem mapeia ProcessId -> ProcessId inverte a arvore inteira e nao recebe erro nenhum.

    SO LEITURA. Nao escreve no Event Log, nao altera politica de auditoria,
    nao executa nada do conteudo dos eventos.

.PARAMETER Path
    Ficheiro .evtx ou pasta com ficheiros .evtx.

.PARAMETER OutFile
    Destino JSON.

.PARAMETER MaxFieldLength
    Trunca campos longos. Existe por um motivo concreto: escrever a linha de comando
    integral de um payload em disco fez o antivirus do host bloquear a escrita.
    Ver DAY-02-EVTX-CORRELATION.md, seccao 8.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$OutFile,
    [int]$MaxFieldLength = 400
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
              Where-Object { $_.Id -eq 4688 }

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
        })
    }
}

$records | ConvertTo-Json -Depth 4 | Set-Content -Path $OutFile -Encoding UTF8

Write-Output ("eventos 4688 normalizados : {0}" -f $records.Count)
Write-Output ("ficheiros lidos           : {0}" -f @($files).Count)
Write-Output ("sem ParentImage no schema : {0}" -f @($records | Where-Object { -not $_.ParentImage }).Count)
Write-Output ("destino                   : {0}" -f $OutFile)
