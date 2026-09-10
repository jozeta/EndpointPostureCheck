#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    EndpointPostureCheck - Enterprise Windows 11 Endpoint Security Posture Auditor.

.DESCRIPTION
    Invoke-EndpointPostureCheck performs an exhaustive, read-only security posture audit of a
    Windows 11 endpoint across eleven core hardening domains: platform/firmware integrity,
    virtualization-based security, volume encryption, next-gen antivirus/EDR, attack surface
    reduction & exploit mitigation, application control, identity & privilege management,
    network hardening, cryptography/Schannel, PowerShell subsystem security, and advanced
    security auditing.

    Every individual control evaluation is captured through the Add-AuditResult helper and
    mapped to CIS Controls v8, NIST SP 800-53 Rev.5, MITRE ATT&CK, ISO/IEC 27001:2022, the
    NIS2 Directive (Art. 21), and NSA/CISA hardening guidance. Results are aggregated into a
    weighted compliance score, an overall risk badge, and rendered as a self-contained,
    single-file HTML executive dashboard. Raw findings can optionally be exported to JSON, and
    a companion remediation script can be generated to address every FAIL finding.

    The script is fault tolerant by design: every control is evaluated inside its own
    try/catch boundary so that a missing subsystem, unsupported SKU, or access-denied
    condition never aborts the overall audit. Such conditions are logged as WARN/INFO
    findings instead.

.PARAMETER ReportPath
    Optional path for the generated HTML dashboard. May be a directory (in which case the
    default file name is used) or a full file path. Defaults to the current working directory.

.PARAMETER ExportJson
    Switch. When present, exports the complete structured audit result set to a JSON file
    alongside the HTML report.

.PARAMETER GenerateRemediationScript
    Switch. When present, generates a companion Remediate-EndpointPostureCheck.ps1 script
    containing modular, commented remediation commands for every FAIL finding.

.EXAMPLE
    .\Invoke-EndpointPostureCheck.ps1

    Runs a full audit and writes the HTML dashboard to the current directory.

.EXAMPLE
    .\Invoke-EndpointPostureCheck.ps1 -ReportPath C:\Reports -ExportJson -GenerateRemediationScript

    Runs a full audit, writes the HTML dashboard and JSON export to C:\Reports, and generates
    a remediation script for every failed control.

.NOTES
    Name       : EndpointPostureCheck
    Author     : Senior Enterprise Microsoft Security Architecture Team
    Requires   : Windows 11, PowerShell 5.1+ or 7.x, local Administrator
    Compatible : Windows PowerShell 5.1 and PowerShell 7.x
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$ReportPath,

    [Parameter(Mandatory = $false)]
    [switch]$ExportJson,

    [Parameter(Mandatory = $false)]
    [switch]$GenerateRemediationScript
)

#region ============================== INITIALIZATION ==============================

# Do not use Set-StrictMode here: many CIM/registry properties are legitimately absent on
# certain SKUs/hardware, and the audit must tolerate that gracefully rather than throw.
$ProgressPreference = 'Continue'

$Script:ScriptVersion   = '1.0.0'
$Script:StartTime       = Get-Date
$Script:ComputerName    = $env:COMPUTERNAME
$Script:AuditResults    = [System.Collections.Generic.List[PSObject]]::new()

# Known Attack Surface Reduction rule GUID -> friendly name map (Microsoft Defender ASR).
$Script:ASRRuleMap = @{
    '56a863a9-875e-4185-98a7-b882c64b5ce5' = 'Block abuse of exploited vulnerable signed drivers'
    '7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c' = 'Block Adobe Reader from creating child processes'
    'd4f940ab-401b-4efc-aadc-ad5f3c50688a' = 'Block all Office applications from creating child processes'
    '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2' = 'Block credential stealing from the Windows local security authority subsystem (lsass.exe)'
    'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550' = 'Block executable content from email client and webmail'
    '01443614-cd74-433a-b99e-2ecdc07bfc25' = 'Block executable files from running unless they meet a prevalence, age, or trusted list criterion'
    '5beb7efe-fd9a-4556-801d-275e5ffc04cc' = 'Block execution of potentially obfuscated scripts'
    'd3e037e1-3eb8-44c8-a917-57927947596d' = 'Block JavaScript or VBScript from launching downloaded executable content'
    '3b576869-a4ec-4529-8536-b80a7769e899' = 'Block Office applications from creating executable content'
    '75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84' = 'Block Office applications from injecting code into other processes'
    '26190899-1602-49e8-8b27-eb1d0a1ce869' = 'Block Office communication application from creating child processes'
    'e6db77e5-3df2-4cf1-b95a-636979351e5b' = 'Block persistence through WMI event subscription'
    'd1e49aac-8f56-4280-b9ba-993a6d77406c' = 'Block process creations originating from PSExec and WMI commands'
    'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4' = 'Block untrusted and unsigned processes that run from USB'
    '92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b' = 'Block Win32 API calls from Office macros'
    'c1db55ab-c21a-4637-bb3f-a12568109d35' = 'Use advanced protection against ransomware'
    'a8f5898e-1dc8-49a9-9878-85004b8a61e6' = 'Block Webshell creation for Servers'
    '33ddedf1-c6e0-47cb-833e-de6133960387' = 'Block rebooting machine in Safe Mode'
    'c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb' = 'Block use of copied or impersonated system tools'
}

# The subset of ASR rules considered critical attack-vector coverage. Anything other than
# Block (1) on these rules is treated as a High/Critical severity finding.
$Script:CriticalASRRules = @(
    '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2', # Credential theft from LSASS
    'd4f940ab-401b-4efc-aadc-ad5f3c50688a', # Office child process spawning
    '3b576869-a4ec-4529-8536-b80a7769e899', # Office creating executable content
    '92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b', # Win32 API calls from Office macros
    '5beb7efe-fd9a-4556-801d-275e5ffc04cc', # Obfuscated script execution
    'd1e49aac-8f56-4280-b9ba-993a6d77406c', # PsExec/WMI child processes
    'c1db55ab-c21a-4637-bb3f-a12568109d35'  # Ransomware protection
)

#endregion

#region ============================== CORE HELPER FUNCTIONS ==============================

function Test-IsElevated {
    <#
        Returns $true if the current process token has the local Administrator role.
    #>
    try {
        $identity  = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        return $false
    }
}

function Add-AuditResult {
    <#
        Standardized finding logger. Every control evaluation in EndpointPostureCheck must
        call this helper so that all findings share one consistent schema for scoring,
        JSON export, HTML rendering, and remediation-script generation.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]  [string]$Category,
        [Parameter(Mandatory = $true)]  [string]$Control,
        [Parameter(Mandatory = $true)]  [ValidateSet('PASS','FAIL','WARN','INFO')] [string]$Status,
        [Parameter(Mandatory = $true)]  [ValidateSet('Critical','High','Medium','Low','Informational')] [string]$Severity,
        [Parameter(Mandatory = $false)] [string]$CurrentValue     = 'N/A',
        [Parameter(Mandatory = $false)] [string]$RecommendedValue = 'N/A',
        [Parameter(Mandatory = $false)] [string]$CIS_Control      = 'N/A',
        [Parameter(Mandatory = $false)] [string]$NIST_Control     = 'N/A',
        [Parameter(Mandatory = $false)] [string]$MITRE_Technique  = 'N/A',
        [Parameter(Mandatory = $false)] [string]$ISO27001_Control = 'N/A',
        [Parameter(Mandatory = $false)] [string]$NIS2_Article     = 'N/A',
        [Parameter(Mandatory = $false)] [string]$NSA_Guidance     = 'N/A',
        [Parameter(Mandatory = $false)] [string]$Recommendation   = 'No remediation required.'
    )

    $finding = [PSCustomObject]@{
        Id               = $Script:AuditResults.Count + 1
        Category         = $Category
        Control          = $Control
        Status           = $Status
        Severity         = $Severity
        CurrentValue     = $CurrentValue
        RecommendedValue = $RecommendedValue
        CIS_Control      = $CIS_Control
        NIST_Control      = $NIST_Control
        MITRE_Technique  = $MITRE_Technique
        ISO27001_Control = $ISO27001_Control
        NIS2_Article     = $NIS2_Article
        NSA_Guidance     = $NSA_Guidance
        Recommendation   = $Recommendation
        Timestamp        = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
    }

    $Script:AuditResults.Add($finding) | Out-Null

    # Live console feedback per finding.
    $color = switch ($Status) {
        'PASS' { 'Green' }
        'FAIL' { 'Red' }
        'WARN' { 'Yellow' }
        'INFO' { 'Cyan' }
        default { 'Gray' }
    }
    Write-Host ("  [{0,-4}] {1,-8} {2}" -f $Status, "($Severity)", $Control) -ForegroundColor $color
}

function Write-SectionBanner {
    param([Parameter(Mandatory = $true)][string]$Title)
    Write-Host ""
    Write-Host ("=" * 78) -ForegroundColor DarkCyan
    Write-Host (" {0}" -f $Title) -ForegroundColor Cyan
    Write-Host ("=" * 78) -ForegroundColor DarkCyan
}

function Get-RegistryValueSafe {
    <#
        Reads a single registry value, returning a caller-supplied default instead of
        throwing when the key or value does not exist. Centralizes the very common
        "registry policy not configured" pattern used throughout every check function.
    #>
    param(
        [Parameter(Mandatory = $true)]  [string]$Path,
        [Parameter(Mandatory = $true)]  [string]$Name,
        [Parameter(Mandatory = $false)] $DefaultValue = $null
    )
    try {
        if (Test-Path -LiteralPath $Path) {
            $item = Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop
            return $item.$Name
        }
        return $DefaultValue
    } catch {
        return $DefaultValue
    }
}

#endregion

#region ============================== 1. HARDWARE, FIRMWARE & PLATFORM INTEGRITY ==============================

function Test-TPMStatus {
    <#
        Verifies TPM presence, operational readiness, ownership, and 2.0 specification
        compliance via the built-in Get-Tpm cmdlet and the Win32_Tpm CIM class.
    #>
    Write-SectionBanner 'Hardware, Firmware & Platform Integrity - TPM'
    try {
        $tpm = Get-Tpm -ErrorAction Stop
        $tpmCim = $null
        try {
            $tpmCim = Get-CimInstance -Namespace 'root/cimv2/security/microsofttpm' -ClassName Win32_Tpm -ErrorAction Stop
        } catch { $tpmCim = $null }

        $specVersion = 'Unknown'
        if ($tpmCim -and $tpmCim.SpecVersion) { $specVersion = $tpmCim.SpecVersion }
        $isTpm2 = $specVersion -match '^\s*2\.0'

        if (-not $tpm.TpmPresent) {
            Add-AuditResult -Category 'Hardware, Firmware & Platform Integrity' -Control 'TPM 2.0 Presence & Readiness' `
                -Status 'FAIL' -Severity 'Critical' -CurrentValue 'No TPM detected' -RecommendedValue 'TPM 2.0 present, ready, and enabled' `
                -CIS_Control 'CIS 10.5' -NIST_Control 'IA-3, SC-28' -MITRE_Technique 'T1552.004 (Private Keys), T1200 (Hardware Additions)' `
                -ISO27001_Control 'A.8.24' -NIS2_Article 'Art.21(2)(h)' -NSA_Guidance 'NSA/CISA Advancing Zero Trust Maturity - Device Pillar' `
                -Recommendation 'Enable TPM 2.0 in firmware/UEFI setup. On hardware without a TPM, this endpoint cannot support Credential Guard, BitLocker with TPM protectors, or a full hardware root of trust.'
        } elseif (-not $isTpm2) {
            Add-AuditResult -Category 'Hardware, Firmware & Platform Integrity' -Control 'TPM 2.0 Presence & Readiness' `
                -Status 'WARN' -Severity 'High' -CurrentValue "TPM present, Spec=$specVersion" -RecommendedValue 'TPM Specification Version 2.0' `
                -CIS_Control 'CIS 10.5' -NIST_Control 'IA-3, SC-28' -MITRE_Technique 'T1552.004 (Private Keys)' `
                -ISO27001_Control 'A.8.24' -NIS2_Article 'Art.21(2)(h)' -NSA_Guidance 'NSA/CISA Advancing Zero Trust Maturity - Device Pillar' `
                -Recommendation 'Upgrade to a TPM 2.0-compliant device. TPM 1.2 lacks algorithm agility and is not supported for full VBS/Credential Guard hardware attestation.'
        } elseif (-not ($tpm.TpmReady -and $tpm.TpmEnabled)) {
            Add-AuditResult -Category 'Hardware, Firmware & Platform Integrity' -Control 'TPM 2.0 Presence & Readiness' `
                -Status 'FAIL' -Severity 'Critical' -CurrentValue "Present=$($tpm.TpmPresent); Ready=$($tpm.TpmReady); Enabled=$($tpm.TpmEnabled); Spec=$specVersion" `
                -RecommendedValue 'TpmReady=True, TpmEnabled=True' -CIS_Control 'CIS 10.5' -NIST_Control 'IA-3, SC-28' `
                -MITRE_Technique 'T1552.004 (Private Keys)' -ISO27001_Control 'A.8.24' -NIS2_Article 'Art.21(2)(h)' `
                -NSA_Guidance 'NSA/CISA Advancing Zero Trust Maturity - Device Pillar' `
                -Recommendation 'Enable and initialize the TPM in UEFI firmware settings, then run "Initialize-Tpm" from an elevated PowerShell session.'
        } else {
            Add-AuditResult -Category 'Hardware, Firmware & Platform Integrity' -Control 'TPM 2.0 Presence & Readiness' `
                -Status 'PASS' -Severity 'Critical' -CurrentValue "Present=True; Ready=True; Enabled=True; Owned=$($tpm.TpmOwned); Spec=$specVersion" `
                -RecommendedValue 'TPM 2.0 present, ready, and enabled' -CIS_Control 'CIS 10.5' -NIST_Control 'IA-3, SC-28' `
                -MITRE_Technique 'T1552.004 (Private Keys)' -ISO27001_Control 'A.8.24' -NIS2_Article 'Art.21(2)(h)' `
                -NSA_Guidance 'NSA/CISA Advancing Zero Trust Maturity - Device Pillar' -Recommendation 'No action required. Keep TPM/UEFI firmware current via OEM updates.'
        }

        if ($tpm.TpmPresent -and -not $tpm.TpmOwned) {
            Add-AuditResult -Category 'Hardware, Firmware & Platform Integrity' -Control 'TPM Ownership' `
                -Status 'WARN' -Severity 'Medium' -CurrentValue 'TPM not owned/provisioned' -RecommendedValue 'TPM owned and provisioned by the OS' `
                -CIS_Control 'CIS 10.5' -NIST_Control 'SC-28' -MITRE_Technique 'T1552.004 (Private Keys)' -ISO27001_Control 'A.8.24' `
                -NIS2_Article 'Art.21(2)(h)' -NSA_Guidance 'NSA/CISA Advancing Zero Trust Maturity - Device Pillar' `
                -Recommendation 'Provision TPM ownership via Initialize-Tpm so BitLocker and Credential Guard can bind protectors to the module.'
        }
    } catch {
        Add-AuditResult -Category 'Hardware, Firmware & Platform Integrity' -Control 'TPM 2.0 Presence & Readiness' `
            -Status 'WARN' -Severity 'Low' -CurrentValue 'Query failed' -RecommendedValue 'TPM 2.0 present, ready, and enabled' `
            -CIS_Control 'CIS 10.5' -NIST_Control 'IA-3, SC-28' -Recommendation "Unable to query TPM state: $($_.Exception.Message)"
    }
}

function Test-SecureBootAndUEFI {
    <#
        Verifies UEFI firmware mode and Secure Boot enforcement via Confirm-SecureBootUEFI.
        Confirm-SecureBootUEFI throws on legacy BIOS/CSM systems, which is used here to
        positively detect a legacy boot configuration.
    #>
    Write-SectionBanner 'Hardware, Firmware & Platform Integrity - Secure Boot & UEFI'
    $uefiMode = $false
    $secureBootEnabled = $false
    try {
        $secureBootEnabled = [bool](Confirm-SecureBootUEFI -ErrorAction Stop)
        $uefiMode = $true
    } catch {
        $uefiMode = $false
    }

    if ($uefiMode -and $secureBootEnabled) {
        Add-AuditResult -Category 'Hardware, Firmware & Platform Integrity' -Control 'Secure Boot & UEFI Firmware Mode' `
            -Status 'PASS' -Severity 'Critical' -CurrentValue 'UEFI mode; Secure Boot Enabled' -RecommendedValue 'UEFI mode; Secure Boot Enabled' `
            -CIS_Control 'CIS 10.5' -NIST_Control 'SI-7, SC-28' -MITRE_Technique 'T1542.003 (Bootkit), T1542.001 (System Firmware)' `
            -ISO27001_Control 'A.8.24' -NIS2_Article 'Art.21(2)(d)' -NSA_Guidance 'NSA/CISA UEFI Secure Boot Customization Guidance' `
            -Recommendation 'No action required. Periodically update the Secure Boot DBX revocation list via Windows Update.'
    } elseif ($uefiMode -and -not $secureBootEnabled) {
        Add-AuditResult -Category 'Hardware, Firmware & Platform Integrity' -Control 'Secure Boot & UEFI Firmware Mode' `
            -Status 'FAIL' -Severity 'Critical' -CurrentValue 'UEFI mode; Secure Boot Disabled' -RecommendedValue 'UEFI mode; Secure Boot Enabled' `
            -CIS_Control 'CIS 10.5' -NIST_Control 'SI-7, SC-28' -MITRE_Technique 'T1542.003 (Bootkit)' -ISO27001_Control 'A.8.24' `
            -NIS2_Article 'Art.21(2)(d)' -NSA_Guidance 'NSA/CISA UEFI Secure Boot Customization Guidance' `
            -Recommendation 'Enable Secure Boot from UEFI firmware setup (typically F2/F10/Del at boot) to prevent unsigned bootkit/rootkit execution.'
    } else {
        Add-AuditResult -Category 'Hardware, Firmware & Platform Integrity' -Control 'Secure Boot & UEFI Firmware Mode' `
            -Status 'FAIL' -Severity 'Critical' -CurrentValue 'Legacy BIOS / CSM mode (Secure Boot unavailable)' -RecommendedValue 'UEFI mode; Secure Boot Enabled' `
            -CIS_Control 'CIS 10.5' -NIST_Control 'SI-7, SC-28' -MITRE_Technique 'T1542.003 (Bootkit)' -ISO27001_Control 'A.8.24' `
            -NIS2_Article 'Art.21(2)(d)' -NSA_Guidance 'NSA/CISA UEFI Secure Boot Customization Guidance' `
            -Recommendation 'Convert the system disk to GPT (MBR2GPT.exe) and switch firmware from Legacy/CSM to native UEFI, then enable Secure Boot.'
    }
}

function Test-DMAProtection {
    <#
        Audits Kernel DMA Protection. Runtime enforcement is only authoritatively surfaced
        via System Information (msinfo32); this check reports the GPO-backed policy state
        (Kernel DMA Protection device enumeration policy) as the auditable proxy and flags
        the result as informational when no explicit policy is present, since modern Windows
        11-certified hardware enables Kernel DMA Protection by default without a policy.
    #>
    Write-SectionBanner 'Hardware, Firmware & Platform Integrity - Kernel DMA Protection'
    try {
        $policyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection'
        $policyValue = Get-RegistryValueSafe -Path $policyPath -Name 'DeviceEnumerationPolicy' -DefaultValue $null

        # Bus-relevant hardware capability flag (set by DCH drivers on Thunderbolt/USB4 capable systems).
        $deviceGuard = $null
        try { $deviceGuard = Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName Win32_DeviceGuard -ErrorAction Stop } catch { $deviceGuard = $null }

        if ($null -ne $policyValue) {
            $policyMap = @{ 0 = 'Block all (most secure)'; 1 = 'Allow all (least secure)'; 2 = 'Allow only backward-compatible devices'; 3 = 'Allow only external devices with UEFI DMA protection' }
            $desc = $policyMap[[int]$policyValue]
            if ([int]$policyValue -eq 0 -or [int]$policyValue -eq 3) {
                Add-AuditResult -Category 'Hardware, Firmware & Platform Integrity' -Control 'Hardware-Enforced Kernel DMA Protection' `
                    -Status 'PASS' -Severity 'High' -CurrentValue "Policy=$policyValue ($desc)" -RecommendedValue 'Block all, or Allow only UEFI DMA-protected devices' `
                    -CIS_Control 'CIS 10.5' -NIST_Control 'SC-28, SC-41' -MITRE_Technique 'T1200 (Hardware Additions)' -ISO27001_Control 'A.8.24' `
                    -NIS2_Article 'Art.21(2)(d)' -NSA_Guidance 'NSA/CISA Stop Malicious Cyber Activity - Physical Access Vectors' `
                    -Recommendation 'No action required.'
            } else {
                Add-AuditResult -Category 'Hardware, Firmware & Platform Integrity' -Control 'Hardware-Enforced Kernel DMA Protection' `
                    -Status 'FAIL' -Severity 'High' -CurrentValue "Policy=$policyValue ($desc)" -RecommendedValue 'Block all, or Allow only UEFI DMA-protected devices' `
                    -CIS_Control 'CIS 10.5' -NIST_Control 'SC-28, SC-41' -MITRE_Technique 'T1200 (Hardware Additions)' -ISO27001_Control 'A.8.24' `
                    -NIS2_Article 'Art.21(2)(d)' -NSA_Guidance 'NSA/CISA Stop Malicious Cyber Activity - Physical Access Vectors' `
                    -Recommendation 'Set GPO "Enumeration policy for external devices incompatible with Kernel DMA Protection" to Block All under Administrative Templates > Device Guard.'
            }
        } else {
            Add-AuditResult -Category 'Hardware, Firmware & Platform Integrity' -Control 'Hardware-Enforced Kernel DMA Protection' `
                -Status 'INFO' -Severity 'Informational' -CurrentValue 'No explicit GPO policy configured' -RecommendedValue 'Verify via msinfo32.exe "Kernel DMA Protection" = On' `
                -CIS_Control 'CIS 10.5' -NIST_Control 'SC-28, SC-41' -MITRE_Technique 'T1200 (Hardware Additions)' -ISO27001_Control 'A.8.24' `
                -NIS2_Article 'Art.21(2)(d)' -NSA_Guidance 'NSA/CISA Stop Malicious Cyber Activity - Physical Access Vectors' `
                -Recommendation 'No explicit policy is set. On Windows 11-certified hardware with an IOMMU, Kernel DMA Protection is on by default; confirm the live state via System Information (msinfo32.exe) and set the GPO explicitly for defense in depth.'
        }
    } catch {
        Add-AuditResult -Category 'Hardware, Firmware & Platform Integrity' -Control 'Hardware-Enforced Kernel DMA Protection' `
            -Status 'WARN' -Severity 'Low' -CurrentValue 'Query failed' -RecommendedValue 'Block all, or Allow only UEFI DMA-protected devices' `
            -Recommendation "Unable to determine DMA protection state: $($_.Exception.Message)"
    }
}

#endregion

#region ============================== 2. VIRTUALIZATION-BASED SECURITY & KERNEL ISOLATION ==============================

function Get-DeviceGuardStatus {
    <#
        Central accessor for Win32_DeviceGuard, shared by the VBS/HVCI, Credential Guard, and
        System Guard checks so the CIM call is only made once per audit run.
    #>
    if ($null -eq $Script:DeviceGuardCache) {
        try {
            $Script:DeviceGuardCache = Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName Win32_DeviceGuard -ErrorAction Stop
        } catch {
            $Script:DeviceGuardCache = $false
        }
    }
    return $Script:DeviceGuardCache
}

function Test-VBSAndHVCI {
    <#
        Audits Virtualization-Based Security enablement and Hypervisor-Enforced Code
        Integrity (Memory Integrity / HVCI) via Win32_DeviceGuard.
        VirtualizationBasedSecurityStatus: 0=Not enabled, 1=Enabled not running, 2=Running.
        SecurityServicesRunning enum: 1=Credential Guard, 2=HVCI, 3=System Guard Secure Launch, 4=SMM Firmware Measurement.
    #>
    Write-SectionBanner 'Virtualization-Based Security - VBS & HVCI'
    try {
        $dg = Get-DeviceGuardStatus
        if (-not $dg) { throw 'Win32_DeviceGuard class unavailable' }

        $vbsStatus = $dg.VirtualizationBasedSecurityStatus
        $vbsMap = @{ 0 = 'Not Enabled'; 1 = 'Enabled, Not Running'; 2 = 'Enabled and Running' }
        $vbsDesc = $vbsMap[[int]$vbsStatus]

        if ([int]$vbsStatus -eq 2) {
            Add-AuditResult -Category 'Virtualization-Based Security' -Control 'Virtualization-Based Security (VBS)' `
                -Status 'PASS' -Severity 'Critical' -CurrentValue $vbsDesc -RecommendedValue 'Enabled and Running' `
                -CIS_Control 'CIS 10.5' -NIST_Control 'SC-39, SC-7' -MITRE_Technique 'T1055 (Process Injection), T1068 (Exploitation for Privilege Escalation)' `
                -ISO27001_Control 'A.8.24' -NIS2_Article 'Art.21(2)(d)' -NSA_Guidance 'NSA Hardening Guidance for Windows 11' `
                -Recommendation 'No action required.'
        } else {
            Add-AuditResult -Category 'Virtualization-Based Security' -Control 'Virtualization-Based Security (VBS)' `
                -Status 'FAIL' -Severity 'Critical' -CurrentValue $vbsDesc -RecommendedValue 'Enabled and Running' `
                -CIS_Control 'CIS 10.5' -NIST_Control 'SC-39, SC-7' -MITRE_Technique 'T1055 (Process Injection), T1068 (Exploitation for Privilege Escalation)' `
                -ISO27001_Control 'A.8.24' -NIS2_Article 'Art.21(2)(d)' -NSA_Guidance 'NSA Hardening Guidance for Windows 11' `
                -Recommendation 'Enable VBS via GPO: Computer Configuration > Administrative Templates > System > Device Guard > "Turn On Virtualization Based Security". Requires UEFI, Secure Boot, and a compatible CPU with virtualization extensions enabled in firmware.'
        }

        $running = @()
        if ($dg.SecurityServicesRunning) { $running = $dg.SecurityServicesRunning }
        $hvciRunning = $running -contains 2

        if ($hvciRunning) {
            Add-AuditResult -Category 'Virtualization-Based Security' -Control 'Hypervisor-Enforced Code Integrity (HVCI / Memory Integrity)' `
                -Status 'PASS' -Severity 'Critical' -CurrentValue 'Running' -RecommendedValue 'Running' `
                -CIS_Control 'CIS 10.5' -NIST_Control 'SI-7, SC-39' -MITRE_Technique 'T1014 (Rootkit), T1055 (Process Injection)' `
                -ISO27001_Control 'A.8.24' -NIS2_Article 'Art.21(2)(d)' -NSA_Guidance 'NSA Hardening Guidance for Windows 11' `
                -Recommendation 'No action required.'
        } else {
            Add-AuditResult -Category 'Virtualization-Based Security' -Control 'Hypervisor-Enforced Code Integrity (HVCI / Memory Integrity)' `
                -Status 'FAIL' -Severity 'Critical' -CurrentValue 'Not Running' -RecommendedValue 'Running' `
                -CIS_Control 'CIS 10.5' -NIST_Control 'SI-7, SC-39' -MITRE_Technique 'T1014 (Rootkit), T1055 (Process Injection)' `
                -ISO27001_Control 'A.8.24' -NIS2_Article 'Art.21(2)(d)' -NSA_Guidance 'NSA Hardening Guidance for Windows 11' `
                -Recommendation 'Enable "Memory Integrity" in Windows Security > Device Security > Core Isolation, or via GPO "Turn On Virtualization Based Security" > Enable Hypervisor Enforced Code Integrity.'
        }
    } catch {
        Add-AuditResult -Category 'Virtualization-Based Security' -Control 'Virtualization-Based Security (VBS)' `
            -Status 'WARN' -Severity 'Low' -CurrentValue 'Query failed' -RecommendedValue 'Enabled and Running' `
            -Recommendation "Unable to query Device Guard/VBS state: $($_.Exception.Message)"
    }
}

function Test-CredentialGuard {
    <#
        Audits Windows Defender Credential Guard, which isolates LSASS secrets (NTLM hashes,
        Kerberos TGTs) in a VBS-protected container inaccessible even to the kernel.
    #>
    Write-SectionBanner 'Virtualization-Based Security - Credential Guard'
    try {
        $dg = Get-DeviceGuardStatus
        if (-not $dg) { throw 'Win32_DeviceGuard class unavailable' }

        $running = @()
        if ($dg.SecurityServicesRunning) { $running = $dg.SecurityServicesRunning }
        $configured = @()
        if ($dg.SecurityServicesConfigured) { $configured = $dg.SecurityServicesConfigured }

        $cgRunning = $running -contains 1
        $cgConfigured = $configured -contains 1

        if ($cgRunning) {
            Add-AuditResult -Category 'Virtualization-Based Security' -Control 'Credential Guard (LSASS Secrets Isolation)' `
                -Status 'PASS' -Severity 'Critical' -CurrentValue 'Running' -RecommendedValue 'Running' `
                -CIS_Control 'CIS 18.4' -NIST_Control 'IA-5, SC-28' -MITRE_Technique 'T1003.001 (LSASS Memory)' -ISO27001_Control 'A.8.5' `
                -NIS2_Article 'Art.21(2)(i)' -NSA_Guidance 'NSA CSI: Mitigating Credential Theft' `
                -Recommendation 'No action required.'
        } elseif ($cgConfigured) {
            Add-AuditResult -Category 'Virtualization-Based Security' -Control 'Credential Guard (LSASS Secrets Isolation)' `
                -Status 'WARN' -Severity 'High' -CurrentValue 'Configured but not yet running (reboot pending)' -RecommendedValue 'Running' `
                -CIS_Control 'CIS 18.4' -NIST_Control 'IA-5, SC-28' -MITRE_Technique 'T1003.001 (LSASS Memory)' -ISO27001_Control 'A.8.5' `
                -NIS2_Article 'Art.21(2)(i)' -NSA_Guidance 'NSA CSI: Mitigating Credential Theft' `
                -Recommendation 'Reboot the endpoint to complete Credential Guard activation.'
        } else {
            Add-AuditResult -Category 'Virtualization-Based Security' -Control 'Credential Guard (LSASS Secrets Isolation)' `
                -Status 'FAIL' -Severity 'Critical' -CurrentValue 'Not Configured / Not Running' -RecommendedValue 'Running' `
                -CIS_Control 'CIS 18.4' -NIST_Control 'IA-5, SC-28' -MITRE_Technique 'T1003.001 (LSASS Memory)' -ISO27001_Control 'A.8.5' `
                -NIS2_Article 'Art.21(2)(i)' -NSA_Guidance 'NSA CSI: Mitigating Credential Theft' `
                -Recommendation 'Enable via GPO: Computer Configuration > Administrative Templates > System > Device Guard > "Turn On Virtualization Based Security" > Credential Guard Configuration = Enabled with UEFI lock. Requires VBS.'
        }
    } catch {
        Add-AuditResult -Category 'Virtualization-Based Security' -Control 'Credential Guard (LSASS Secrets Isolation)' `
            -Status 'WARN' -Severity 'Low' -CurrentValue 'Query failed' -RecommendedValue 'Running' `
            -Recommendation "Unable to query Credential Guard state: $($_.Exception.Message)"
    }
}

function Test-SystemGuard {
    <#
        Audits System Guard Secure Launch (hardware-rooted DRTM boot trust) and SMM Firmware
        Measurement, both surfaced as SecurityServicesRunning enum values 3 and 4.
    #>
    Write-SectionBanner 'Virtualization-Based Security - System Guard'
    try {
        $dg = Get-DeviceGuardStatus
        if (-not $dg) { throw 'Win32_DeviceGuard class unavailable' }

        $running = @()
        if ($dg.SecurityServicesRunning) { $running = $dg.SecurityServicesRunning }
        $secureLaunchRunning = $running -contains 3

        if ($secureLaunchRunning) {
            Add-AuditResult -Category 'Virtualization-Based Security' -Control 'System Guard Secure Launch (DRTM)' `
                -Status 'PASS' -Severity 'High' -CurrentValue 'Running' -RecommendedValue 'Running' `
                -CIS_Control 'CIS 10.5' -NIST_Control 'SI-7, SC-28' -MITRE_Technique 'T1542.001 (System Firmware)' -ISO27001_Control 'A.8.24' `
                -NIS2_Article 'Art.21(2)(d)' -NSA_Guidance 'NSA Hardening Guidance for Windows 11' -Recommendation 'No action required.'
        } else {
            Add-AuditResult -Category 'Virtualization-Based Security' -Control 'System Guard Secure Launch (DRTM)' `
                -Status 'WARN' -Severity 'Medium' -CurrentValue 'Not Running' -RecommendedValue 'Running (hardware-dependent)' `
                -CIS_Control 'CIS 10.5' -NIST_Control 'SI-7, SC-28' -MITRE_Technique 'T1542.001 (System Firmware)' -ISO27001_Control 'A.8.24' `
                -NIS2_Article 'Art.21(2)(d)' -NSA_Guidance 'NSA Hardening Guidance for Windows 11' `
                -Recommendation 'Enable "Turn On Virtualization Based Security" > Secure Launch Configuration = Enabled. Note: requires DRTM-capable firmware (Intel TXT / AMD SKINIT); not present on all hardware.'
        }
    } catch {
        Add-AuditResult -Category 'Virtualization-Based Security' -Control 'System Guard Secure Launch (DRTM)' `
            -Status 'WARN' -Severity 'Low' -CurrentValue 'Query failed' -RecommendedValue 'Running (hardware-dependent)' `
            -Recommendation "Unable to query System Guard state: $($_.Exception.Message)"
    }
}

function Test-LSAProtection {
    <#
        Audits LSA Protection (RunAsPPL), which runs LSASS as a Protected Process Light so
        that even an Administrator-context process cannot inject into or dump it without a
        signed, Microsoft-trusted protected-process driver.
    #>
    Write-SectionBanner 'Virtualization-Based Security - LSA Protection'
    try {
        $lsaPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
        $runAsPPL = Get-RegistryValueSafe -Path $lsaPath -Name 'RunAsPPL' -DefaultValue 0

        if ([int]$runAsPPL -ge 1) {
            $mode = if ([int]$runAsPPL -eq 2) { 'Enabled without UEFI lock' } else { 'Enabled with UEFI lock' }
            Add-AuditResult -Category 'Virtualization-Based Security' -Control 'LSA Protection (RunAsPPL)' `
                -Status 'PASS' -Severity 'Critical' -CurrentValue "RunAsPPL=$runAsPPL ($mode)" -RecommendedValue 'RunAsPPL=1' `
                -CIS_Control 'CIS 18.4' -NIST_Control 'SC-39, AC-6' -MITRE_Technique 'T1003.001 (LSASS Memory)' -ISO27001_Control 'A.8.5' `
                -NIS2_Article 'Art.21(2)(i)' -NSA_Guidance 'NSA CSI: Mitigating Credential Theft' -Recommendation 'No action required.'
        } else {
            Add-AuditResult -Category 'Virtualization-Based Security' -Control 'LSA Protection (RunAsPPL)' `
                -Status 'FAIL' -Severity 'Critical' -CurrentValue 'RunAsPPL=0 (Disabled)' -RecommendedValue 'RunAsPPL=1' `
                -CIS_Control 'CIS 18.4' -NIST_Control 'SC-39, AC-6' -MITRE_Technique 'T1003.001 (LSASS Memory)' -ISO27001_Control 'A.8.5' `
                -NIS2_Article 'Art.21(2)(i)' -NSA_Guidance 'NSA CSI: Mitigating Credential Theft' `
                -Recommendation 'Set HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL (DWORD) = 1, then reboot. Tools such as Mimikatz cannot read LSASS memory once this protection is active.'
        }
    } catch {
        Add-AuditResult -Category 'Virtualization-Based Security' -Control 'LSA Protection (RunAsPPL)' `
            -Status 'WARN' -Severity 'Low' -CurrentValue 'Query failed' -RecommendedValue 'RunAsPPL=1' `
            -Recommendation "Unable to query LSA Protection state: $($_.Exception.Message)"
    }
}

#endregion

#region ============================== 3. VOLUME ENCRYPTION & DATA-AT-REST SECURITY ==============================

function Test-BitLocker {
    <#
        Audits BitLocker Drive Encryption across every fixed volume: encryption state,
        cipher strength, key protector architecture (TPM/PIN/Recovery), and enforcement of
        pre-boot authentication.
    #>
    Write-SectionBanner 'Volume Encryption - BitLocker'
    try {
        $volumes = Get-BitLockerVolume -ErrorAction Stop
        if (-not $volumes -or $volumes.Count -eq 0) {
            Add-AuditResult -Category 'Volume Encryption & Data-at-Rest' -Control 'BitLocker Volume Enumeration' `
                -Status 'WARN' -Severity 'Medium' -CurrentValue 'No volumes returned' -RecommendedValue 'All fixed volumes encrypted' `
                -Recommendation 'BitLocker cmdlets returned no volumes. Confirm the BitLocker feature is installed (Enterprise/Education/Pro).'
            return
        }

        foreach ($vol in $volumes) {
            $mp = $vol.MountPoint
            $isOsVolume = $vol.VolumeType -eq 'OperatingSystem'
            $label = if ($isOsVolume) { "OS Volume ($mp)" } else { "Data Volume ($mp)" }

            # --- Encryption status & percentage ---
            if ($vol.VolumeStatus -eq 'FullyEncrypted' -and $vol.ProtectionStatus -eq 'On') {
                Add-AuditResult -Category 'Volume Encryption & Data-at-Rest' -Control "BitLocker Encryption Status - $label" `
                    -Status 'PASS' -Severity 'Critical' -CurrentValue "Status=$($vol.VolumeStatus); Protection=$($vol.ProtectionStatus); Encrypted=$($vol.EncryptionPercentage)%" `
                    -RecommendedValue 'FullyEncrypted; Protection On; 100%' -CIS_Control 'CIS 3.11' -NIST_Control 'SC-28, SC-12' `
                    -MITRE_Technique 'T1005 (Data from Local System)' -ISO27001_Control 'A.8.24' -NIS2_Article 'Art.21(2)(h)' `
                    -NSA_Guidance 'NSA CSI: Data-at-Rest Encryption Best Practices' -Recommendation 'No action required.'
            } elseif ($vol.VolumeStatus -eq 'EncryptionInProgress') {
                Add-AuditResult -Category 'Volume Encryption & Data-at-Rest' -Control "BitLocker Encryption Status - $label" `
                    -Status 'WARN' -Severity 'Medium' -CurrentValue "Status=EncryptionInProgress; $($vol.EncryptionPercentage)% complete" `
                    -RecommendedValue 'FullyEncrypted; 100%' -CIS_Control 'CIS 3.11' -NIST_Control 'SC-28, SC-12' -ISO27001_Control 'A.8.24' `
                    -NIS2_Article 'Art.21(2)(h)' -NSA_Guidance 'NSA CSI: Data-at-Rest Encryption Best Practices' `
                    -Recommendation 'Allow encryption to complete; do not interrupt power during the operation.'
            } else {
                Add-AuditResult -Category 'Volume Encryption & Data-at-Rest' -Control "BitLocker Encryption Status - $label" `
                    -Status 'FAIL' -Severity 'Critical' -CurrentValue "Status=$($vol.VolumeStatus); Protection=$($vol.ProtectionStatus)" `
                    -RecommendedValue 'FullyEncrypted; Protection On' -CIS_Control 'CIS 3.11' -NIST_Control 'SC-28, SC-12' `
                    -MITRE_Technique 'T1005 (Data from Local System)' -ISO27001_Control 'A.8.24' -NIS2_Article 'Art.21(2)(h)' `
                    -NSA_Guidance 'NSA CSI: Data-at-Rest Encryption Best Practices' `
                    -Recommendation "Enable BitLocker on $mp via 'manage-bde -on $mp -RecoveryPassword' or Control Panel > BitLocker Drive Encryption, and ensure protection is turned On."
            }

            # --- Cipher strength ---
            $method = $vol.EncryptionMethod
            if ($method -match 'XtsAes256') {
                Add-AuditResult -Category 'Volume Encryption & Data-at-Rest' -Control "BitLocker Cipher Strength - $label" `
                    -Status 'PASS' -Severity 'High' -CurrentValue "$method" -RecommendedValue 'XtsAes256' -CIS_Control 'CIS 3.11' `
                    -NIST_Control 'SC-13, SC-28' -ISO27001_Control 'A.8.24' -NIS2_Article 'Art.21(2)(h)' `
                    -NSA_Guidance 'NSA CSI: CNSA 2.0 Cryptographic Guidance' -Recommendation 'No action required.'
            } elseif ($method -match 'XtsAes128') {
                Add-AuditResult -Category 'Volume Encryption & Data-at-Rest' -Control "BitLocker Cipher Strength - $label" `
                    -Status 'WARN' -Severity 'Low' -CurrentValue "$method" -RecommendedValue 'XtsAes256' -CIS_Control 'CIS 3.11' `
                    -NIST_Control 'SC-13, SC-28' -ISO27001_Control 'A.8.24' -NIS2_Article 'Art.21(2)(h)' `
                    -NSA_Guidance 'NSA CSI: CNSA 2.0 Cryptographic Guidance' `
                    -Recommendation 'Set GPO "Choose drive encryption method and cipher strength" to XTS-AES 256-bit, then decrypt/re-encrypt the volume for the new method to apply.'
            } elseif ([string]::IsNullOrWhiteSpace($method) -or $method -eq 'None') {
                Add-AuditResult -Category 'Volume Encryption & Data-at-Rest' -Control "BitLocker Cipher Strength - $label" `
                    -Status 'INFO' -Severity 'Informational' -CurrentValue 'Not applicable (volume not encrypted)' -RecommendedValue 'XtsAes256' `
                    -Recommendation 'Resolve the encryption status finding above first.'
            } else {
                Add-AuditResult -Category 'Volume Encryption & Data-at-Rest' -Control "BitLocker Cipher Strength - $label" `
                    -Status 'FAIL' -Severity 'High' -CurrentValue "$method" -RecommendedValue 'XtsAes256' -CIS_Control 'CIS 3.11' `
                    -NIST_Control 'SC-13, SC-28' -ISO27001_Control 'A.8.24' -NIS2_Article 'Art.21(2)(h)' `
                    -NSA_Guidance 'NSA CSI: CNSA 2.0 Cryptographic Guidance' `
                    -Recommendation 'Legacy AES-CBC cipher in use. Re-encrypt using XTS-AES 256-bit via updated GPO policy.'
            }

            # --- Key protector architecture (OS volume only: expect TPM, and ideally TPM+PIN) ---
            if ($isOsVolume) {
                $protectorTypes = @($vol.KeyProtector | ForEach-Object { $_.KeyProtectorType })
                $hasTpm    = $protectorTypes -contains 'Tpm'
                $hasTpmPin = $protectorTypes -contains 'TpmPin'
                $hasRecovery = $protectorTypes -contains 'RecoveryPassword'

                if ($hasTpmPin) {
                    Add-AuditResult -Category 'Volume Encryption & Data-at-Rest' -Control 'BitLocker Key Protector Architecture (OS Volume)' `
                        -Status 'PASS' -Severity 'High' -CurrentValue ("Protectors: " + ($protectorTypes -join ', ')) -RecommendedValue 'TPM + PIN (pre-boot authentication)' `
                        -CIS_Control 'CIS 3.11' -NIST_Control 'IA-2, SC-28' -MITRE_Technique 'T1200 (Hardware Additions)' -ISO27001_Control 'A.8.24' `
                        -NIS2_Article 'Art.21(2)(h)' -NSA_Guidance 'NSA CSI: Data-at-Rest Encryption Best Practices' -Recommendation 'No action required.'
                } elseif ($hasTpm) {
                    Add-AuditResult -Category 'Volume Encryption & Data-at-Rest' -Control 'BitLocker Key Protector Architecture (OS Volume)' `
                        -Status 'WARN' -Severity 'Medium' -CurrentValue ("Protectors: " + ($protectorTypes -join ', ')) -RecommendedValue 'TPM + PIN (pre-boot authentication)' `
                        -CIS_Control 'CIS 3.11' -NIST_Control 'IA-2, SC-28' -ISO27001_Control 'A.8.24' -NIS2_Article 'Art.21(2)(h)' `
                        -NSA_Guidance 'NSA CSI: Data-at-Rest Encryption Best Practices' `
                        -Recommendation 'TPM-only protection is vulnerable to bootstrap/cold-boot style attacks against high-value assets. Add a pre-boot PIN via GPO "Require additional authentication at startup" and manage-bde -protectors -add -TPMAndPIN.'
                } else {
                    Add-AuditResult -Category 'Volume Encryption & Data-at-Rest' -Control 'BitLocker Key Protector Architecture (OS Volume)' `
                        -Status 'FAIL' -Severity 'High' -CurrentValue ("Protectors: " + (($protectorTypes -join ', ') -replace '^$','None')) -RecommendedValue 'TPM + PIN (pre-boot authentication)' `
                        -CIS_Control 'CIS 3.11' -NIST_Control 'IA-2, SC-28' -ISO27001_Control 'A.8.24' -NIS2_Article 'Art.21(2)(h)' `
                        -NSA_Guidance 'NSA CSI: Data-at-Rest Encryption Best Practices' `
                        -Recommendation 'No TPM-based key protector is bound. Add one via manage-bde -protectors -add C: -TPMAndPIN, and ensure the TPM is enabled/owned.'
                }

                if ($hasRecovery) {
                    Add-AuditResult -Category 'Volume Encryption & Data-at-Rest' -Control 'BitLocker Recovery Key Backup (OS Volume)' `
                        -Status 'PASS' -Severity 'Medium' -CurrentValue 'Recovery password protector present' -RecommendedValue 'Recovery password escrowed to AD/Entra ID or printed/stored securely' `
                        -CIS_Control 'CIS 3.11' -NIST_Control 'CP-9, SC-28' -ISO27001_Control 'A.8.13' -NIS2_Article 'Art.21(2)(c)' `
                        -NSA_Guidance 'NSA CSI: Data-at-Rest Encryption Best Practices' `
                        -Recommendation 'Confirm the recovery key is also escrowed centrally (Entra ID / Active Directory / MBAM) and not solely local, so IT can recover the volume if the PIN/TPM path fails.'
                } else {
                    Add-AuditResult -Category 'Volume Encryption & Data-at-Rest' -Control 'BitLocker Recovery Key Backup (OS Volume)' `
                        -Status 'FAIL' -Severity 'Medium' -CurrentValue 'No recovery password protector found' -RecommendedValue 'Recovery password escrowed centrally' `
                        -CIS_Control 'CIS 3.11' -NIST_Control 'CP-9, SC-28' -ISO27001_Control 'A.8.13' -NIS2_Article 'Art.21(2)(c)' `
                        -NSA_Guidance 'NSA CSI: Data-at-Rest Encryption Best Practices' `
                        -Recommendation 'Generate and escrow a recovery key: manage-bde -protectors -add C: -RecoveryPassword, then back it up to Entra ID/AD via GPO "Store BitLocker recovery information in Active Directory Domain Services" or Entra ID device-based escrow.'
                }
            }
        }
    } catch {
        Add-AuditResult -Category 'Volume Encryption & Data-at-Rest' -Control 'BitLocker Volume Enumeration' `
            -Status 'WARN' -Severity 'Low' -CurrentValue 'Query failed' -RecommendedValue 'All fixed volumes encrypted' `
            -Recommendation "Unable to query BitLocker status: $($_.Exception.Message). Confirm the BitLocker feature/module is present."
    }
}

#endregion

#region ============================== 4. NEXT-GEN ANTIVIRUS & EDR ==============================

function Get-DefenderStatusCache {
    if ($null -eq $Script:MpStatusCache) {
        try { $Script:MpStatusCache = Get-MpComputerStatus -ErrorAction Stop } catch { $Script:MpStatusCache = $false }
    }
    return $Script:MpStatusCache
}

function Get-DefenderPreferenceCache {
    if ($null -eq $Script:MpPrefCache) {
        try { $Script:MpPrefCache = Get-MpPreference -ErrorAction Stop } catch { $Script:MpPrefCache = $false }
    }
    return $Script:MpPrefCache
}

function Test-DefenderRealTimeProtection {
    <#
        Audits Microsoft Defender Antivirus real-time monitoring, behavior monitoring,
        IOAV (downloaded file/attachment) protection, and script scanning (which backs AMSI
        inspection for PowerShell/VBScript/JScript).
    #>
    Write-SectionBanner 'Next-Gen Antivirus & EDR - Real-Time Protection'
    try {
        $status = Get-DefenderStatusCache
        $pref = Get-DefenderPreferenceCache
        if (-not $status) { throw 'Get-MpComputerStatus unavailable - Defender may be replaced by a third-party AV' }

        $checks = @(
            @{ Name = 'Real-Time Monitoring'; Value = $status.RealTimeProtectionEnabled; Mitre = 'T1562.001 (Disable or Modify Tools)' }
            @{ Name = 'Behavior Monitoring';  Value = $status.BehaviorMonitorEnabled;   Mitre = 'T1562.001 (Disable or Modify Tools)' }
            @{ Name = 'IOAV (Downloads/Attachments) Protection'; Value = $status.IoavProtectionEnabled; Mitre = 'T1204 (User Execution)' }
            @{ Name = 'On-Access Protection'; Value = $status.OnAccessProtectionEnabled; Mitre = 'T1204 (User Execution)' }
        )
        foreach ($c in $checks) {
            if ($c.Value -eq $true) {
                Add-AuditResult -Category 'Next-Gen Antivirus & EDR' -Control "Defender $($c.Name)" -Status 'PASS' -Severity 'Critical' `
                    -CurrentValue 'Enabled' -RecommendedValue 'Enabled' -CIS_Control 'CIS 10.1' -NIST_Control 'SI-3, SI-4' -MITRE_Technique $c.Mitre `
                    -ISO27001_Control 'A.8.7' -NIS2_Article 'Art.21(2)(b)' -NSA_Guidance 'NSA/CISA Guidance on Endpoint Detection and Response' `
                    -Recommendation 'No action required.'
            } else {
                Add-AuditResult -Category 'Next-Gen Antivirus & EDR' -Control "Defender $($c.Name)" -Status 'FAIL' -Severity 'Critical' `
                    -CurrentValue 'Disabled' -RecommendedValue 'Enabled' -CIS_Control 'CIS 10.1' -NIST_Control 'SI-3, SI-4' -MITRE_Technique $c.Mitre `
                    -ISO27001_Control 'A.8.7' -NIS2_Article 'Art.21(2)(b)' -NSA_Guidance 'NSA/CISA Guidance on Endpoint Detection and Response' `
                    -Recommendation "Enable via Set-MpPreference or Windows Security > Virus & threat protection settings. If centrally managed, verify Intune/GPO Defender policy is applying."
            }
        }

        if ($pref) {
            if ($pref.DisableScriptScanning -eq $false -or $null -eq $pref.DisableScriptScanning) {
                Add-AuditResult -Category 'Next-Gen Antivirus & EDR' -Control 'AMSI Script Scanning' -Status 'PASS' -Severity 'High' `
                    -CurrentValue 'Script scanning enabled (AMSI active)' -RecommendedValue 'Enabled' -CIS_Control 'CIS 10.1' -NIST_Control 'SI-3' `
                    -MITRE_Technique 'T1059 (Command and Scripting Interpreter), T1027 (Obfuscated Files or Information)' -ISO27001_Control 'A.8.7' `
                    -NIS2_Article 'Art.21(2)(b)' -NSA_Guidance 'NSA/CISA Guidance on Endpoint Detection and Response' -Recommendation 'No action required.'
            } else {
                Add-AuditResult -Category 'Next-Gen Antivirus & EDR' -Control 'AMSI Script Scanning' -Status 'FAIL' -Severity 'High' `
                    -CurrentValue 'Script scanning disabled' -RecommendedValue 'Enabled' -CIS_Control 'CIS 10.1' -NIST_Control 'SI-3' `
                    -MITRE_Technique 'T1059 (Command and Scripting Interpreter), T1027 (Obfuscated Files or Information)' -ISO27001_Control 'A.8.7' `
                    -NIS2_Article 'Art.21(2)(b)' -NSA_Guidance 'NSA/CISA Guidance on Endpoint Detection and Response' `
                    -Recommendation 'Run Set-MpPreference -DisableScriptScanning $false to restore AMSI-backed script inspection for PowerShell/JScript/VBScript.'
            }
        }
    } catch {
        Add-AuditResult -Category 'Next-Gen Antivirus & EDR' -Control 'Defender Real-Time Monitoring' -Status 'WARN' -Severity 'Medium' `
            -CurrentValue 'Unavailable' -RecommendedValue 'Enabled' -Recommendation "Microsoft Defender status could not be queried ($($_.Exception.Message)). If a third-party AV/EDR is the primary provider, verify its real-time protection is enabled through its own console."
    }
}

function Test-DefenderCloudProtection {
    <#
        Audits cloud-delivered protection level, automatic sample submission, and cloud
        block-at-first-sight configuration, which extend detection beyond local signatures.
    #>
    Write-SectionBanner 'Next-Gen Antivirus & EDR - Cloud Intelligence'
    try {
        $status = Get-DefenderStatusCache
        $pref = Get-DefenderPreferenceCache
        if (-not $status) { throw 'Defender status unavailable' }

        if ($status.AMServiceEnabled -and $status.AntispywareEnabled) {
            # MAPS/cloud reporting level: 0=Disabled, 1=Basic, 2=Advanced
            $mapsLevel = if ($pref) { $pref.MAPSReporting } else { $null }
            if ($mapsLevel -eq 2) {
                Add-AuditResult -Category 'Next-Gen Antivirus & EDR' -Control 'Cloud-Delivered Protection (MAPS)' -Status 'PASS' -Severity 'High' `
                    -CurrentValue 'Advanced membership' -RecommendedValue 'Advanced membership' -CIS_Control 'CIS 10.1' -NIST_Control 'SI-3, SI-4' `
                    -MITRE_Technique 'T1027 (Obfuscated Files or Information)' -ISO27001_Control 'A.8.7' -NIS2_Article 'Art.21(2)(b)' `
                    -NSA_Guidance 'NSA/CISA Guidance on Endpoint Detection and Response' -Recommendation 'No action required.'
            } elseif ($mapsLevel -eq 1) {
                Add-AuditResult -Category 'Next-Gen Antivirus & EDR' -Control 'Cloud-Delivered Protection (MAPS)' -Status 'WARN' -Severity 'Medium' `
                    -CurrentValue 'Basic membership' -RecommendedValue 'Advanced membership' -CIS_Control 'CIS 10.1' -NIST_Control 'SI-3, SI-4' `
                    -ISO27001_Control 'A.8.7' -NIS2_Article 'Art.21(2)(b)' -NSA_Guidance 'NSA/CISA Guidance on Endpoint Detection and Response' `
                    -Recommendation 'Set-MpPreference -MAPSReporting Advanced for the fullest telemetry-driven cloud detection.'
            } else {
                Add-AuditResult -Category 'Next-Gen Antivirus & EDR' -Control 'Cloud-Delivered Protection (MAPS)' -Status 'FAIL' -Severity 'High' `
                    -CurrentValue 'Disabled / Not Configured' -RecommendedValue 'Advanced membership' -CIS_Control 'CIS 10.1' -NIST_Control 'SI-3, SI-4' `
                    -ISO27001_Control 'A.8.7' -NIS2_Article 'Art.21(2)(b)' -NSA_Guidance 'NSA/CISA Guidance on Endpoint Detection and Response' `
                    -Recommendation 'Set-MpPreference -MAPSReporting Advanced. Cloud protection materially reduces detection latency for novel malware.'
            }
        }

        if ($pref) {
            # SubmitSamplesConsent: 0=Always Ask, 1=Send Safe Samples Automatically, 2=Never Send, 3=Send All Automatically
            $consent = $pref.SubmitSamplesConsent
            if ($consent -eq 1 -or $consent -eq 3) {
                Add-AuditResult -Category 'Next-Gen Antivirus & EDR' -Control 'Automatic Sample Submission' -Status 'PASS' -Severity 'Medium' `
                    -CurrentValue "SubmitSamplesConsent=$consent" -RecommendedValue '1 (Safe samples automatically) or 3 (All automatically)' `
                    -CIS_Control 'CIS 10.1' -NIST_Control 'SI-4' -ISO27001_Control 'A.8.7' -NIS2_Article 'Art.21(2)(b)' `
                    -NSA_Guidance 'NSA/CISA Guidance on Endpoint Detection and Response' -Recommendation 'No action required.'
            } elseif ($consent -eq 2) {
                Add-AuditResult -Category 'Next-Gen Antivirus & EDR' -Control 'Automatic Sample Submission' -Status 'FAIL' -Severity 'Medium' `
                    -CurrentValue 'Never Send (2)' -RecommendedValue '1 (Safe samples automatically)' -CIS_Control 'CIS 10.1' -NIST_Control 'SI-4' `
                    -ISO27001_Control 'A.8.7' -NIS2_Article 'Art.21(2)(b)' -NSA_Guidance 'NSA/CISA Guidance on Endpoint Detection and Response' `
                    -Recommendation 'Set-MpPreference -SubmitSamplesConsent SendSafeSamples so novel threats can be analyzed by Microsoft threat intelligence.'
            } else {
                Add-AuditResult -Category 'Next-Gen Antivirus & EDR' -Control 'Automatic Sample Submission' -Status 'WARN' -Severity 'Low' `
                    -CurrentValue "SubmitSamplesConsent=$consent (Always Ask)" -RecommendedValue '1 (Safe samples automatically)' `
                    -CIS_Control 'CIS 10.1' -NIST_Control 'SI-4' -ISO27001_Control 'A.8.7' -NIS2_Article 'Art.21(2)(b)' `
                    -Recommendation 'Configure automatic submission so unattended endpoints still contribute telemetry.'
            }

            # CloudBlockLevel: 0=Default, 2=Moderate, 4=High, 6=High+, 8=ZeroTolerance
            if ($pref.CloudBlockLevel -ge 2) {
                Add-AuditResult -Category 'Next-Gen Antivirus & EDR' -Control 'Cloud Block-at-First-Sight Level' -Status 'PASS' -Severity 'Medium' `
                    -CurrentValue "CloudBlockLevel=$($pref.CloudBlockLevel)" -RecommendedValue '>=2 (Moderate or higher)' -CIS_Control 'CIS 10.1' `
                    -NIST_Control 'SI-3' -ISO27001_Control 'A.8.7' -NIS2_Article 'Art.21(2)(b)' -Recommendation 'No action required.'
            } else {
                Add-AuditResult -Category 'Next-Gen Antivirus & EDR' -Control 'Cloud Block-at-First-Sight Level' -Status 'WARN' -Severity 'Low' `
                    -CurrentValue "CloudBlockLevel=$($pref.CloudBlockLevel) (Default)" -RecommendedValue '>=2 (Moderate or higher)' `
                    -CIS_Control 'CIS 10.1' -NIST_Control 'SI-3' -ISO27001_Control 'A.8.7' -NIS2_Article 'Art.21(2)(b)' `
                    -Recommendation 'Set-MpPreference -CloudBlockLevel High to increase aggressiveness of cloud-based blocking for suspicious files.'
            }
        }
    } catch {
        Add-AuditResult -Category 'Next-Gen Antivirus & EDR' -Control 'Cloud-Delivered Protection (MAPS)' -Status 'WARN' -Severity 'Low' `
            -CurrentValue 'Unavailable' -Recommendation "Unable to query cloud protection preferences: $($_.Exception.Message)"
    }
}

function Test-DefenderHealthAndSignatures {
    <#
        Audits signature/engine freshness and overall antimalware platform health.
    #>
    Write-SectionBanner 'Next-Gen Antivirus & EDR - Sensor Freshness & Health'
    try {
        $status = Get-DefenderStatusCache
        if (-not $status) { throw 'Defender status unavailable' }

        $avAge = $status.AntivirusSignatureAge
        if ($null -ne $avAge -and [int]$avAge -le 1) {
            Add-AuditResult -Category 'Next-Gen Antivirus & EDR' -Control 'Antivirus Signature Freshness' -Status 'PASS' -Severity 'High' `
                -CurrentValue "$avAge day(s) old" -RecommendedValue '<= 1 day old' -CIS_Control 'CIS 10.1' -NIST_Control 'SI-3' `
                -MITRE_Technique 'T1562.001 (Disable or Modify Tools)' -ISO27001_Control 'A.8.7' -NIS2_Article 'Art.21(2)(b)' `
                -NSA_Guidance 'NSA/CISA Guidance on Endpoint Detection and Response' -Recommendation 'No action required.'
        } elseif ($null -ne $avAge -and [int]$avAge -le 7) {
            Add-AuditResult -Category 'Next-Gen Antivirus & EDR' -Control 'Antivirus Signature Freshness' -Status 'WARN' -Severity 'Medium' `
                -CurrentValue "$avAge day(s) old" -RecommendedValue '<= 1 day old' -CIS_Control 'CIS 10.1' -NIST_Control 'SI-3' -ISO27001_Control 'A.8.7' `
                -NIS2_Article 'Art.21(2)(b)' -Recommendation 'Run Update-MpSignature or verify connectivity to Microsoft Update / WSUS signature distribution point.'
        } else {
            Add-AuditResult -Category 'Next-Gen Antivirus & EDR' -Control 'Antivirus Signature Freshness' -Status 'FAIL' -Severity 'High' `
                -CurrentValue "$avAge day(s) old" -RecommendedValue '<= 1 day old' -CIS_Control 'CIS 10.1' -NIST_Control 'SI-3' `
                -MITRE_Technique 'T1562.001 (Disable or Modify Tools)' -ISO27001_Control 'A.8.7' -NIS2_Article 'Art.21(2)(b)' `
                -NSA_Guidance 'NSA/CISA Guidance on Endpoint Detection and Response' `
                -Recommendation 'Signatures are critically stale. Run Update-MpSignature immediately and investigate update distribution failures.'
        }

        if ($status.AMServiceEnabled -and $status.AMEngineVersion) {
            Add-AuditResult -Category 'Next-Gen Antivirus & EDR' -Control 'Antimalware Engine & Platform Health' -Status 'PASS' -Severity 'Medium' `
                -CurrentValue "Engine=$($status.AMEngineVersion); Platform=$($status.AMProductVersion)" -RecommendedValue 'Service running, current engine/platform' `
                -CIS_Control 'CIS 10.1' -NIST_Control 'SI-3' -ISO27001_Control 'A.8.7' -NIS2_Article 'Art.21(2)(b)' -Recommendation 'No action required.'
        } else {
            Add-AuditResult -Category 'Next-Gen Antivirus & EDR' -Control 'Antimalware Engine & Platform Health' -Status 'FAIL' -Severity 'Critical' `
                -CurrentValue 'AM service not enabled/reporting' -RecommendedValue 'Service running, current engine/platform' -CIS_Control 'CIS 10.1' `
                -NIST_Control 'SI-3' -MITRE_Technique 'T1562.001 (Disable or Modify Tools)' -ISO27001_Control 'A.8.7' -NIS2_Article 'Art.21(2)(b)' `
                -Recommendation 'Verify the Windows Defender Antivirus Service (WinDefend) is running: Start-Service WinDefend, and confirm no third-party AV has taken exclusive registration.'
        }
    } catch {
        Add-AuditResult -Category 'Next-Gen Antivirus & EDR' -Control 'Antivirus Signature Freshness' -Status 'WARN' -Severity 'Low' `
            -CurrentValue 'Unavailable' -Recommendation "Unable to query signature/engine health: $($_.Exception.Message)"
    }
}

function Test-DefenderTamperAndPUA {
    <#
        Audits Tamper Protection (blocks unauthorized changes to Defender configuration,
        including by local admins/scripts) and Potentially Unwanted Application blocking.
    #>
    Write-SectionBanner 'Next-Gen Antivirus & EDR - Tamper Resistance & PUA'
    try {
        $status = Get-DefenderStatusCache
        $pref = Get-DefenderPreferenceCache

        if ($status -and ($status.PSObject.Properties.Name -contains 'IsTamperProtected')) {
            if ($status.IsTamperProtected) {
                Add-AuditResult -Category 'Next-Gen Antivirus & EDR' -Control 'Tamper Protection' -Status 'PASS' -Severity 'Critical' `
                    -CurrentValue 'Enabled' -RecommendedValue 'Enabled' -CIS_Control 'CIS 10.1' -NIST_Control 'SI-3, CM-5' `
                    -MITRE_Technique 'T1562.001 (Disable or Modify Tools)' -ISO27001_Control 'A.8.7' -NIS2_Article 'Art.21(2)(b)' `
                    -NSA_Guidance 'NSA/CISA Guidance on Endpoint Detection and Response' -Recommendation 'No action required.'
            } else {
                Add-AuditResult -Category 'Next-Gen Antivirus & EDR' -Control 'Tamper Protection' -Status 'FAIL' -Severity 'Critical' `
                    -CurrentValue 'Disabled' -RecommendedValue 'Enabled' -CIS_Control 'CIS 10.1' -NIST_Control 'SI-3, CM-5' `
                    -MITRE_Technique 'T1562.001 (Disable or Modify Tools)' -ISO27001_Control 'A.8.7' -NIS2_Article 'Art.21(2)(b)' `
                    -NSA_Guidance 'NSA/CISA Guidance on Endpoint Detection and Response' `
                    -Recommendation 'Enable Tamper Protection via Windows Security > Virus & threat protection settings, Intune "Tamper Protection" policy, or Microsoft 365 Defender portal.'
            }
        } else {
            Add-AuditResult -Category 'Next-Gen Antivirus & EDR' -Control 'Tamper Protection' -Status 'INFO' -Severity 'Informational' `
                -CurrentValue 'Not reported by this OS build' -RecommendedValue 'Enabled' -Recommendation 'Verify Tamper Protection status directly in Windows Security if not surfaced by Get-MpComputerStatus on this build.'
        }

        if ($pref) {
            # PUAProtection: 0=Off, 1=On, 2=Audit Mode
            switch ($pref.PUAProtection) {
                1 {
                    Add-AuditResult -Category 'Next-Gen Antivirus & EDR' -Control 'Potentially Unwanted Application (PUA) Protection' -Status 'PASS' -Severity 'Medium' `
                        -CurrentValue 'On' -RecommendedValue 'On' -CIS_Control 'CIS 10.1' -NIST_Control 'SI-3' -MITRE_Technique 'T1204 (User Execution)' `
                        -ISO27001_Control 'A.8.7' -NIS2_Article 'Art.21(2)(b)' -Recommendation 'No action required.'
                }
                2 {
                    Add-AuditResult -Category 'Next-Gen Antivirus & EDR' -Control 'Potentially Unwanted Application (PUA) Protection' -Status 'WARN' -Severity 'Low' `
                        -CurrentValue 'Audit Mode' -RecommendedValue 'On' -CIS_Control 'CIS 10.1' -NIST_Control 'SI-3' -ISO27001_Control 'A.8.7' `
                        -NIS2_Article 'Art.21(2)(b)' -Recommendation 'Set-MpPreference -PUAProtection Enabled to move from audit to enforced blocking.'
                }
                default {
                    Add-AuditResult -Category 'Next-Gen Antivirus & EDR' -Control 'Potentially Unwanted Application (PUA) Protection' -Status 'FAIL' -Severity 'Medium' `
                        -CurrentValue 'Off' -RecommendedValue 'On' -CIS_Control 'CIS 10.1' -NIST_Control 'SI-3' -MITRE_Technique 'T1204 (User Execution)' `
                        -ISO27001_Control 'A.8.7' -NIS2_Article 'Art.21(2)(b)' -Recommendation 'Set-MpPreference -PUAProtection Enabled to block adware/bundleware/browser hijackers.'
                }
            }
        }
    } catch {
        Add-AuditResult -Category 'Next-Gen Antivirus & EDR' -Control 'Tamper Protection' -Status 'WARN' -Severity 'Low' `
            -CurrentValue 'Unavailable' -Recommendation "Unable to query tamper/PUA state: $($_.Exception.Message)"
    }
}

function Test-MDEOnboarding {
    <#
        Audits Microsoft Defender for Endpoint (MDE) onboarding state and the health of the
        Sense sensor service, which carries EDR telemetry to the Defender cloud back end.
    #>
    Write-SectionBanner 'Next-Gen Antivirus & EDR - MDE / EDR Integration'
    try {
        $onboardPath = 'HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status'
        $onboardState = Get-RegistryValueSafe -Path $onboardPath -Name 'OnboardingState' -DefaultValue $null

        $senseService = Get-Service -Name 'Sense' -ErrorAction SilentlyContinue

        if ($onboardState -eq 1 -and $senseService -and $senseService.Status -eq 'Running') {
            Add-AuditResult -Category 'Next-Gen Antivirus & EDR' -Control 'Microsoft Defender for Endpoint (MDE) Onboarding' -Status 'PASS' -Severity 'High' `
                -CurrentValue "OnboardingState=1; Sense Service=Running" -RecommendedValue 'Onboarded; Sense service Running' -CIS_Control 'CIS 8.2' `
                -NIST_Control 'SI-4, AU-6' -MITRE_Technique 'T1562.001 (Disable or Modify Tools)' -ISO27001_Control 'A.8.16' -NIS2_Article 'Art.21(2)(b)' `
                -NSA_Guidance 'NSA/CISA Guidance on Endpoint Detection and Response' -Recommendation 'No action required.'
        } elseif ($onboardState -eq 1 -and (-not $senseService -or $senseService.Status -ne 'Running')) {
            Add-AuditResult -Category 'Next-Gen Antivirus & EDR' -Control 'Microsoft Defender for Endpoint (MDE) Onboarding' -Status 'FAIL' -Severity 'High' `
                -CurrentValue 'Onboarded, but Sense service not running' -RecommendedValue 'Onboarded; Sense service Running' -CIS_Control 'CIS 8.2' `
                -NIST_Control 'SI-4, AU-6' -MITRE_Technique 'T1562.001 (Disable or Modify Tools)' -ISO27001_Control 'A.8.16' -NIS2_Article 'Art.21(2)(b)' `
                -NSA_Guidance 'NSA/CISA Guidance on Endpoint Detection and Response' `
                -Recommendation 'Start the Sense service: Start-Service Sense. If it fails to start, review Event Viewer > Applications and Services Logs > Microsoft > Windows > SENSE for the root cause.'
        } else {
            Add-AuditResult -Category 'Next-Gen Antivirus & EDR' -Control 'Microsoft Defender for Endpoint (MDE) Onboarding' -Status 'WARN' -Severity 'Medium' `
                -CurrentValue 'Not Onboarded to MDE' -RecommendedValue 'Onboarded via Intune/GPO/local script' -CIS_Control 'CIS 8.2' -NIST_Control 'SI-4, AU-6' `
                -ISO27001_Control 'A.8.16' -NIS2_Article 'Art.21(2)(b)' -NSA_Guidance 'NSA/CISA Guidance on Endpoint Detection and Response' `
                -Recommendation 'Onboard the device to Microsoft Defender for Endpoint via Intune configuration profile, GPO, or the onboarding script from the Microsoft 365 Defender portal, so centralized EDR telemetry and response actions are available for this endpoint.'
        }
    } catch {
        Add-AuditResult -Category 'Next-Gen Antivirus & EDR' -Control 'Microsoft Defender for Endpoint (MDE) Onboarding' -Status 'WARN' -Severity 'Low' `
            -CurrentValue 'Query failed' -Recommendation "Unable to determine MDE onboarding state: $($_.Exception.Message)"
    }
}

#endregion

#region ============================== 5. ATTACK SURFACE REDUCTION & EXPLOIT PREVENTION ==============================

function Test-ASRRules {
    <#
        Audits the configured state of every Microsoft Defender Attack Surface Reduction
        rule (Block / Audit / Warn / Disabled), with explicit elevated-severity handling for
        the subset of rules covering credential theft, Office macro/child-process abuse,
        script obfuscation, and ransomware behavior.
    #>
    Write-SectionBanner 'Attack Surface Reduction - ASR Rules'
    try {
        $pref = Get-DefenderPreferenceCache
        if (-not $pref) { throw 'Defender preferences unavailable' }

        $ids = @()
        $actions = @()
        if ($pref.AttackSurfaceReductionRules_Ids)    { $ids = @($pref.AttackSurfaceReductionRules_Ids) }
        if ($pref.AttackSurfaceReductionRules_Actions) { $actions = @($pref.AttackSurfaceReductionRules_Actions) }

        if ($ids.Count -eq 0) {
            Add-AuditResult -Category 'Attack Surface Reduction & Exploit Prevention' -Control 'ASR Rules - Overall Configuration' `
                -Status 'FAIL' -Severity 'High' -CurrentValue 'No ASR rules configured' -RecommendedValue 'All applicable rules set to Block (1)' `
                -CIS_Control 'CIS 10.1' -NIST_Control 'SI-3, CM-7' -MITRE_Technique 'T1204, T1059, T1055' -ISO27001_Control 'A.8.7' `
                -NIS2_Article 'Art.21(2)(b)' -NSA_Guidance 'NSA CSI: Reduce Attack Surface with ASR Rules' `
                -Recommendation 'Deploy ASR rules in Block mode via Intune Endpoint Security > Attack Surface Reduction policy, or Set-MpPreference -AttackSurfaceReductionRules_Ids <GUID> -AttackSurfaceReductionRules_Actions Enabled.'
        } else {
            $actionMap = @{ 0 = 'Disabled'; 1 = 'Block'; 2 = 'Audit'; 6 = 'Warn' }
            for ($i = 0; $i -lt $ids.Count; $i++) {
                $guid = $ids[$i].ToString().ToLower()
                $action = if ($i -lt $actions.Count) { [int]$actions[$i] } else { 0 }
                $actionDesc = $actionMap[$action]
                if (-not $actionDesc) { $actionDesc = "Unknown ($action)" }
                $friendlyName = $Script:ASRRuleMap[$guid]
                if (-not $friendlyName) { $friendlyName = "Unmapped rule ($guid)" }
                $isCritical = $Script:CriticalASRRules -contains $guid
                $severity = if ($isCritical) { 'High' } else { 'Medium' }

                if ($action -eq 1) {
                    Add-AuditResult -Category 'Attack Surface Reduction & Exploit Prevention' -Control "ASR Rule: $friendlyName" `
                        -Status 'PASS' -Severity $severity -CurrentValue 'Block' -RecommendedValue 'Block' -CIS_Control 'CIS 10.1' `
                        -NIST_Control 'SI-3, CM-7' -MITRE_Technique 'T1204, T1059, T1055, T1003.001' -ISO27001_Control 'A.8.7' `
                        -NIS2_Article 'Art.21(2)(b)' -NSA_Guidance 'NSA CSI: Reduce Attack Surface with ASR Rules' -Recommendation 'No action required.'
                } elseif ($action -eq 2 -or $action -eq 6) {
                    Add-AuditResult -Category 'Attack Surface Reduction & Exploit Prevention' -Control "ASR Rule: $friendlyName" `
                        -Status 'WARN' -Severity $severity -CurrentValue $actionDesc -RecommendedValue 'Block' -CIS_Control 'CIS 10.1' `
                        -NIST_Control 'SI-3, CM-7' -MITRE_Technique 'T1204, T1059, T1055, T1003.001' -ISO27001_Control 'A.8.7' `
                        -NIS2_Article 'Art.21(2)(b)' -NSA_Guidance 'NSA CSI: Reduce Attack Surface with ASR Rules' `
                        -Recommendation "Rule is in Audit/Warn mode. Review Defender ASR audit events (Event ID 1121) for false positives, then promote to Block via Intune or Set-MpPreference -AttackSurfaceReductionRules_Actions Enabled."
                } else {
                    Add-AuditResult -Category 'Attack Surface Reduction & Exploit Prevention' -Control "ASR Rule: $friendlyName" `
                        -Status 'FAIL' -Severity $severity -CurrentValue $actionDesc -RecommendedValue 'Block' -CIS_Control 'CIS 10.1' `
                        -NIST_Control 'SI-3, CM-7' -MITRE_Technique 'T1204, T1059, T1055, T1003.001' -ISO27001_Control 'A.8.7' `
                        -NIS2_Article 'Art.21(2)(b)' -NSA_Guidance 'NSA CSI: Reduce Attack Surface with ASR Rules' `
                        -Recommendation "Enable this rule in Block mode via Intune ASR policy or Add-MpPreference -AttackSurfaceReductionRules_Ids $guid -AttackSurfaceReductionRules_Actions Enabled."
                }
            }

            # Flag critical rules that are entirely absent from the configured set.
            $configuredGuids = $ids | ForEach-Object { $_.ToString().ToLower() }
            foreach ($criticalGuid in $Script:CriticalASRRules) {
                if ($configuredGuids -notcontains $criticalGuid) {
                    $friendlyName = $Script:ASRRuleMap[$criticalGuid]
                    Add-AuditResult -Category 'Attack Surface Reduction & Exploit Prevention' -Control "ASR Rule: $friendlyName" `
                        -Status 'FAIL' -Severity 'High' -CurrentValue 'Not Configured' -RecommendedValue 'Block' -CIS_Control 'CIS 10.1' `
                        -NIST_Control 'SI-3, CM-7' -MITRE_Technique 'T1204, T1059, T1055, T1003.001' -ISO27001_Control 'A.8.7' `
                        -NIS2_Article 'Art.21(2)(b)' -NSA_Guidance 'NSA CSI: Reduce Attack Surface with ASR Rules' `
                        -Recommendation "This high-value rule is not configured at all. Add-MpPreference -AttackSurfaceReductionRules_Ids $criticalGuid -AttackSurfaceReductionRules_Actions Enabled."
                }
            }
        }
    } catch {
        Add-AuditResult -Category 'Attack Surface Reduction & Exploit Prevention' -Control 'ASR Rules - Overall Configuration' `
            -Status 'WARN' -Severity 'Low' -CurrentValue 'Query failed' -Recommendation "Unable to query ASR rule configuration: $($_.Exception.Message)"
    }
}

function Test-ExploitProtection {
    <#
        Audits system-wide Exploit Protection mitigations (DEP, ASLR bottom-up/high-entropy,
        Control Flow Guard, Heap corruption termination) via Get-ProcessMitigation -System.
    #>
    Write-SectionBanner 'Attack Surface Reduction - System-Wide Exploit Mitigations'
    try {
        $mitigations = Get-ProcessMitigation -System -ErrorAction Stop

        $depEnabled = $mitigations.DEP.Enable -eq 'ON' -or $mitigations.DEP.Enable -eq $true
        if ($depEnabled) {
            Add-AuditResult -Category 'Attack Surface Reduction & Exploit Prevention' -Control 'Data Execution Prevention (DEP)' -Status 'PASS' -Severity 'High' `
                -CurrentValue 'Enabled' -RecommendedValue 'Enabled' -CIS_Control 'CIS 10.1' -NIST_Control 'SI-16, SC-39' `
                -MITRE_Technique 'T1055 (Process Injection), T1203 (Exploitation for Client Execution)' -ISO27001_Control 'A.8.7' -NIS2_Article 'Art.21(2)(b)' `
                -NSA_Guidance 'NSA Hardening Guidance for Windows 11' -Recommendation 'No action required.'
        } else {
            Add-AuditResult -Category 'Attack Surface Reduction & Exploit Prevention' -Control 'Data Execution Prevention (DEP)' -Status 'FAIL' -Severity 'High' `
                -CurrentValue 'Disabled' -RecommendedValue 'Enabled' -CIS_Control 'CIS 10.1' -NIST_Control 'SI-16, SC-39' `
                -MITRE_Technique 'T1055 (Process Injection)' -ISO27001_Control 'A.8.7' -NIS2_Article 'Art.21(2)(b)' `
                -NSA_Guidance 'NSA Hardening Guidance for Windows 11' -Recommendation 'Set-ProcessMitigation -System -Enable DEP, or enable via Exploit Protection settings > Program settings > System settings.'
        }

        $aslrBottomUp = $mitigations.ASLR.BottomUp -eq 'ON' -or $mitigations.ASLR.BottomUp -eq $true
        $aslrHighEntropy = $mitigations.ASLR.HighEntropy -eq 'ON' -or $mitigations.ASLR.HighEntropy -eq $true
        if ($aslrBottomUp -and $aslrHighEntropy) {
            Add-AuditResult -Category 'Attack Surface Reduction & Exploit Prevention' -Control 'Address Space Layout Randomization (ASLR)' -Status 'PASS' -Severity 'High' `
                -CurrentValue 'Bottom-Up=On; High-Entropy=On' -RecommendedValue 'Bottom-Up=On; High-Entropy=On' -CIS_Control 'CIS 10.1' `
                -NIST_Control 'SI-16, SC-39' -MITRE_Technique 'T1055 (Process Injection)' -ISO27001_Control 'A.8.7' -NIS2_Article 'Art.21(2)(b)' `
                -NSA_Guidance 'NSA Hardening Guidance for Windows 11' -Recommendation 'No action required.'
        } else {
            Add-AuditResult -Category 'Attack Surface Reduction & Exploit Prevention' -Control 'Address Space Layout Randomization (ASLR)' -Status 'FAIL' -Severity 'High' `
                -CurrentValue "Bottom-Up=$aslrBottomUp; High-Entropy=$aslrHighEntropy" -RecommendedValue 'Bottom-Up=On; High-Entropy=On' -CIS_Control 'CIS 10.1' `
                -NIST_Control 'SI-16, SC-39' -MITRE_Technique 'T1055 (Process Injection)' -ISO27001_Control 'A.8.7' -NIS2_Article 'Art.21(2)(b)' `
                -NSA_Guidance 'NSA Hardening Guidance for Windows 11' -Recommendation 'Set-ProcessMitigation -System -Enable ForceRelocateImages,BottomUp,HighEntropy to enforce full ASLR system-wide.'
        }

        $cfgEnabled = $mitigations.CFG.Enable -eq 'ON' -or $mitigations.CFG.Enable -eq $true
        if ($cfgEnabled) {
            Add-AuditResult -Category 'Attack Surface Reduction & Exploit Prevention' -Control 'Control Flow Guard (CFG)' -Status 'PASS' -Severity 'Medium' `
                -CurrentValue 'Enabled' -RecommendedValue 'Enabled' -CIS_Control 'CIS 10.1' -NIST_Control 'SI-16, SC-39' `
                -MITRE_Technique 'T1055 (Process Injection)' -ISO27001_Control 'A.8.7' -NIS2_Article 'Art.21(2)(b)' -Recommendation 'No action required.'
        } else {
            Add-AuditResult -Category 'Attack Surface Reduction & Exploit Prevention' -Control 'Control Flow Guard (CFG)' -Status 'FAIL' -Severity 'Medium' `
                -CurrentValue 'Disabled' -RecommendedValue 'Enabled' -CIS_Control 'CIS 10.1' -NIST_Control 'SI-16, SC-39' -ISO27001_Control 'A.8.7' `
                -NIS2_Article 'Art.21(2)(b)' -Recommendation 'Set-ProcessMitigation -System -Enable CFG to require indirect call target validation across processes.'
        }

        $heapTerminate = $mitigations.Heap.TerminateOnError -eq 'ON' -or $mitigations.Heap.TerminateOnError -eq $true
        if ($heapTerminate) {
            Add-AuditResult -Category 'Attack Surface Reduction & Exploit Prevention' -Control 'Heap Integrity (Terminate on Corruption)' -Status 'PASS' -Severity 'Medium' `
                -CurrentValue 'Enabled' -RecommendedValue 'Enabled' -CIS_Control 'CIS 10.1' -NIST_Control 'SI-16, SC-39' -ISO27001_Control 'A.8.7' `
                -NIS2_Article 'Art.21(2)(b)' -Recommendation 'No action required.'
        } else {
            Add-AuditResult -Category 'Attack Surface Reduction & Exploit Prevention' -Control 'Heap Integrity (Terminate on Corruption)' -Status 'FAIL' -Severity 'Medium' `
                -CurrentValue 'Disabled' -RecommendedValue 'Enabled' -CIS_Control 'CIS 10.1' -NIST_Control 'SI-16, SC-39' -ISO27001_Control 'A.8.7' `
                -NIS2_Article 'Art.21(2)(b)' -Recommendation 'Set-ProcessMitigation -System -Enable TerminateOnError so heap-corruption exploitation attempts crash the process instead of continuing execution.'
        }
    } catch {
        Add-AuditResult -Category 'Attack Surface Reduction & Exploit Prevention' -Control 'System-Wide Exploit Mitigations' -Status 'WARN' -Severity 'Low' `
            -CurrentValue 'Query failed' -Recommendation "Unable to query Exploit Protection settings: $($_.Exception.Message)"
    }
}

#endregion

#region ============================== 6. APPLICATION CONTROL & SOFTWARE WHITELISTING ==============================

function Test-WDAC {
    <#
        Audits Windows Defender Application Control (WDAC) policy presence and enforcement
        mode via Win32_DeviceGuard's CodeIntegrityPolicyEnforcementStatus, plus a filesystem
        check for deployed multiple-policy-format (.cip) or legacy SIPolicy.p7b policies.
        Enforcement enum: 0=Off, 1=Audit Mode, 2=Enforced.
    #>
    Write-SectionBanner 'Application Control & Software Whitelisting - WDAC'
    try {
        $dg = Get-DeviceGuardStatus
        $enforcementMap = @{ 0 = 'Off'; 1 = 'Audit Mode'; 2 = 'Enforced' }

        $activePolicyDir = Join-Path -Path $env:WINDIR -ChildPath 'System32\CodeIntegrity\CIPolicies\Active'
        $legacyPolicy = Join-Path -Path $env:WINDIR -ChildPath 'System32\CodeIntegrity\SIPolicy.p7b'
        $hasActivePolicies = (Test-Path -LiteralPath $activePolicyDir) -and ((Get-ChildItem -LiteralPath $activePolicyDir -Filter '*.cip' -ErrorAction SilentlyContinue).Count -gt 0)
        $hasLegacyPolicy = Test-Path -LiteralPath $legacyPolicy

        if ($dg -and $dg.PSObject.Properties.Name -contains 'CodeIntegrityPolicyEnforcementStatus') {
            $status = [int]$dg.CodeIntegrityPolicyEnforcementStatus
            $desc = $enforcementMap[$status]
            if ($status -eq 2) {
                Add-AuditResult -Category 'Application Control & Software Whitelisting' -Control 'Windows Defender Application Control (WDAC)' `
                    -Status 'PASS' -Severity 'High' -CurrentValue "Enforced (Policies present: $($hasActivePolicies -or $hasLegacyPolicy))" -RecommendedValue 'Enforced' `
                    -CIS_Control 'CIS 2.5' -NIST_Control 'CM-7, SI-7' -MITRE_Technique 'T1059 (Command and Scripting Interpreter), T1218 (System Binary Proxy Execution)' `
                    -ISO27001_Control 'A.8.19' -NIS2_Article 'Art.21(2)(e)' -NSA_Guidance 'NSA/CISA Application Allowlisting Guidance' -Recommendation 'No action required.'
            } elseif ($status -eq 1) {
                Add-AuditResult -Category 'Application Control & Software Whitelisting' -Control 'Windows Defender Application Control (WDAC)' `
                    -Status 'WARN' -Severity 'Medium' -CurrentValue 'Audit Mode' -RecommendedValue 'Enforced' -CIS_Control 'CIS 2.5' `
                    -NIST_Control 'CM-7, SI-7' -ISO27001_Control 'A.8.19' -NIS2_Article 'Art.21(2)(e)' -NSA_Guidance 'NSA/CISA Application Allowlisting Guidance' `
                    -Recommendation 'Review CodeIntegrity audit events (Event ID 3076) for blocked-would-be binaries, then convert the policy from Audit to Enforced mode.'
            } else {
                Add-AuditResult -Category 'Application Control & Software Whitelisting' -Control 'Windows Defender Application Control (WDAC)' `
                    -Status 'INFO' -Severity 'Informational' -CurrentValue 'Not Configured' -RecommendedValue 'Enforced (where operationally feasible)' `
                    -CIS_Control 'CIS 2.5' -NIST_Control 'CM-7, SI-7' -ISO27001_Control 'A.8.19' -NIS2_Article 'Art.21(2)(e)' `
                    -NSA_Guidance 'NSA/CISA Application Allowlisting Guidance' `
                    -Recommendation 'Consider deploying a WDAC policy for high-value endpoints to restrict execution to explicitly trusted, signed code. Build via New-CIPolicy and deploy through Intune or GPO.'
            }
        } else {
            Add-AuditResult -Category 'Application Control & Software Whitelisting' -Control 'Windows Defender Application Control (WDAC)' `
                -Status 'INFO' -Severity 'Informational' -CurrentValue "Status not reported; policy files present=$($hasActivePolicies -or $hasLegacyPolicy)" `
                -RecommendedValue 'Enforced (where operationally feasible)' -CIS_Control 'CIS 2.5' -NIST_Control 'CM-7, SI-7' -ISO27001_Control 'A.8.19' `
                -NIS2_Article 'Art.21(2)(e)' -Recommendation 'Unable to positively confirm WDAC enforcement status from this OS build; verify manually via Get-CimInstance -ClassName Win32_DeviceGuard.'
        }
    } catch {
        Add-AuditResult -Category 'Application Control & Software Whitelisting' -Control 'Windows Defender Application Control (WDAC)' `
            -Status 'WARN' -Severity 'Low' -CurrentValue 'Query failed' -Recommendation "Unable to query WDAC state: $($_.Exception.Message)"
    }
}

function Test-AppLocker {
    <#
        Audits AppLocker rule-collection enforcement mode for Exe, Msi/Script (Windows
        Installer + Script collection), and Dll rule collections via Get-AppLockerPolicy.
        Requires Windows 11 Enterprise/Education; not available on Pro.
    #>
    Write-SectionBanner 'Application Control & Software Whitelisting - AppLocker'
    try {
        $policy = Get-AppLockerPolicy -Effective -ErrorAction Stop
        if (-not $policy -or -not $policy.RuleCollections -or $policy.RuleCollections.Count -eq 0) {
            Add-AuditResult -Category 'Application Control & Software Whitelisting' -Control 'AppLocker Rule Enforcement' `
                -Status 'FAIL' -Severity 'Medium' -CurrentValue 'No effective AppLocker policy / rule collections' -RecommendedValue 'Enabled rule collections for Exe, Script, Msi, Dll' `
                -CIS_Control 'CIS 2.5' -NIST_Control 'CM-7' -MITRE_Technique 'T1218 (System Binary Proxy Execution)' -ISO27001_Control 'A.8.19' `
                -NIS2_Article 'Art.21(2)(e)' -NSA_Guidance 'NSA/CISA Application Allowlisting Guidance' `
                -Recommendation 'Configure AppLocker rule collections (Exe, Script, Windows Installer, DLL) via Local Security Policy > Application Control Policies > AppLocker, or via GPO, and set enforcement to Enabled.'
        } else {
            foreach ($collection in $policy.RuleCollections) {
                $type = $collection.RuleCollectionType
                $mode = $collection.EnforcementMode
                if ($mode -eq 'Enabled') {
                    Add-AuditResult -Category 'Application Control & Software Whitelisting' -Control "AppLocker Rule Collection - $type" -Status 'PASS' -Severity 'Medium' `
                        -CurrentValue 'Enabled' -RecommendedValue 'Enabled' -CIS_Control 'CIS 2.5' -NIST_Control 'CM-7' `
                        -MITRE_Technique 'T1218 (System Binary Proxy Execution)' -ISO27001_Control 'A.8.19' -NIS2_Article 'Art.21(2)(e)' `
                        -NSA_Guidance 'NSA/CISA Application Allowlisting Guidance' -Recommendation 'No action required.'
                } elseif ($mode -eq 'AuditOnly') {
                    Add-AuditResult -Category 'Application Control & Software Whitelisting' -Control "AppLocker Rule Collection - $type" -Status 'WARN' -Severity 'Low' `
                        -CurrentValue 'Audit Only' -RecommendedValue 'Enabled' -CIS_Control 'CIS 2.5' -NIST_Control 'CM-7' -ISO27001_Control 'A.8.19' `
                        -NIS2_Article 'Art.21(2)(e)' -Recommendation "Review AppLocker audit events (Event ID 8003/8006/8007) for the $type collection, then switch enforcement mode from Audit Only to Enabled."
                } else {
                    Add-AuditResult -Category 'Application Control & Software Whitelisting' -Control "AppLocker Rule Collection - $type" -Status 'FAIL' -Severity 'Medium' `
                        -CurrentValue 'Not Configured' -RecommendedValue 'Enabled' -CIS_Control 'CIS 2.5' -NIST_Control 'CM-7' `
                        -MITRE_Technique 'T1218 (System Binary Proxy Execution)' -ISO27001_Control 'A.8.19' -NIS2_Article 'Art.21(2)(e)' `
                        -NSA_Guidance 'NSA/CISA Application Allowlisting Guidance' -Recommendation "Define and enable rules for the $type collection in AppLocker policy."
                }
            }
        }
    } catch {
        Add-AuditResult -Category 'Application Control & Software Whitelisting' -Control 'AppLocker Rule Enforcement' `
            -Status 'INFO' -Severity 'Informational' -CurrentValue 'AppLocker unavailable on this SKU/build' -RecommendedValue 'Enabled rule collections for Exe, Script, Msi, Dll' `
            -Recommendation 'AppLocker requires Windows 11 Enterprise or Education. On Pro/Home editions, use WDAC for application control instead.'
    }
}

function Test-InstallerAndServicePathSecurity {
    <#
        Checks for the classic AlwaysInstallElevated local-privilege-escalation
        misconfiguration and enumerates services with unquoted, space-containing binary
        paths (the "unquoted service path" vulnerability class).
    #>
    Write-SectionBanner 'Application Control & Software Whitelisting - Installer & Service Path Security'
    try {
        $hklmVal = Get-RegistryValueSafe -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name 'AlwaysInstallElevated' -DefaultValue 0
        $hkcuVal = Get-RegistryValueSafe -Path 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name 'AlwaysInstallElevated' -DefaultValue 0

        if ([int]$hklmVal -eq 1 -and [int]$hkcuVal -eq 1) {
            Add-AuditResult -Category 'Application Control & Software Whitelisting' -Control 'Windows Installer AlwaysInstallElevated' `
                -Status 'FAIL' -Severity 'Critical' -CurrentValue 'HKLM=1; HKCU=1 (both set)' -RecommendedValue '0 (or not configured) on both hives' `
                -CIS_Control 'CIS 4.8' -NIST_Control 'AC-6, CM-7' -MITRE_Technique 'T1548.002 (Bypass User Account Control), T1068 (Exploitation for Privilege Escalation)' `
                -ISO27001_Control 'A.8.19' -NIS2_Article 'Art.21(2)(i)' -NSA_Guidance 'NSA/CISA Identity and Access Management Best Practices' `
                -Recommendation 'Set both HKLM and HKCU AlwaysInstallElevated to 0 (or remove the value) - a standard user can otherwise install arbitrary MSI packages with SYSTEM privileges.'
        } else {
            Add-AuditResult -Category 'Application Control & Software Whitelisting' -Control 'Windows Installer AlwaysInstallElevated' `
                -Status 'PASS' -Severity 'Critical' -CurrentValue "HKLM=$hklmVal; HKCU=$hkcuVal" -RecommendedValue '0 (or not configured)' -CIS_Control 'CIS 4.8' `
                -NIST_Control 'AC-6, CM-7' -MITRE_Technique 'T1548.002 (Bypass User Account Control)' -ISO27001_Control 'A.8.19' -NIS2_Article 'Art.21(2)(i)' `
                -NSA_Guidance 'NSA/CISA Identity and Access Management Best Practices' -Recommendation 'No action required.'
        }

        $unquotedServices = @()
        $services = Get-CimInstance -ClassName Win32_Service -ErrorAction Stop | Where-Object { $_.PathName -and $_.PathName -notmatch '^\s*"' -and $_.PathName -match '\s' }
        foreach ($svc in $services) {
            $exePart = $svc.PathName -replace '\.(exe|com|sys)\b.*$', '.$1' -replace '(?i)^(.*?\.(exe|com|sys)).*$', '$1'
            if ($exePart -match '\s' -and $svc.PathName -notmatch '^\s*"') {
                $unquotedServices += "$($svc.Name) [$($svc.StartMode)] -> $($svc.PathName)"
            }
        }

        if ($unquotedServices.Count -eq 0) {
            Add-AuditResult -Category 'Application Control & Software Whitelisting' -Control 'Unquoted Service Path Vulnerabilities' `
                -Status 'PASS' -Severity 'High' -CurrentValue 'No vulnerable unquoted service paths found' -RecommendedValue 'All service ImagePaths quoted or space-free' `
                -CIS_Control 'CIS 4.8' -NIST_Control 'CM-7, AC-6' -MITRE_Technique 'T1574.009 (Path Interception by Unquoted Path)' -ISO27001_Control 'A.8.19' `
                -NIS2_Article 'Art.21(2)(i)' -NSA_Guidance 'NSA/CISA Identity and Access Management Best Practices' -Recommendation 'No action required.'
        } else {
            Add-AuditResult -Category 'Application Control & Software Whitelisting' -Control 'Unquoted Service Path Vulnerabilities' `
                -Status 'FAIL' -Severity 'High' -CurrentValue "$($unquotedServices.Count) service(s) affected: $($unquotedServices -join ' | ')" `
                -RecommendedValue 'All service ImagePaths quoted or space-free' -CIS_Control 'CIS 4.8' -NIST_Control 'CM-7, AC-6' `
                -MITRE_Technique 'T1574.009 (Path Interception by Unquoted Path)' -ISO27001_Control 'A.8.19' -NIS2_Article 'Art.21(2)(i)' `
                -NSA_Guidance 'NSA/CISA Identity and Access Management Best Practices' `
                -Recommendation 'Wrap each affected service ImagePath in double quotes (sc.exe config <svc> binPath= "\"C:\Path With Space\svc.exe\"") to prevent local privilege escalation via path interception.'
        }
    } catch {
        Add-AuditResult -Category 'Application Control & Software Whitelisting' -Control 'Installer & Service Path Security' `
            -Status 'WARN' -Severity 'Low' -CurrentValue 'Query failed' -Recommendation "Unable to complete installer/service path audit: $($_.Exception.Message)"
    }
}

#endregion

#region ============================== 7. IDENTITY, PRIVILEGE MANAGEMENT & ACCESS CONTROL ==============================

function Test-LocalAccounts {
    <#
        Audits the built-in RID 500 Administrator and RID 501 Guest accounts for enabled
        state and default-name usage.
    #>
    Write-SectionBanner 'Identity & Privilege Management - Built-in Accounts'
    try {
        $localUsers = Get-LocalUser -ErrorAction Stop
        $adminAccount = $localUsers | Where-Object { $_.SID -like '*-500' }
        $guestAccount = $localUsers | Where-Object { $_.SID -like '*-501' }

        if ($adminAccount) {
            if ($adminAccount.Enabled -eq $false) {
                Add-AuditResult -Category 'Identity, Privilege Management & Access Control' -Control 'Built-in Administrator Account State' -Status 'PASS' -Severity 'High' `
                    -CurrentValue "Name=$($adminAccount.Name); Enabled=False" -RecommendedValue 'Disabled (or renamed and closely monitored if enabled)' `
                    -CIS_Control 'CIS 5.2' -NIST_Control 'AC-2, IA-4' -MITRE_Technique 'T1078.001 (Default Accounts)' -ISO27001_Control 'A.5.16' `
                    -NIS2_Article 'Art.21(2)(i)' -NSA_Guidance 'NSA/CISA Identity and Access Management Best Practices' -Recommendation 'No action required.'
            } else {
                $renamed = $adminAccount.Name -ne 'Administrator'
                if ($renamed) {
                    Add-AuditResult -Category 'Identity, Privilege Management & Access Control' -Control 'Built-in Administrator Account State' -Status 'WARN' -Severity 'Medium' `
                        -CurrentValue "Name=$($adminAccount.Name); Enabled=True (renamed)" -RecommendedValue 'Disabled (or renamed with a unique, strong, rotated password)' `
                        -CIS_Control 'CIS 5.2' -NIST_Control 'AC-2, IA-4' -MITRE_Technique 'T1078.001 (Default Accounts)' -ISO27001_Control 'A.5.16' `
                        -NIS2_Article 'Art.21(2)(i)' -NSA_Guidance 'NSA/CISA Identity and Access Management Best Practices' `
                        -Recommendation 'The account is renamed but still enabled. Disable it (Disable-LocalUser) unless it is actively required, and ensure LAPS manages its password if it must remain enabled.'
                } else {
                    Add-AuditResult -Category 'Identity, Privilege Management & Access Control' -Control 'Built-in Administrator Account State' -Status 'FAIL' -Severity 'High' `
                        -CurrentValue "Name=Administrator; Enabled=True" -RecommendedValue 'Disabled (or renamed and closely monitored if enabled)' `
                        -CIS_Control 'CIS 5.2' -NIST_Control 'AC-2, IA-4' -MITRE_Technique 'T1078.001 (Default Accounts)' -ISO27001_Control 'A.5.16' `
                        -NIS2_Article 'Art.21(2)(i)' -NSA_Guidance 'NSA/CISA Identity and Access Management Best Practices' `
                        -Recommendation 'Disable-LocalUser -Name Administrator, or rename it via GPO "Accounts: Rename administrator account" and manage its password through LAPS.'
                }
            }
        }

        if ($guestAccount) {
            if ($guestAccount.Enabled -eq $false) {
                Add-AuditResult -Category 'Identity, Privilege Management & Access Control' -Control 'Built-in Guest Account State' -Status 'PASS' -Severity 'High' `
                    -CurrentValue "Name=$($guestAccount.Name); Enabled=False" -RecommendedValue 'Disabled' -CIS_Control 'CIS 5.2' -NIST_Control 'AC-2, IA-4' `
                    -MITRE_Technique 'T1078.001 (Default Accounts)' -ISO27001_Control 'A.5.16' -NIS2_Article 'Art.21(2)(i)' `
                    -NSA_Guidance 'NSA/CISA Identity and Access Management Best Practices' -Recommendation 'No action required.'
            } else {
                Add-AuditResult -Category 'Identity, Privilege Management & Access Control' -Control 'Built-in Guest Account State' -Status 'FAIL' -Severity 'High' `
                    -CurrentValue "Name=$($guestAccount.Name); Enabled=True" -RecommendedValue 'Disabled' -CIS_Control 'CIS 5.2' -NIST_Control 'AC-2, IA-4' `
                    -MITRE_Technique 'T1078.001 (Default Accounts)' -ISO27001_Control 'A.5.16' -NIS2_Article 'Art.21(2)(i)' `
                    -NSA_Guidance 'NSA/CISA Identity and Access Management Best Practices' -Recommendation 'Disable-LocalUser -Name Guest immediately - an enabled Guest account provides anonymous/low-friction local access.'
            }
        }
    } catch {
        Add-AuditResult -Category 'Identity, Privilege Management & Access Control' -Control 'Built-in Account Hardening' -Status 'WARN' -Severity 'Low' `
            -CurrentValue 'Query failed' -Recommendation "Unable to enumerate local accounts: $($_.Exception.Message)"
    }
}

function Test-LAPS {
    <#
        Audits Windows LAPS (built into Windows 11 22H2+, policy-driven) and legacy Microsoft
        LAPS (CSE-based) presence for automated local administrator password rotation.
    #>
    Write-SectionBanner 'Identity & Privilege Management - Local Administrator Password Solution'
    try {
        $windowsLapsPolicy = 'HKLM:\SOFTWARE\Microsoft\Policies\LAPS'
        $windowsLapsConfigured = (Test-Path -LiteralPath $windowsLapsPolicy) -and ((Get-ItemProperty -LiteralPath $windowsLapsPolicy -ErrorAction SilentlyContinue).PSObject.Properties.Name.Count -gt 0)
        $legacyLapsCse = Join-Path -Path ${env:ProgramFiles} -ChildPath 'LAPS\CSE\AdmPwd.dll'
        $legacyLapsPresent = Test-Path -LiteralPath $legacyLapsCse

        # Windows LAPS also exposes an operational state under this path once it has run.
        $lapsStatePath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS\State'
        $lapsLastRotation = Get-RegistryValueSafe -Path $lapsStatePath -Name 'PwdLastSet' -DefaultValue $null

        if ($windowsLapsConfigured) {
            Add-AuditResult -Category 'Identity, Privilege Management & Access Control' -Control 'Local Administrator Password Solution (LAPS)' -Status 'PASS' -Severity 'High' `
                -CurrentValue 'Windows LAPS policy configured' -RecommendedValue 'Windows LAPS enabled with rotation policy enforced' -CIS_Control 'CIS 5.3' `
                -NIST_Control 'IA-5, AC-2' -MITRE_Technique 'T1078.003 (Local Accounts), T1110 (Brute Force)' -ISO27001_Control 'A.5.17' -NIS2_Article 'Art.21(2)(i)' `
                -NSA_Guidance 'NSA/CISA Identity and Access Management Best Practices' -Recommendation 'No action required. Periodically verify rotation is succeeding (Get-LapsDiagnostics).'
        } elseif ($legacyLapsPresent) {
            Add-AuditResult -Category 'Identity, Privilege Management & Access Control' -Control 'Local Administrator Password Solution (LAPS)' -Status 'WARN' -Severity 'Medium' `
                -CurrentValue 'Legacy Microsoft LAPS CSE installed' -RecommendedValue 'Migrate to Windows LAPS (built-in, Windows 11 22H2+)' -CIS_Control 'CIS 5.3' `
                -NIST_Control 'IA-5, AC-2' -MITRE_Technique 'T1078.003 (Local Accounts)' -ISO27001_Control 'A.5.17' -NIS2_Article 'Art.21(2)(i)' `
                -NSA_Guidance 'NSA/CISA Identity and Access Management Best Practices' `
                -Recommendation 'Legacy LAPS is in extended support only. Migrate to Windows LAPS, which is natively integrated, supports Entra ID-joined devices, and offers passphrase/history features legacy LAPS lacks.'
        } else {
            Add-AuditResult -Category 'Identity, Privilege Management & Access Control' -Control 'Local Administrator Password Solution (LAPS)' -Status 'FAIL' -Severity 'High' `
                -CurrentValue 'Not Configured (neither Windows LAPS nor legacy LAPS detected)' -RecommendedValue 'Windows LAPS enabled with rotation policy enforced' `
                -CIS_Control 'CIS 5.3' -NIST_Control 'IA-5, AC-2' -MITRE_Technique 'T1078.003 (Local Accounts), T1110 (Brute Force)' -ISO27001_Control 'A.5.17' `
                -NIS2_Article 'Art.21(2)(i)' -NSA_Guidance 'NSA/CISA Identity and Access Management Best Practices' `
                -Recommendation 'Deploy Windows LAPS via GPO/Intune (Computer Configuration > Administrative Templates > System > LAPS) to enforce randomized, automatically rotated local administrator passwords and prevent pass-the-hash lateral movement between identically-passworded endpoints.'
        }
    } catch {
        Add-AuditResult -Category 'Identity, Privilege Management & Access Control' -Control 'Local Administrator Password Solution (LAPS)' -Status 'WARN' -Severity 'Low' `
            -CurrentValue 'Query failed' -Recommendation "Unable to determine LAPS state: $($_.Exception.Message)"
    }
}

function Test-PasswordAndLockoutPolicy {
    <#
        Audits local account lockout threshold/duration and password policy (length,
        complexity, max/min age, history) via secedit export, since these local security
        policy settings have no direct read cmdlet.
    #>
    Write-SectionBanner 'Identity & Privilege Management - Authentication & Lockout Policy'
    $tempCfg = Join-Path -Path $env:TEMP -ChildPath "EndpointPostureCheck_secedit_$PID.cfg"
    try {
        $null = & secedit.exe /export /cfg $tempCfg /quiet 2>$null
        if (-not (Test-Path -LiteralPath $tempCfg)) { throw 'secedit export failed to produce output file' }

        $cfg = Get-Content -LiteralPath $tempCfg -ErrorAction Stop
        function Get-SeceditValue {
            param($lines, $key)
            $line = $lines | Where-Object { $_ -match "^\s*$key\s*=" } | Select-Object -First 1
            if ($line) { return ($line -split '=')[1].Trim() }
            return $null
        }

        $lockoutThreshold = Get-SeceditValue $cfg 'LockoutBadCount'
        $lockoutDuration  = Get-SeceditValue $cfg 'LockoutDuration'
        $minPwdLength     = Get-SeceditValue $cfg 'MinimumPasswordLength'
        $pwdComplexity    = Get-SeceditValue $cfg 'PasswordComplexity'
        $maxPwdAge        = Get-SeceditValue $cfg 'MaximumPasswordAge'
        $minPwdAge        = Get-SeceditValue $cfg 'MinimumPasswordAge'
        $pwdHistory       = Get-SeceditValue $cfg 'PasswordHistorySize'

        if ($lockoutThreshold -and [int]$lockoutThreshold -gt 0 -and [int]$lockoutThreshold -le 10) {
            Add-AuditResult -Category 'Identity, Privilege Management & Access Control' -Control 'Account Lockout Threshold' -Status 'PASS' -Severity 'High' `
                -CurrentValue "$lockoutThreshold invalid attempts" -RecommendedValue '<= 10 (CIS: 5 recommended)' -CIS_Control 'CIS 4.4' -NIST_Control 'AC-7' `
                -MITRE_Technique 'T1110 (Brute Force)' -ISO27001_Control 'A.8.5' -NIS2_Article 'Art.21(2)(i)' `
                -NSA_Guidance 'NSA/CISA Selecting Secure Multifactor Authentication' -Recommendation 'No action required.'
        } else {
            Add-AuditResult -Category 'Identity, Privilege Management & Access Control' -Control 'Account Lockout Threshold' -Status 'FAIL' -Severity 'High' `
                -CurrentValue "$lockoutThreshold invalid attempts (0 = never locks out)" -RecommendedValue '<= 10 (CIS: 5 recommended)' -CIS_Control 'CIS 4.4' `
                -NIST_Control 'AC-7' -MITRE_Technique 'T1110 (Brute Force)' -ISO27001_Control 'A.8.5' -NIS2_Article 'Art.21(2)(i)' `
                -NSA_Guidance 'NSA/CISA Selecting Secure Multifactor Authentication' `
                -Recommendation 'Set Account Lockout Threshold to 5 invalid attempts via Local Security Policy > Account Policies > Account Lockout Policy, or GPO equivalent.'
        }

        if ($minPwdLength -and [int]$minPwdLength -ge 14) {
            Add-AuditResult -Category 'Identity, Privilege Management & Access Control' -Control 'Minimum Password Length' -Status 'PASS' -Severity 'Medium' `
                -CurrentValue "$minPwdLength characters" -RecommendedValue '>= 14 characters' -CIS_Control 'CIS 5.2' -NIST_Control 'IA-5' -ISO27001_Control 'A.8.5' `
                -NIS2_Article 'Art.21(2)(i)' -NSA_Guidance 'NSA/CISA Selecting Secure Multifactor Authentication' -Recommendation 'No action required.'
        } else {
            Add-AuditResult -Category 'Identity, Privilege Management & Access Control' -Control 'Minimum Password Length' -Status 'FAIL' -Severity 'Medium' `
                -CurrentValue "$minPwdLength characters" -RecommendedValue '>= 14 characters' -CIS_Control 'CIS 5.2' -NIST_Control 'IA-5' -ISO27001_Control 'A.8.5' `
                -NIS2_Article 'Art.21(2)(i)' -NSA_Guidance 'NSA/CISA Selecting Secure Multifactor Authentication' `
                -Recommendation 'Increase minimum password length to 14+ characters via Local Security Policy > Account Policies > Password Policy.'
        }

        if ($pwdComplexity -eq '1') {
            Add-AuditResult -Category 'Identity, Privilege Management & Access Control' -Control 'Password Complexity Requirements' -Status 'PASS' -Severity 'Medium' `
                -CurrentValue 'Enabled' -RecommendedValue 'Enabled' -CIS_Control 'CIS 5.2' -NIST_Control 'IA-5' -ISO27001_Control 'A.8.5' `
                -NIS2_Article 'Art.21(2)(i)' -Recommendation 'No action required.'
        } else {
            Add-AuditResult -Category 'Identity, Privilege Management & Access Control' -Control 'Password Complexity Requirements' -Status 'FAIL' -Severity 'Medium' `
                -CurrentValue 'Disabled' -RecommendedValue 'Enabled' -CIS_Control 'CIS 5.2' -NIST_Control 'IA-5' -ISO27001_Control 'A.8.5' -NIS2_Article 'Art.21(2)(i)' `
                -Recommendation 'Enable "Password must meet complexity requirements" via Local Security Policy > Account Policies > Password Policy.'
        }

        if ($maxPwdAge -and ([int]$maxPwdAge -le 365 -and [int]$maxPwdAge -ne 0)) {
            Add-AuditResult -Category 'Identity, Privilege Management & Access Control' -Control 'Maximum Password Age' -Status 'PASS' -Severity 'Low' `
                -CurrentValue "$maxPwdAge days" -RecommendedValue '<= 365 days (or managed via risk-based/passwordless policy)' -CIS_Control 'CIS 5.2' `
                -NIST_Control 'IA-5' -ISO27001_Control 'A.8.5' -NIS2_Article 'Art.21(2)(i)' -Recommendation 'No action required.'
        } else {
            Add-AuditResult -Category 'Identity, Privilege Management & Access Control' -Control 'Maximum Password Age' -Status 'WARN' -Severity 'Low' `
                -CurrentValue "$maxPwdAge days" -RecommendedValue '<= 365 days (or managed via risk-based/passwordless policy)' -CIS_Control 'CIS 5.2' `
                -NIST_Control 'IA-5' -ISO27001_Control 'A.8.5' -NIS2_Article 'Art.21(2)(i)' `
                -Recommendation 'Set a bounded maximum password age, or adopt a modern passwordless/risk-based authentication strategy (Windows Hello for Business, FIDO2) in place of periodic rotation.'
        }

        if ($pwdHistory -and [int]$pwdHistory -ge 24) {
            Add-AuditResult -Category 'Identity, Privilege Management & Access Control' -Control 'Password History Enforcement' -Status 'PASS' -Severity 'Low' `
                -CurrentValue "$pwdHistory remembered passwords" -RecommendedValue '>= 24' -CIS_Control 'CIS 5.2' -NIST_Control 'IA-5' -ISO27001_Control 'A.8.5' `
                -NIS2_Article 'Art.21(2)(i)' -Recommendation 'No action required.'
        } else {
            Add-AuditResult -Category 'Identity, Privilege Management & Access Control' -Control 'Password History Enforcement' -Status 'FAIL' -Severity 'Low' `
                -CurrentValue "$pwdHistory remembered passwords" -RecommendedValue '>= 24' -CIS_Control 'CIS 5.2' -NIST_Control 'IA-5' -ISO27001_Control 'A.8.5' `
                -NIS2_Article 'Art.21(2)(i)' -Recommendation 'Set "Enforce password history" to 24 or more via Local Security Policy > Account Policies > Password Policy.'
        }
    } catch {
        Add-AuditResult -Category 'Identity, Privilege Management & Access Control' -Control 'Authentication & Lockout Policy' -Status 'WARN' -Severity 'Low' `
            -CurrentValue 'Query failed' -Recommendation "Unable to export/parse local security policy via secedit: $($_.Exception.Message)"
    } finally {
        if (Test-Path -LiteralPath $tempCfg) { Remove-Item -LiteralPath $tempCfg -Force -ErrorAction SilentlyContinue }
    }
}

function Test-UAC {
    <#
        Audits User Account Control architecture: LUA enforcement, elevation prompt behavior
        for administrators, secure-desktop prompting, and RID 500 admin-approval-mode token
        filtering.
    #>
    Write-SectionBanner 'Identity & Privilege Management - User Account Control (UAC)'
    try {
        $uacPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
        $enableLua = Get-RegistryValueSafe -Path $uacPath -Name 'EnableLUA' -DefaultValue 1
        $consentPromptAdmin = Get-RegistryValueSafe -Path $uacPath -Name 'ConsentPromptBehaviorAdmin' -DefaultValue 5
        $promptOnSecureDesktop = Get-RegistryValueSafe -Path $uacPath -Name 'PromptOnSecureDesktop' -DefaultValue 1
        $filterAdminToken = Get-RegistryValueSafe -Path $uacPath -Name 'FilterAdministratorToken' -DefaultValue 0

        if ([int]$enableLua -eq 1) {
            Add-AuditResult -Category 'Identity, Privilege Management & Access Control' -Control 'UAC Enforcement (EnableLUA)' -Status 'PASS' -Severity 'Critical' `
                -CurrentValue 'Enabled' -RecommendedValue 'Enabled' -CIS_Control 'CIS 5.4' -NIST_Control 'AC-6, CM-7' `
                -MITRE_Technique 'T1548.002 (Bypass User Account Control)' -ISO27001_Control 'A.8.2' -NIS2_Article 'Art.21(2)(i)' `
                -NSA_Guidance 'NSA/CISA Identity and Access Management Best Practices' -Recommendation 'No action required.'
        } else {
            Add-AuditResult -Category 'Identity, Privilege Management & Access Control' -Control 'UAC Enforcement (EnableLUA)' -Status 'FAIL' -Severity 'Critical' `
                -CurrentValue 'Disabled' -RecommendedValue 'Enabled' -CIS_Control 'CIS 5.4' -NIST_Control 'AC-6, CM-7' `
                -MITRE_Technique 'T1548.002 (Bypass User Account Control)' -ISO27001_Control 'A.8.2' -NIS2_Article 'Art.21(2)(i)' `
                -NSA_Guidance 'NSA/CISA Identity and Access Management Best Practices' -Recommendation 'Set HKLM:\...\Policies\System\EnableLUA = 1 and reboot. UAC is foundational to standard-user/admin token separation.'
        }

        if ([int]$consentPromptAdmin -eq 2) {
            Add-AuditResult -Category 'Identity, Privilege Management & Access Control' -Control 'UAC Elevation Prompt Behavior (Administrators)' -Status 'PASS' -Severity 'Medium' `
                -CurrentValue 'Prompt for consent on the secure desktop' -RecommendedValue '2 (Prompt for consent on the secure desktop)' -CIS_Control 'CIS 5.4' `
                -NIST_Control 'AC-6' -ISO27001_Control 'A.8.2' -NIS2_Article 'Art.21(2)(i)' -Recommendation 'No action required.'
        } else {
            Add-AuditResult -Category 'Identity, Privilege Management & Access Control' -Control 'UAC Elevation Prompt Behavior (Administrators)' -Status 'FAIL' -Severity 'Medium' `
                -CurrentValue "ConsentPromptBehaviorAdmin=$consentPromptAdmin" -RecommendedValue '2 (Prompt for consent on the secure desktop)' -CIS_Control 'CIS 5.4' `
                -NIST_Control 'AC-6' -ISO27001_Control 'A.8.2' -NIS2_Article 'Art.21(2)(i)' `
                -Recommendation 'Set "User Account Control: Behavior of the elevation prompt for administrators" to Prompt for consent on the secure desktop.'
        }

        if ([int]$promptOnSecureDesktop -eq 1) {
            Add-AuditResult -Category 'Identity, Privilege Management & Access Control' -Control 'UAC Secure Desktop Prompting' -Status 'PASS' -Severity 'Medium' `
                -CurrentValue 'Enabled' -RecommendedValue 'Enabled' -CIS_Control 'CIS 5.4' -NIST_Control 'AC-6' -ISO27001_Control 'A.8.2' `
                -NIS2_Article 'Art.21(2)(i)' -Recommendation 'No action required.'
        } else {
            Add-AuditResult -Category 'Identity, Privilege Management & Access Control' -Control 'UAC Secure Desktop Prompting' -Status 'FAIL' -Severity 'Medium' `
                -CurrentValue 'Disabled' -RecommendedValue 'Enabled' -CIS_Control 'CIS 5.4' -NIST_Control 'AC-6' -ISO27001_Control 'A.8.2' -NIS2_Article 'Art.21(2)(i)' `
                -Recommendation 'Enable "User Account Control: Switch to the secure desktop when prompting for elevation" to prevent UI-redress spoofing of the elevation prompt.'
        }

        if ([int]$filterAdminToken -eq 1) {
            Add-AuditResult -Category 'Identity, Privilege Management & Access Control' -Control 'Built-in Administrator Admin Approval Mode (Token Filtering)' -Status 'PASS' -Severity 'Medium' `
                -CurrentValue 'Enabled' -RecommendedValue 'Enabled' -CIS_Control 'CIS 5.4' -NIST_Control 'AC-6' -ISO27001_Control 'A.8.2' `
                -NIS2_Article 'Art.21(2)(i)' -Recommendation 'No action required.'
        } else {
            Add-AuditResult -Category 'Identity, Privilege Management & Access Control' -Control 'Built-in Administrator Admin Approval Mode (Token Filtering)' -Status 'WARN' -Severity 'Low' `
                -CurrentValue 'Disabled' -RecommendedValue 'Enabled' -CIS_Control 'CIS 5.4' -NIST_Control 'AC-6' -ISO27001_Control 'A.8.2' -NIS2_Article 'Art.21(2)(i)' `
                -Recommendation 'Enable "User Account Control: Admin Approval Mode for the Built-in Administrator account" so even the RID 500 account runs with a filtered token by default.'
        }
    } catch {
        Add-AuditResult -Category 'Identity, Privilege Management & Access Control' -Control 'User Account Control (UAC)' -Status 'WARN' -Severity 'Low' `
            -CurrentValue 'Query failed' -Recommendation "Unable to query UAC registry policy: $($_.Exception.Message)"
    }
}

#endregion

#region ============================== 8. NETWORK ARCHITECTURE & PROTOCOL HARDENING ==============================

function Test-Firewall {
    <#
        Audits Windows Firewall operational state and default inbound/outbound actions
        across the Domain, Private, and Public profiles.
    #>
    Write-SectionBanner 'Network Architecture - Host Firewall'
    try {
        $profiles = Get-NetFirewallProfile -ErrorAction Stop
        foreach ($p in $profiles) {
            if ($p.Enabled) {
                Add-AuditResult -Category 'Network Architecture & Protocol Hardening' -Control "Windows Firewall - $($p.Name) Profile State" -Status 'PASS' -Severity 'High' `
                    -CurrentValue 'Enabled' -RecommendedValue 'Enabled' -CIS_Control 'CIS 4.4' -NIST_Control 'SC-7, CM-7' -MITRE_Technique 'T1562.004 (Disable or Modify System Firewall)' `
                    -ISO27001_Control 'A.8.20' -NIS2_Article 'Art.21(2)(d)' -NSA_Guidance 'NSA/CISA Host-Based Firewall Guidance' -Recommendation 'No action required.'
            } else {
                Add-AuditResult -Category 'Network Architecture & Protocol Hardening' -Control "Windows Firewall - $($p.Name) Profile State" -Status 'FAIL' -Severity 'Critical' `
                    -CurrentValue 'Disabled' -RecommendedValue 'Enabled' -CIS_Control 'CIS 4.4' -NIST_Control 'SC-7, CM-7' -MITRE_Technique 'T1562.004 (Disable or Modify System Firewall)' `
                    -ISO27001_Control 'A.8.20' -NIS2_Article 'Art.21(2)(d)' -NSA_Guidance 'NSA/CISA Host-Based Firewall Guidance' `
                    -Recommendation "Set-NetFirewallProfile -Profile $($p.Name) -Enabled True. A disabled host firewall removes an essential layer of network segmentation for laptops on untrusted networks."
            }

            if ($p.DefaultInboundAction -eq 'Block') {
                Add-AuditResult -Category 'Network Architecture & Protocol Hardening' -Control "Windows Firewall - $($p.Name) Default Inbound Action" -Status 'PASS' -Severity 'High' `
                    -CurrentValue 'Block' -RecommendedValue 'Block' -CIS_Control 'CIS 4.4' -NIST_Control 'SC-7' -ISO27001_Control 'A.8.20' -NIS2_Article 'Art.21(2)(d)' `
                    -Recommendation 'No action required.'
            } else {
                Add-AuditResult -Category 'Network Architecture & Protocol Hardening' -Control "Windows Firewall - $($p.Name) Default Inbound Action" -Status 'FAIL' -Severity 'High' `
                    -CurrentValue "$($p.DefaultInboundAction)" -RecommendedValue 'Block' -CIS_Control 'CIS 4.4' -NIST_Control 'SC-7' -MITRE_Technique 'T1190 (Exploit Public-Facing Application)' `
                    -ISO27001_Control 'A.8.20' -NIS2_Article 'Art.21(2)(d)' `
                    -Recommendation "Set-NetFirewallProfile -Profile $($p.Name) -DefaultInboundAction Block to deny unsolicited inbound connections by default."
            }
        }
    } catch {
        Add-AuditResult -Category 'Network Architecture & Protocol Hardening' -Control 'Windows Firewall' -Status 'WARN' -Severity 'Low' `
            -CurrentValue 'Query failed' -Recommendation "Unable to query firewall profiles: $($_.Exception.Message)"
    }
}

function Test-LegacyProtocols {
    <#
        Audits deprecated/insecure network protocols: SMBv1, LLMNR, NetBIOS over TCP/IP,
        mDNS, and the WinHTTP AutoProxy (WPAD) auto-discovery service.
    #>
    Write-SectionBanner 'Network Architecture - Legacy Protocol Deprecation'

    # --- SMBv1 ---
    try {
        $smb1 = $null
        try {
            $smb1Feature = Get-WindowsOptionalFeature -Online -FeatureName 'SMB1Protocol' -ErrorAction Stop
            $smb1 = $smb1Feature.State
        } catch {
            $cfg = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
            if ($cfg) { $smb1 = if ($cfg.EnableSMB1Protocol) { 'Enabled' } else { 'Disabled' } }
        }
        if ($smb1 -eq 'Disabled') {
            Add-AuditResult -Category 'Network Architecture & Protocol Hardening' -Control 'SMBv1 Protocol' -Status 'PASS' -Severity 'Critical' `
                -CurrentValue 'Disabled' -RecommendedValue 'Disabled' -CIS_Control 'CIS 4.7' -NIST_Control 'CM-7, SC-8' -MITRE_Technique 'T1210 (Exploitation of Remote Services), T1021.002 (SMB/Windows Admin Shares)' `
                -ISO27001_Control 'A.8.20' -NIS2_Article 'Art.21(2)(d)' -NSA_Guidance 'NSA/CISA Advisory: Eliminate Obsolete SMBv1' -Recommendation 'No action required.'
        } else {
            Add-AuditResult -Category 'Network Architecture & Protocol Hardening' -Control 'SMBv1 Protocol' -Status 'FAIL' -Severity 'Critical' `
                -CurrentValue "$smb1" -RecommendedValue 'Disabled' -CIS_Control 'CIS 4.7' -NIST_Control 'CM-7, SC-8' -MITRE_Technique 'T1210 (Exploitation of Remote Services)' `
                -ISO27001_Control 'A.8.20' -NIS2_Article 'Art.21(2)(d)' -NSA_Guidance 'NSA/CISA Advisory: Eliminate Obsolete SMBv1' `
                -Recommendation 'Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol. SMBv1 has no protection against relay/downgrade attacks and was the vector for WannaCry/NotPetya.'
        }
    } catch {
        Add-AuditResult -Category 'Network Architecture & Protocol Hardening' -Control 'SMBv1 Protocol' -Status 'WARN' -Severity 'Low' `
            -CurrentValue 'Query failed' -Recommendation "Unable to determine SMBv1 state: $($_.Exception.Message)"
    }

    # --- LLMNR ---
    try {
        $llmnr = Get-RegistryValueSafe -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name 'EnableMulticast' -DefaultValue $null
        if ($llmnr -eq 0) {
            Add-AuditResult -Category 'Network Architecture & Protocol Hardening' -Control 'Link-Local Multicast Name Resolution (LLMNR)' -Status 'PASS' -Severity 'High' `
                -CurrentValue 'Disabled' -RecommendedValue 'Disabled' -CIS_Control 'CIS 4.7' -NIST_Control 'SC-8, CM-7' -MITRE_Technique 'T1557.001 (LLMNR/NBT-NS Poisoning and SMB Relay)' `
                -ISO27001_Control 'A.8.20' -NIS2_Article 'Art.21(2)(d)' -NSA_Guidance 'NSA/CISA Reduce Exposure - Network Protocol Poisoning' -Recommendation 'No action required.'
        } else {
            Add-AuditResult -Category 'Network Architecture & Protocol Hardening' -Control 'Link-Local Multicast Name Resolution (LLMNR)' -Status 'FAIL' -Severity 'High' `
                -CurrentValue 'Enabled / Not Configured' -RecommendedValue 'Disabled' -CIS_Control 'CIS 4.7' -NIST_Control 'SC-8, CM-7' -MITRE_Technique 'T1557.001 (LLMNR/NBT-NS Poisoning and SMB Relay)' `
                -ISO27001_Control 'A.8.20' -NIS2_Article 'Art.21(2)(d)' -NSA_Guidance 'NSA/CISA Reduce Exposure - Network Protocol Poisoning' `
                -Recommendation 'Set GPO "Turn OFF Multicast Name Resolution" (Computer Configuration > Administrative Templates > Network > DNS Client) to Enabled, which writes EnableMulticast=0. Tools such as Responder abuse LLMNR for credential relay.'
        }
    } catch {
        Add-AuditResult -Category 'Network Architecture & Protocol Hardening' -Control 'LLMNR' -Status 'WARN' -Severity 'Low' -CurrentValue 'Query failed' `
            -Recommendation "Unable to determine LLMNR state: $($_.Exception.Message)"
    }

    # --- NetBIOS over TCP/IP (per adapter) ---
    try {
        $adapters = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' -ErrorAction Stop
        $enabledAdapters = @($adapters | Where-Object { $_.TcpipNetbiosOptions -ne 2 })
        if ($enabledAdapters.Count -eq 0) {
            Add-AuditResult -Category 'Network Architecture & Protocol Hardening' -Control 'NetBIOS over TCP/IP' -Status 'PASS' -Severity 'Medium' `
                -CurrentValue 'Disabled on all active adapters' -RecommendedValue 'Disabled' -CIS_Control 'CIS 4.7' -NIST_Control 'SC-8, CM-7' `
                -MITRE_Technique 'T1557.001 (LLMNR/NBT-NS Poisoning and SMB Relay)' -ISO27001_Control 'A.8.20' -NIS2_Article 'Art.21(2)(d)' `
                -NSA_Guidance 'NSA/CISA Reduce Exposure - Network Protocol Poisoning' -Recommendation 'No action required.'
        } else {
            Add-AuditResult -Category 'Network Architecture & Protocol Hardening' -Control 'NetBIOS over TCP/IP' -Status 'FAIL' -Severity 'Medium' `
                -CurrentValue "Enabled on $($enabledAdapters.Count) adapter(s)" -RecommendedValue 'Disabled' -CIS_Control 'CIS 4.7' -NIST_Control 'SC-8, CM-7' `
                -MITRE_Technique 'T1557.001 (LLMNR/NBT-NS Poisoning and SMB Relay)' -ISO27001_Control 'A.8.20' -NIS2_Article 'Art.21(2)(d)' `
                -NSA_Guidance 'NSA/CISA Reduce Exposure - Network Protocol Poisoning' `
                -Recommendation 'Disable NetBIOS over TCP/IP on each adapter: (Get-WmiObject Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True") | ForEach-Object { $_.SetTcpipNetbios(2) }, or set via adapter TCP/IPv4 WINS tab.'
        }
    } catch {
        Add-AuditResult -Category 'Network Architecture & Protocol Hardening' -Control 'NetBIOS over TCP/IP' -Status 'WARN' -Severity 'Low' -CurrentValue 'Query failed' `
            -Recommendation "Unable to enumerate adapter NetBIOS configuration: $($_.Exception.Message)"
    }

    # --- mDNS ---
    try {
        $mdns = Get-RegistryValueSafe -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name 'EnableMDNS' -DefaultValue $null
        if ($mdns -eq 0) {
            Add-AuditResult -Category 'Network Architecture & Protocol Hardening' -Control 'Multicast DNS (mDNS)' -Status 'PASS' -Severity 'Medium' `
                -CurrentValue 'Disabled' -RecommendedValue 'Disabled' -CIS_Control 'CIS 4.7' -NIST_Control 'SC-8, CM-7' -MITRE_Technique 'T1557.001 (LLMNR/NBT-NS Poisoning and SMB Relay)' `
                -ISO27001_Control 'A.8.20' -NIS2_Article 'Art.21(2)(d)' -NSA_Guidance 'NSA/CISA Reduce Exposure - Network Protocol Poisoning' -Recommendation 'No action required.'
        } else {
            Add-AuditResult -Category 'Network Architecture & Protocol Hardening' -Control 'Multicast DNS (mDNS)' -Status 'WARN' -Severity 'Medium' `
                -CurrentValue 'Enabled / Not Configured' -RecommendedValue 'Disabled' -CIS_Control 'CIS 4.7' -NIST_Control 'SC-8, CM-7' -ISO27001_Control 'A.8.20' `
                -NIS2_Article 'Art.21(2)(d)' -NSA_Guidance 'NSA/CISA Reduce Exposure - Network Protocol Poisoning' `
                -Recommendation 'Set GPO "Turn off multicast DNS (mDNS) client" to Enabled (writes EnableMDNS=0) where mDNS/Bonjour-style discovery is not operationally required.'
        }
    } catch {
        Add-AuditResult -Category 'Network Architecture & Protocol Hardening' -Control 'Multicast DNS (mDNS)' -Status 'INFO' -Severity 'Informational' -CurrentValue 'Not evaluated' `
            -Recommendation "mDNS policy could not be evaluated: $($_.Exception.Message)"
    }

    # --- WPAD / WinHTTP AutoProxy ---
    try {
        $wpadSvc = Get-Service -Name 'WinHttpAutoProxySvc' -ErrorAction SilentlyContinue
        if ($wpadSvc -and $wpadSvc.StartType -eq 'Disabled') {
            Add-AuditResult -Category 'Network Architecture & Protocol Hardening' -Control 'WPAD Auto-Discovery (WinHTTP AutoProxy)' -Status 'PASS' -Severity 'Medium' `
                -CurrentValue 'WinHttpAutoProxySvc Disabled' -RecommendedValue 'Disabled unless proxy auto-discovery is explicitly required' -CIS_Control 'CIS 4.7' `
                -NIST_Control 'SC-8, CM-7' -MITRE_Technique 'T1557 (Adversary-in-the-Middle)' -ISO27001_Control 'A.8.20' -NIS2_Article 'Art.21(2)(d)' `
                -NSA_Guidance 'NSA/CISA Reduce Exposure - Network Protocol Poisoning' -Recommendation 'No action required.'
        } else {
            $state = if ($wpadSvc) { $wpadSvc.StartType } else { 'Not Present' }
            Add-AuditResult -Category 'Network Architecture & Protocol Hardening' -Control 'WPAD Auto-Discovery (WinHTTP AutoProxy)' -Status 'WARN' -Severity 'Medium' `
                -CurrentValue "WinHttpAutoProxySvc StartType=$state" -RecommendedValue 'Disabled unless proxy auto-discovery is explicitly required' -CIS_Control 'CIS 4.7' `
                -NIST_Control 'SC-8, CM-7' -MITRE_Technique 'T1557 (Adversary-in-the-Middle)' -ISO27001_Control 'A.8.20' -NIS2_Article 'Art.21(2)(d)' `
                -NSA_Guidance 'NSA/CISA Reduce Exposure - Network Protocol Poisoning' `
                -Recommendation 'If WPAD is not required, disable it: Set-Service WinHttpAutoProxySvc -StartupType Disabled, and disable "Automatically detect settings" in WinINET/proxy configuration to prevent rogue WPAD server spoofing.'
        }
    } catch {
        Add-AuditResult -Category 'Network Architecture & Protocol Hardening' -Control 'WPAD Auto-Discovery' -Status 'WARN' -Severity 'Low' -CurrentValue 'Query failed' `
            -Recommendation "Unable to determine WPAD/WinHTTP AutoProxy state: $($_.Exception.Message)"
    }
}

function Test-RDPAndAdminShares {
    <#
        Audits Remote Desktop enablement, Network Level Authentication enforcement, and
        default administrative share exposure (C$, ADMIN$).
    #>
    Write-SectionBanner 'Network Architecture - Remote Access & Administrative Shares'
    try {
        $tsPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
        $denyConnections = Get-RegistryValueSafe -Path $tsPath -Name 'fDenyTSConnections' -DefaultValue 1
        $rdpEnabled = [int]$denyConnections -eq 0

        if (-not $rdpEnabled) {
            Add-AuditResult -Category 'Network Architecture & Protocol Hardening' -Control 'Remote Desktop Protocol (RDP) State' -Status 'PASS' -Severity 'Medium' `
                -CurrentValue 'Disabled' -RecommendedValue 'Disabled unless required; if required, enforce NLA + restrict source IPs' -CIS_Control 'CIS 4.9' `
                -NIST_Control 'AC-17, SC-7' -MITRE_Technique 'T1021.001 (Remote Desktop Protocol)' -ISO27001_Control 'A.8.20' -NIS2_Article 'Art.21(2)(j)' `
                -NSA_Guidance 'NSA/CISA Selecting Secure Remote Access Solutions' -Recommendation 'No action required.'
        } else {
            $nlaPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
            $nla = Get-RegistryValueSafe -Path $nlaPath -Name 'UserAuthentication' -DefaultValue 0
            if ([int]$nla -eq 1) {
                Add-AuditResult -Category 'Network Architecture & Protocol Hardening' -Control 'Remote Desktop Protocol (RDP) State' -Status 'WARN' -Severity 'Medium' `
                    -CurrentValue 'Enabled with NLA enforced' -RecommendedValue 'Disabled unless required; if required, enforce NLA + restrict source IPs' -CIS_Control 'CIS 4.9' `
                    -NIST_Control 'AC-17, SC-7' -MITRE_Technique 'T1021.001 (Remote Desktop Protocol)' -ISO27001_Control 'A.8.20' -NIS2_Article 'Art.21(2)(j)' `
                    -NSA_Guidance 'NSA/CISA Selecting Secure Remote Access Solutions' `
                    -Recommendation 'RDP is enabled and NLA is enforced (acceptable if business-required). Ensure access is further restricted via firewall scoping, VPN/Zero Trust gateway, and MFA-enforcing Conditional Access rather than direct internet exposure.'
                Add-AuditResult -Category 'Network Architecture & Protocol Hardening' -Control 'RDP Network Level Authentication (NLA)' -Status 'PASS' -Severity 'High' `
                    -CurrentValue 'Enforced' -RecommendedValue 'Enforced' -CIS_Control 'CIS 4.9' -NIST_Control 'IA-2, AC-17' -MITRE_Technique 'T1021.001 (Remote Desktop Protocol)' `
                    -ISO27001_Control 'A.8.20' -NIS2_Article 'Art.21(2)(j)' -NSA_Guidance 'NSA/CISA Selecting Secure Remote Access Solutions' -Recommendation 'No action required.'
            } else {
                Add-AuditResult -Category 'Network Architecture & Protocol Hardening' -Control 'Remote Desktop Protocol (RDP) State' -Status 'FAIL' -Severity 'High' `
                    -CurrentValue 'Enabled without NLA' -RecommendedValue 'Disabled unless required; if required, enforce NLA + restrict source IPs' -CIS_Control 'CIS 4.9' `
                    -NIST_Control 'AC-17, SC-7' -MITRE_Technique 'T1021.001 (Remote Desktop Protocol)' -ISO27001_Control 'A.8.20' -NIS2_Article 'Art.21(2)(j)' `
                    -NSA_Guidance 'NSA/CISA Selecting Secure Remote Access Solutions' `
                    -Recommendation 'Enable NLA immediately (GPO: "Require user authentication for remote connections by using Network Level Authentication"), and disable RDP entirely unless there is an explicit business need.'
                Add-AuditResult -Category 'Network Architecture & Protocol Hardening' -Control 'RDP Network Level Authentication (NLA)' -Status 'FAIL' -Severity 'High' `
                    -CurrentValue 'Not Enforced' -RecommendedValue 'Enforced' -CIS_Control 'CIS 4.9' -NIST_Control 'IA-2, AC-17' -MITRE_Technique 'T1021.001 (Remote Desktop Protocol)' `
                    -ISO27001_Control 'A.8.20' -NIS2_Article 'Art.21(2)(j)' -NSA_Guidance 'NSA/CISA Selecting Secure Remote Access Solutions' `
                    -Recommendation 'Set UserAuthentication=1 on the RDP-Tcp WinStation via GPO to require pre-session credential authentication and reduce exposure to unauthenticated RDP exploits (e.g. BlueKeep-class vulnerabilities).'
            }
        }

        $autoShareWks = Get-RegistryValueSafe -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'AutoShareWks' -DefaultValue 1
        if ([int]$autoShareWks -eq 0) {
            Add-AuditResult -Category 'Network Architecture & Protocol Hardening' -Control 'Default Administrative Shares (C$, ADMIN$)' -Status 'PASS' -Severity 'Medium' `
                -CurrentValue 'AutoShareWks=0 (Disabled)' -RecommendedValue 'Disabled where not operationally required' -CIS_Control 'CIS 4.9' -NIST_Control 'AC-6, SC-7' `
                -MITRE_Technique 'T1021.002 (SMB/Windows Admin Shares)' -ISO27001_Control 'A.8.20' -NIS2_Article 'Art.21(2)(d)' -Recommendation 'No action required.'
        } else {
            Add-AuditResult -Category 'Network Architecture & Protocol Hardening' -Control 'Default Administrative Shares (C$, ADMIN$)' -Status 'WARN' -Severity 'Medium' `
                -CurrentValue 'Enabled (default)' -RecommendedValue 'Disabled where not operationally required' -CIS_Control 'CIS 4.9' -NIST_Control 'AC-6, SC-7' `
                -MITRE_Technique 'T1021.002 (SMB/Windows Admin Shares)' -ISO27001_Control 'A.8.20' -NIS2_Article 'Art.21(2)(d)' `
                -Recommendation 'Default admin shares enable lateral movement via tools like PsExec once credentials are compromised. If remote management tooling (SCCM/Intune remote help, backup agents) does not require them, set AutoShareWks (DWORD) = 0 under LanmanServer\Parameters and restart the Server service.'
        }
    } catch {
        Add-AuditResult -Category 'Network Architecture & Protocol Hardening' -Control 'Remote Access & Administrative Shares' -Status 'WARN' -Severity 'Low' `
            -CurrentValue 'Query failed' -Recommendation "Unable to complete RDP/admin-share audit: $($_.Exception.Message)"
    }
}

function Test-SMBSigningAndEncryption {
    <#
        Audits SMB client/server signing enforcement and server-side SMB encryption.
    #>
    Write-SectionBanner 'Network Architecture - SMB Transport Security'
    try {
        $serverCfg = Get-SmbServerConfiguration -ErrorAction Stop
        $clientCfg = Get-SmbClientConfiguration -ErrorAction Stop

        if ($serverCfg.RequireSecuritySignature) {
            Add-AuditResult -Category 'Network Architecture & Protocol Hardening' -Control 'SMB Server Signing Requirement' -Status 'PASS' -Severity 'High' `
                -CurrentValue 'Required' -RecommendedValue 'Required' -CIS_Control 'CIS 4.7' -NIST_Control 'SC-8, SC-23' -MITRE_Technique 'T1557.001 (LLMNR/NBT-NS Poisoning and SMB Relay)' `
                -ISO27001_Control 'A.8.20' -NIS2_Article 'Art.21(2)(d)' -NSA_Guidance 'NSA/CISA Guidance on SMB Signing' -Recommendation 'No action required.'
        } else {
            Add-AuditResult -Category 'Network Architecture & Protocol Hardening' -Control 'SMB Server Signing Requirement' -Status 'FAIL' -Severity 'High' `
                -CurrentValue 'Not Required' -RecommendedValue 'Required' -CIS_Control 'CIS 4.7' -NIST_Control 'SC-8, SC-23' -MITRE_Technique 'T1557.001 (LLMNR/NBT-NS Poisoning and SMB Relay)' `
                -ISO27001_Control 'A.8.20' -NIS2_Article 'Art.21(2)(d)' -NSA_Guidance 'NSA/CISA Guidance on SMB Signing' `
                -Recommendation 'Set-SmbServerConfiguration -RequireSecuritySignature $true to prevent SMB relay attacks.'
        }

        if ($clientCfg.RequireSecuritySignature) {
            Add-AuditResult -Category 'Network Architecture & Protocol Hardening' -Control 'SMB Client Signing Requirement' -Status 'PASS' -Severity 'High' `
                -CurrentValue 'Required' -RecommendedValue 'Required' -CIS_Control 'CIS 4.7' -NIST_Control 'SC-8, SC-23' -MITRE_Technique 'T1557.001 (LLMNR/NBT-NS Poisoning and SMB Relay)' `
                -ISO27001_Control 'A.8.20' -NIS2_Article 'Art.21(2)(d)' -NSA_Guidance 'NSA/CISA Guidance on SMB Signing' -Recommendation 'No action required.'
        } else {
            Add-AuditResult -Category 'Network Architecture & Protocol Hardening' -Control 'SMB Client Signing Requirement' -Status 'FAIL' -Severity 'High' `
                -CurrentValue 'Not Required' -RecommendedValue 'Required' -CIS_Control 'CIS 4.7' -NIST_Control 'SC-8, SC-23' -MITRE_Technique 'T1557.001 (LLMNR/NBT-NS Poisoning and SMB Relay)' `
                -ISO27001_Control 'A.8.20' -NIS2_Article 'Art.21(2)(d)' -NSA_Guidance 'NSA/CISA Guidance on SMB Signing' `
                -Recommendation 'Set-SmbClientConfiguration -RequireSecuritySignature $true so this endpoint refuses to talk to unsigned/rogue SMB servers.'
        }

        if ($serverCfg.EncryptData) {
            Add-AuditResult -Category 'Network Architecture & Protocol Hardening' -Control 'SMB Encryption (Server)' -Status 'PASS' -Severity 'Medium' `
                -CurrentValue 'Enabled' -RecommendedValue 'Enabled (SMB 3.1.1, AES-128/256-GCM)' -CIS_Control 'CIS 4.7' -NIST_Control 'SC-8, SC-13' -ISO27001_Control 'A.8.24' `
                -NIS2_Article 'Art.21(2)(h)' -Recommendation 'No action required.'
        } else {
            Add-AuditResult -Category 'Network Architecture & Protocol Hardening' -Control 'SMB Encryption (Server)' -Status 'WARN' -Severity 'Medium' `
                -CurrentValue 'Disabled' -RecommendedValue 'Enabled (SMB 3.1.1, AES-128/256-GCM)' -CIS_Control 'CIS 4.7' -NIST_Control 'SC-8, SC-13' -ISO27001_Control 'A.8.24' `
                -NIS2_Article 'Art.21(2)(h)' -Recommendation 'Set-SmbServerConfiguration -EncryptData $true for confidentiality of SMB traffic in transit, particularly on shared/untrusted network segments.'
        }
    } catch {
        Add-AuditResult -Category 'Network Architecture & Protocol Hardening' -Control 'SMB Transport Security' -Status 'WARN' -Severity 'Low' `
            -CurrentValue 'Query failed' -Recommendation "Unable to query SMB client/server configuration: $($_.Exception.Message)"
    }
}

#endregion

#region ============================== 9. CRYPTOGRAPHY, SCHANNEL & SECURE CHANNELS ==============================

function Test-SchannelProtocols {
    <#
        Audits the enabled/disabled state of every SSL/TLS protocol version, for both Client
        and Server roles, under the Schannel protocol registry tree.
    #>
    Write-SectionBanner 'Cryptography & Schannel - Protocol Hardening'
    try {
        $basePath = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols'
        $legacyProtocols = @('SSL 2.0', 'SSL 3.0', 'TLS 1.0', 'TLS 1.1')
        $modernProtocols = @('TLS 1.2', 'TLS 1.3')

        foreach ($proto in $legacyProtocols) {
            foreach ($role in @('Client', 'Server')) {
                $path = Join-Path -Path $basePath -ChildPath "$proto\$role"
                $enabled = Get-RegistryValueSafe -Path $path -Name 'Enabled' -DefaultValue $null
                $disabledByDefault = Get-RegistryValueSafe -Path $path -Name 'DisabledByDefault' -DefaultValue $null

                # Interpreted as explicitly disabled if Enabled=0, or DisabledByDefault=1 with no Enabled override.
                $isExplicitlyDisabled = ($enabled -eq 0) -or ($disabledByDefault -eq 1 -and $enabled -ne 1)

                if ($isExplicitlyDisabled) {
                    Add-AuditResult -Category 'Cryptography, Schannel & Secure Channels' -Control "Schannel Protocol - $proto ($role)" -Status 'PASS' -Severity 'High' `
                        -CurrentValue 'Disabled' -RecommendedValue 'Disabled' -CIS_Control 'CIS 3.10' -NIST_Control 'SC-8, SC-13' -MITRE_Technique 'T1600 (Weaken Encryption)' `
                        -ISO27001_Control 'A.8.24' -NIS2_Article 'Art.21(2)(h)' -NSA_Guidance 'NSA CSI: CNSA 2.0 Cryptographic Guidance' -Recommendation 'No action required.'
                } else {
                    Add-AuditResult -Category 'Cryptography, Schannel & Secure Channels' -Control "Schannel Protocol - $proto ($role)" -Status 'FAIL' -Severity 'High' `
                        -CurrentValue 'Enabled / Not Explicitly Disabled' -RecommendedValue 'Disabled' -CIS_Control 'CIS 3.10' -NIST_Control 'SC-8, SC-13' `
                        -MITRE_Technique 'T1600 (Weaken Encryption), T1557 (Adversary-in-the-Middle)' -ISO27001_Control 'A.8.24' -NIS2_Article 'Art.21(2)(h)' `
                        -NSA_Guidance 'NSA CSI: CNSA 2.0 Cryptographic Guidance' `
                        -Recommendation "Create/Set registry values Enabled=0 and DisabledByDefault=1 under HKLM:\...\SCHANNEL\Protocols\$proto\$role to disable this deprecated, cryptographically weak protocol version."
                }
            }
        }

        foreach ($proto in $modernProtocols) {
            foreach ($role in @('Client', 'Server')) {
                $path = Join-Path -Path $basePath -ChildPath "$proto\$role"
                $enabled = Get-RegistryValueSafe -Path $path -Name 'Enabled' -DefaultValue $null
                $disabledByDefault = Get-RegistryValueSafe -Path $path -Name 'DisabledByDefault' -DefaultValue $null

                $isExplicitlyDisabled = ($enabled -eq 0) -or ($disabledByDefault -eq 1 -and $enabled -ne 1)

                if (-not $isExplicitlyDisabled) {
                    Add-AuditResult -Category 'Cryptography, Schannel & Secure Channels' -Control "Schannel Protocol - $proto ($role)" -Status 'PASS' -Severity 'Medium' `
                        -CurrentValue 'Enabled (OS default or explicit)' -RecommendedValue 'Enabled' -CIS_Control 'CIS 3.10' -NIST_Control 'SC-8, SC-13' -ISO27001_Control 'A.8.24' `
                        -NIS2_Article 'Art.21(2)(h)' -NSA_Guidance 'NSA CSI: CNSA 2.0 Cryptographic Guidance' -Recommendation 'No action required.'
                } else {
                    Add-AuditResult -Category 'Cryptography, Schannel & Secure Channels' -Control "Schannel Protocol - $proto ($role)" -Status 'FAIL' -Severity 'Medium' `
                        -CurrentValue 'Disabled' -RecommendedValue 'Enabled' -CIS_Control 'CIS 3.10' -NIST_Control 'SC-8, SC-13' -ISO27001_Control 'A.8.24' -NIS2_Article 'Art.21(2)(h)' `
                        -NSA_Guidance 'NSA CSI: CNSA 2.0 Cryptographic Guidance' `
                        -Recommendation "$proto ($role) is disabled. Remove/correct the Enabled and DisabledByDefault registry values under HKLM:\...\SCHANNEL\Protocols\$proto\$role - disabling modern TLS breaks secure connectivity."
                }
            }
        }
    } catch {
        Add-AuditResult -Category 'Cryptography, Schannel & Secure Channels' -Control 'Schannel Protocol Hardening' -Status 'WARN' -Severity 'Low' `
            -CurrentValue 'Query failed' -Recommendation "Unable to enumerate Schannel protocol registry state: $($_.Exception.Message)"
    }
}

function Test-CipherSuitesAndHashing {
    <#
        Audits the enabled TLS cipher suite priority list via Get-TlsCipherSuite, flagging
        any suite that includes a weak cipher (RC4, 3DES/DES, NULL) or a weak hash/MAC
        (MD5, SHA-1) in its name.
    #>
    Write-SectionBanner 'Cryptography & Schannel - Cipher Suite & Hash Integrity'
    try {
        $suites = Get-TlsCipherSuite -ErrorAction Stop
        if (-not $suites -or $suites.Count -eq 0) { throw 'No cipher suites returned' }

        $weakPatterns = @('RC4', '3DES', '_DES_', 'NULL', 'EXPORT', 'MD5')
        $weakSuites = @($suites | Where-Object {
            $name = $_.Name
            $isWeak = $false
            foreach ($p in $weakPatterns) { if ($name -match $p) { $isWeak = $true } }
            $isWeak
        })

        if ($weakSuites.Count -eq 0) {
            Add-AuditResult -Category 'Cryptography, Schannel & Secure Channels' -Control 'Weak Cipher Suite Exposure' -Status 'PASS' -Severity 'High' `
                -CurrentValue "$($suites.Count) suites enabled; none flagged as weak (RC4/3DES/NULL/EXPORT/MD5)" -RecommendedValue 'No RC4, 3DES, NULL, EXPORT, or MD5-based suites enabled' `
                -CIS_Control 'CIS 3.10' -NIST_Control 'SC-8, SC-13' -MITRE_Technique 'T1600 (Weaken Encryption)' -ISO27001_Control 'A.8.24' -NIS2_Article 'Art.21(2)(h)' `
                -NSA_Guidance 'NSA CSI: CNSA 2.0 Cryptographic Guidance' -Recommendation 'No action required.'
        } else {
            $names = ($weakSuites | Select-Object -First 10 -ExpandProperty Name) -join ', '
            Add-AuditResult -Category 'Cryptography, Schannel & Secure Channels' -Control 'Weak Cipher Suite Exposure' -Status 'FAIL' -Severity 'High' `
                -CurrentValue "$($weakSuites.Count) weak suite(s) enabled: $names" -RecommendedValue 'No RC4, 3DES, NULL, EXPORT, or MD5-based suites enabled' `
                -CIS_Control 'CIS 3.10' -NIST_Control 'SC-8, SC-13' -MITRE_Technique 'T1600 (Weaken Encryption)' -ISO27001_Control 'A.8.24' -NIS2_Article 'Art.21(2)(h)' `
                -NSA_Guidance 'NSA CSI: CNSA 2.0 Cryptographic Guidance' `
                -Recommendation 'Remove weak suites with Disable-TlsCipherSuite -Name "<SuiteName>" for each flagged entry, or apply the "SSL Cipher Suite Order" GPO with an approved modern-only suite list (AES-GCM, ECDHE, SHA-256/384).'
        }

        # Weak hashing algorithm policy check (Schannel Hashes subkey - MD5/SHA1 explicit enablement).
        $hashBase = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes'
        foreach ($hashAlg in @('MD5', 'SHA')) {
            $enabled = Get-RegistryValueSafe -Path (Join-Path $hashBase $hashAlg) -Name 'Enabled' -DefaultValue $null
            if ($enabled -eq 0) {
                Add-AuditResult -Category 'Cryptography, Schannel & Secure Channels' -Control "Schannel Hashing Algorithm - $hashAlg" -Status 'PASS' -Severity 'Medium' `
                    -CurrentValue 'Disabled' -RecommendedValue 'Disabled (use SHA-256/384/512 only)' -CIS_Control 'CIS 3.10' -NIST_Control 'SC-13' -ISO27001_Control 'A.8.24' `
                    -NIS2_Article 'Art.21(2)(h)' -NSA_Guidance 'NSA CSI: CNSA 2.0 Cryptographic Guidance' -Recommendation 'No action required.'
            } elseif ($null -ne $enabled) {
                Add-AuditResult -Category 'Cryptography, Schannel & Secure Channels' -Control "Schannel Hashing Algorithm - $hashAlg" -Status 'FAIL' -Severity 'Medium' `
                    -CurrentValue 'Enabled' -RecommendedValue 'Disabled (use SHA-256/384/512 only)' -CIS_Control 'CIS 3.10' -NIST_Control 'SC-13' -ISO27001_Control 'A.8.24' `
                    -NIS2_Article 'Art.21(2)(h)' -NSA_Guidance 'NSA CSI: CNSA 2.0 Cryptographic Guidance' `
                    -Recommendation "Disable the legacy $hashAlg hashing algorithm under Schannel by setting Enabled=0 at $hashBase\$hashAlg."
            } else {
                Add-AuditResult -Category 'Cryptography, Schannel & Secure Channels' -Control "Schannel Hashing Algorithm - $hashAlg" -Status 'INFO' -Severity 'Informational' `
                    -CurrentValue 'Not explicitly configured (OS default applies)' -RecommendedValue 'Explicitly disabled' -CIS_Control 'CIS 3.10' -NIST_Control 'SC-13' `
                    -Recommendation "Consider explicitly disabling $hashAlg via Schannel policy for defense in depth, even though modern Windows defaults exclude it from negotiation."
            }
        }
    } catch {
        Add-AuditResult -Category 'Cryptography, Schannel & Secure Channels' -Control 'Cipher Suite & Hash Integrity' -Status 'WARN' -Severity 'Low' `
            -CurrentValue 'Query failed' -Recommendation "Unable to enumerate TLS cipher suites: $($_.Exception.Message)"
    }
}

#endregion

#region ============================== 10. POWERSHELL SUBSYSTEM & EXECUTION SECURITY ==============================

function Test-PowerShellSecurity {
    <#
        Audits removal of the legacy PowerShell v2 engine, Script Block/Module/Transcription
        logging, execution policy, and Constrained Language Mode.
    #>
    Write-SectionBanner 'PowerShell Subsystem & Execution Security'
    try {
        try {
            $psv2 = Get-WindowsOptionalFeature -Online -FeatureName 'MicrosoftWindowsPowerShellV2Root' -ErrorAction Stop
            if ($psv2.State -eq 'Disabled') {
                Add-AuditResult -Category 'PowerShell Subsystem & Execution Security' -Control 'Legacy PowerShell v2 Engine' -Status 'PASS' -Severity 'Medium' `
                    -CurrentValue 'Disabled' -RecommendedValue 'Disabled' -CIS_Control 'CIS 2.5' -NIST_Control 'CM-7' -MITRE_Technique 'T1059.001 (PowerShell)' `
                    -ISO27001_Control 'A.8.19' -NIS2_Article 'Art.21(2)(e)' -NSA_Guidance 'NSA/CISA PowerShell Security Best Practices' -Recommendation 'No action required.'
            } else {
                Add-AuditResult -Category 'PowerShell Subsystem & Execution Security' -Control 'Legacy PowerShell v2 Engine' -Status 'FAIL' -Severity 'Medium' `
                    -CurrentValue "$($psv2.State)" -RecommendedValue 'Disabled' -CIS_Control 'CIS 2.5' -NIST_Control 'CM-7' -MITRE_Technique 'T1059.001 (PowerShell), T1562.001 (Disable or Modify Tools)' `
                    -ISO27001_Control 'A.8.19' -NIS2_Article 'Art.21(2)(e)' -NSA_Guidance 'NSA/CISA PowerShell Security Best Practices' `
                    -Recommendation 'Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root. PowerShell v2 lacks AMSI/ScriptBlock logging and is commonly abused to bypass modern PowerShell telemetry.'
            }
        } catch {
            Add-AuditResult -Category 'PowerShell Subsystem & Execution Security' -Control 'Legacy PowerShell v2 Engine' -Status 'INFO' -Severity 'Informational' `
                -CurrentValue 'Unable to query optional feature state' -RecommendedValue 'Disabled' -Recommendation "Verify manually via Get-WindowsOptionalFeature: $($_.Exception.Message)"
        }

        $psLogPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell'
        $sbLogging = Get-RegistryValueSafe -Path (Join-Path $psLogPath 'ScriptBlockLogging') -Name 'EnableScriptBlockLogging' -DefaultValue 0
        $moduleLogging = Get-RegistryValueSafe -Path (Join-Path $psLogPath 'ModuleLogging') -Name 'EnableModuleLogging' -DefaultValue 0
        $transcription = Get-RegistryValueSafe -Path (Join-Path $psLogPath 'Transcription') -Name 'EnableTranscripting' -DefaultValue 0

        $loggingChecks = @(
            @{ Name = 'Script Block Logging'; Value = $sbLogging; Mitre = 'T1059.001 (PowerShell), T1027 (Obfuscated Files or Information)' }
            @{ Name = 'Module Logging'; Value = $moduleLogging; Mitre = 'T1059.001 (PowerShell)' }
            @{ Name = 'Transcription Logging'; Value = $transcription; Mitre = 'T1059.001 (PowerShell)' }
        )
        foreach ($c in $loggingChecks) {
            if ([int]$c.Value -eq 1) {
                Add-AuditResult -Category 'PowerShell Subsystem & Execution Security' -Control "PowerShell $($c.Name)" -Status 'PASS' -Severity 'High' `
                    -CurrentValue 'Enabled' -RecommendedValue 'Enabled' -CIS_Control 'CIS 8.5' -NIST_Control 'AU-2, AU-12' -MITRE_Technique $c.Mitre `
                    -ISO27001_Control 'A.8.15' -NIS2_Article 'Art.21(2)(b)' -NSA_Guidance 'NSA/CISA PowerShell Security Best Practices' -Recommendation 'No action required.'
            } else {
                Add-AuditResult -Category 'PowerShell Subsystem & Execution Security' -Control "PowerShell $($c.Name)" -Status 'FAIL' -Severity 'High' `
                    -CurrentValue 'Disabled' -RecommendedValue 'Enabled' -CIS_Control 'CIS 8.5' -NIST_Control 'AU-2, AU-12' -MITRE_Technique $c.Mitre `
                    -ISO27001_Control 'A.8.15' -NIS2_Article 'Art.21(2)(b)' -NSA_Guidance 'NSA/CISA PowerShell Security Best Practices' `
                    -Recommendation "Enable via GPO: Administrative Templates > Windows Components > Windows PowerShell > `"Turn on $($c.Name)`". This is essential telemetry for detecting living-off-the-land PowerShell abuse."
            }
        }

        $execPolicy = Get-ExecutionPolicy -Scope LocalMachine -ErrorAction SilentlyContinue
        if ($execPolicy -in @('AllSigned', 'RemoteSigned', 'Restricted')) {
            Add-AuditResult -Category 'PowerShell Subsystem & Execution Security' -Control 'PowerShell Execution Policy' -Status 'PASS' -Severity 'Medium' `
                -CurrentValue "$execPolicy" -RecommendedValue 'AllSigned or RemoteSigned' -CIS_Control 'CIS 2.5' -NIST_Control 'CM-7' -MITRE_Technique 'T1059.001 (PowerShell)' `
                -ISO27001_Control 'A.8.19' -NIS2_Article 'Art.21(2)(e)' -Recommendation 'No action required.'
        } else {
            Add-AuditResult -Category 'PowerShell Subsystem & Execution Security' -Control 'PowerShell Execution Policy' -Status 'FAIL' -Severity 'Medium' `
                -CurrentValue "$execPolicy" -RecommendedValue 'AllSigned or RemoteSigned' -CIS_Control 'CIS 2.5' -NIST_Control 'CM-7' -MITRE_Technique 'T1059.001 (PowerShell)' `
                -ISO27001_Control 'A.8.19' -NIS2_Article 'Art.21(2)(e)' `
                -Recommendation 'Set-ExecutionPolicy RemoteSigned -Scope LocalMachine (or AllSigned for higher assurance). Note execution policy is a safety rail, not a hard security boundary - pair with AppLocker/WDAC and Script Block Logging.'
        }

        $languageMode = $ExecutionContext.SessionState.LanguageMode
        if ($languageMode -eq 'ConstrainedLanguage' -or $languageMode -eq 'FullLanguage') {
            $status = if ($languageMode -eq 'ConstrainedLanguage') { 'PASS' } else { 'INFO' }
            $severity = if ($languageMode -eq 'ConstrainedLanguage') { 'Medium' } else { 'Informational' }
            Add-AuditResult -Category 'PowerShell Subsystem & Execution Security' -Control 'PowerShell Language Mode' -Status $status -Severity $severity `
                -CurrentValue "$languageMode" -RecommendedValue 'ConstrainedLanguage (on standard-user/high-risk endpoints, via WDAC policy)' -CIS_Control 'CIS 2.5' `
                -NIST_Control 'CM-7, AC-6' -MITRE_Technique 'T1059.001 (PowerShell)' -ISO27001_Control 'A.8.19' -NIS2_Article 'Art.21(2)(e)' `
                -NSA_Guidance 'NSA/CISA PowerShell Security Best Practices' `
                -Recommendation 'FullLanguage mode allows unrestricted access to .NET types/COM/Win32 APIs from PowerShell. Deploy a WDAC policy to drive standard users into Constrained Language Mode, which blocks these primitives for non-administrators.'
        }
    } catch {
        Add-AuditResult -Category 'PowerShell Subsystem & Execution Security' -Control 'PowerShell Subsystem Security' -Status 'WARN' -Severity 'Low' `
            -CurrentValue 'Query failed' -Recommendation "Unable to complete PowerShell subsystem audit: $($_.Exception.Message)"
    }
}

#endregion

#region ============================== 11. ADVANCED SECURITY AUDITING & EVENT LOGGING ==============================

function Test-AdvancedAuditPolicy {
    <#
        Audits Advanced Audit Policy Configuration subcategories via auditpol.exe across the
        critical categories: Logon/Logoff, Privilege Use, Account Management, and Object
        Access. Also verifies command-line argument capture for process creation (Event ID
        4688).
    #>
    Write-SectionBanner 'Advanced Security Auditing & Event Logging'
    try {
        $auditCsv = & auditpol.exe /get /category:* /r 2>$null | ConvertFrom-Csv
        if (-not $auditCsv) { throw 'auditpol returned no data' }

        # Map of subcategory name -> (Category, Severity, MITRE, CIS)
        $subcategoriesToCheck = @(
            @{ Name = 'Logon'; Severity = 'High'; Mitre = 'T1078 (Valid Accounts)' }
            @{ Name = 'Logoff'; Severity = 'Low'; Mitre = 'T1078 (Valid Accounts)' }
            @{ Name = 'Account Lockout'; Severity = 'Medium'; Mitre = 'T1110 (Brute Force)' }
            @{ Name = 'Special Logon'; Severity = 'High'; Mitre = 'T1078.003 (Local Accounts)' }
            @{ Name = 'Sensitive Privilege Use'; Severity = 'High'; Mitre = 'T1548 (Abuse Elevation Control Mechanism)' }
            @{ Name = 'User Account Management'; Severity = 'High'; Mitre = 'T1136 (Create Account), T1098 (Account Manipulation)' }
            @{ Name = 'Security Group Management'; Severity = 'High'; Mitre = 'T1098 (Account Manipulation)' }
            @{ Name = 'Process Creation'; Severity = 'High'; Mitre = 'T1059 (Command and Scripting Interpreter)' }
            @{ Name = 'Audit Policy Change'; Severity = 'Medium'; Mitre = 'T1562.002 (Disable Windows Event Logging)' }
            @{ Name = 'Removable Storage'; Severity = 'Medium'; Mitre = 'T1052.001 (Exfiltration over USB)' }
        )

        foreach ($sub in $subcategoriesToCheck) {
            $row = $auditCsv | Where-Object { $_.Subcategory -eq $sub.Name } | Select-Object -First 1
            if ($row) {
                $setting = $row.'Inclusion Setting'
                $isConfigured = $setting -match 'Success' -or $setting -match 'Failure'
                if ($isConfigured) {
                    Add-AuditResult -Category 'Advanced Security Auditing & Event Logging' -Control "Advanced Audit Policy - $($sub.Name)" -Status 'PASS' -Severity $sub.Severity `
                        -CurrentValue "$setting" -RecommendedValue 'Success and Failure' -CIS_Control 'CIS 8.5' -NIST_Control 'AU-2, AU-12' -MITRE_Technique $sub.Mitre `
                        -ISO27001_Control 'A.8.15' -NIS2_Article 'Art.21(2)(b)' -NSA_Guidance 'NSA/CISA Audit Logging Best Practices' -Recommendation 'No action required.'
                } else {
                    Add-AuditResult -Category 'Advanced Security Auditing & Event Logging' -Control "Advanced Audit Policy - $($sub.Name)" -Status 'FAIL' -Severity $sub.Severity `
                        -CurrentValue "$setting" -RecommendedValue 'Success and Failure' -CIS_Control 'CIS 8.5' -NIST_Control 'AU-2, AU-12' -MITRE_Technique $sub.Mitre `
                        -ISO27001_Control 'A.8.15' -NIS2_Article 'Art.21(2)(b)' -NSA_Guidance 'NSA/CISA Audit Logging Best Practices' `
                        -Recommendation "Enable via: auditpol /set /subcategory:`"$($sub.Name)`" /success:enable /failure:enable, or the equivalent GPO under Advanced Audit Policy Configuration."
                }
            } else {
                Add-AuditResult -Category 'Advanced Security Auditing & Event Logging' -Control "Advanced Audit Policy - $($sub.Name)" -Status 'WARN' -Severity 'Low' `
                    -CurrentValue 'Subcategory not found in auditpol output' -RecommendedValue 'Success and Failure' -Recommendation 'Verify subcategory name/OS build compatibility and re-run auditpol /get /category:* manually.'
            }
        }
    } catch {
        Add-AuditResult -Category 'Advanced Security Auditing & Event Logging' -Control 'Advanced Audit Policy Configuration' -Status 'WARN' -Severity 'Low' `
            -CurrentValue 'Query failed' -Recommendation "Unable to query auditpol.exe: $($_.Exception.Message)"
    }
}

function Test-ProcessCreationLogging {
    <#
        Audits whether command-line arguments are captured in process creation events
        (Event ID 4688), which requires both the "Include command line in process creation
        events" policy and the Process Creation audit subcategory to be enabled.
    #>
    Write-SectionBanner 'Advanced Security Auditing & Event Logging - Process Creation Command-Line Logging'
    try {
        $cmdLinePath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
        $cmdLineLogging = Get-RegistryValueSafe -Path $cmdLinePath -Name 'ProcessCreationIncludeCmdLine_Enabled' -DefaultValue 0

        $processAuditEnabled = $false
        try {
            $auditCsv = & auditpol.exe /get /subcategory:"Process Creation" /r 2>$null | ConvertFrom-Csv
            if ($auditCsv) {
                $setting = ($auditCsv | Select-Object -First 1).'Inclusion Setting'
                $processAuditEnabled = $setting -match 'Success'
            }
        } catch { $processAuditEnabled = $false }

        if ([int]$cmdLineLogging -eq 1 -and $processAuditEnabled) {
            Add-AuditResult -Category 'Advanced Security Auditing & Event Logging' -Control 'Process Creation Command-Line Auditing (Event ID 4688)' -Status 'PASS' -Severity 'High' `
                -CurrentValue 'Command-line capture enabled; Process Creation auditing enabled' -RecommendedValue 'Both enabled' -CIS_Control 'CIS 8.5' `
                -NIST_Control 'AU-3, AU-12' -MITRE_Technique 'T1059 (Command and Scripting Interpreter), T1027 (Obfuscated Files or Information)' -ISO27001_Control 'A.8.15' `
                -NIS2_Article 'Art.21(2)(b)' -NSA_Guidance 'NSA/CISA Audit Logging Best Practices' -Recommendation 'No action required.'
        } else {
            Add-AuditResult -Category 'Advanced Security Auditing & Event Logging' -Control 'Process Creation Command-Line Auditing (Event ID 4688)' -Status 'FAIL' -Severity 'High' `
                -CurrentValue "CmdLineCapture=$cmdLineLogging; ProcessCreationAudit=$processAuditEnabled" -RecommendedValue 'Both enabled' -CIS_Control 'CIS 8.5' `
                -NIST_Control 'AU-3, AU-12' -MITRE_Technique 'T1059 (Command and Scripting Interpreter), T1027 (Obfuscated Files or Information)' -ISO27001_Control 'A.8.15' `
                -NIS2_Article 'Art.21(2)(b)' -NSA_Guidance 'NSA/CISA Audit Logging Best Practices' `
                -Recommendation 'Enable GPO "Include command line in process creation events" (Administrative Templates > System > Audit Process Creation) AND auditpol /set /subcategory:"Process Creation" /success:enable, so Event ID 4688 carries full command-line arguments for EDR/SIEM correlation.'
        }
    } catch {
        Add-AuditResult -Category 'Advanced Security Auditing & Event Logging' -Control 'Process Creation Command-Line Auditing (Event ID 4688)' -Status 'WARN' -Severity 'Low' `
            -CurrentValue 'Query failed' -Recommendation "Unable to determine process-creation logging state: $($_.Exception.Message)"
    }
}

#endregion

#region ============================== 12. NETWORK AUTHENTICATION & CREDENTIAL EXPOSURE HARDENING ==============================

function Test-NTLMAndAnonymousAccessHardening {
    <#
        Audits legacy LAN Manager authentication exposure: the LmCompatibilityLevel
        negotiation floor, LM hash storage, anonymous SAM/share enumeration, and whether
        "Everyone" permissions silently apply to the Anonymous Logon principal.
    #>
    Write-SectionBanner 'Network Authentication - NTLM & Anonymous Access Hardening'
    try {
        $lsaPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
        $lmLevel = Get-RegistryValueSafe -Path $lsaPath -Name 'LmCompatibilityLevel' -DefaultValue 3
        $noLmHash = Get-RegistryValueSafe -Path $lsaPath -Name 'NoLmHash' -DefaultValue 0
        $restrictAnon = Get-RegistryValueSafe -Path $lsaPath -Name 'RestrictAnonymous' -DefaultValue 0
        $restrictAnonSam = Get-RegistryValueSafe -Path $lsaPath -Name 'RestrictAnonymousSAM' -DefaultValue 0
        $everyoneIncludesAnon = Get-RegistryValueSafe -Path $lsaPath -Name 'EveryoneIncludesAnonymous' -DefaultValue 1

        if ([int]$lmLevel -eq 5) {
            Add-AuditResult -Category 'Network Authentication & Credential Exposure' -Control 'LAN Manager Authentication Level' -Status 'PASS' -Severity 'High' `
                -CurrentValue "LmCompatibilityLevel=$lmLevel (Send NTLMv2 response only, refuse LM & NTLM)" -RecommendedValue '5' -CIS_Control 'CIS 18.3' `
                -NIST_Control 'IA-5, SC-8' -MITRE_Technique 'T1557 (Adversary-in-the-Middle), T1550 (Use Alternate Authentication Material)' -ISO27001_Control 'A.8.24' `
                -NIS2_Article 'Art.21(2)(h)' -NSA_Guidance 'NSA/CISA CNSA 2.0 Cryptographic Guidance' -Recommendation 'No action required.'
        } else {
            Add-AuditResult -Category 'Network Authentication & Credential Exposure' -Control 'LAN Manager Authentication Level' -Status 'FAIL' -Severity 'High' `
                -CurrentValue "LmCompatibilityLevel=$lmLevel" -RecommendedValue '5 (Send NTLMv2 response only, refuse LM & NTLM)' -CIS_Control 'CIS 18.3' `
                -NIST_Control 'IA-5, SC-8' -MITRE_Technique 'T1557 (Adversary-in-the-Middle), T1550 (Use Alternate Authentication Material)' -ISO27001_Control 'A.8.24' `
                -NIS2_Article 'Art.21(2)(h)' -NSA_Guidance 'NSA/CISA CNSA 2.0 Cryptographic Guidance' `
                -Recommendation 'Set "Network security: LAN Manager authentication level" to "Send NTLMv2 response only. Refuse LM & NTLM" (LmCompatibilityLevel=5). Legacy LM/NTLMv1 are trivially crackable and vulnerable to relay attacks.'
        }

        if ([int]$noLmHash -eq 1) {
            Add-AuditResult -Category 'Network Authentication & Credential Exposure' -Control 'LM Hash Storage Prevention' -Status 'PASS' -Severity 'Medium' `
                -CurrentValue 'NoLmHash=1 (LM hashes not stored)' -RecommendedValue '1' -CIS_Control 'CIS 18.3' -NIST_Control 'IA-5' `
                -MITRE_Technique 'T1003 (OS Credential Dumping)' -ISO27001_Control 'A.8.24' -NIS2_Article 'Art.21(2)(h)' -Recommendation 'No action required.'
        } else {
            Add-AuditResult -Category 'Network Authentication & Credential Exposure' -Control 'LM Hash Storage Prevention' -Status 'FAIL' -Severity 'Medium' `
                -CurrentValue 'NoLmHash=0 or not configured' -RecommendedValue '1' -CIS_Control 'CIS 18.3' -NIST_Control 'IA-5' -MITRE_Technique 'T1003 (OS Credential Dumping)' `
                -ISO27001_Control 'A.8.24' -NIS2_Article 'Art.21(2)(h)' `
                -Recommendation 'Set "Network security: Do not store LAN Manager hash value on next password change" to Enabled (NoLmHash=1), then force a password change to purge any existing LM hash.'
        }

        if ([int]$restrictAnon -eq 1 -and [int]$restrictAnonSam -eq 1) {
            Add-AuditResult -Category 'Network Authentication & Credential Exposure' -Control 'Anonymous SAM/Share Enumeration Restriction' -Status 'PASS' -Severity 'High' `
                -CurrentValue "RestrictAnonymous=$restrictAnon; RestrictAnonymousSAM=$restrictAnonSam" -RecommendedValue 'Both = 1' -CIS_Control 'CIS 18.3' `
                -NIST_Control 'AC-6, IA-5' -MITRE_Technique 'T1087 (Account Discovery), T1135 (Network Share Discovery)' -ISO27001_Control 'A.8.3' -NIS2_Article 'Art.21(2)(i)' `
                -NSA_Guidance 'NSA/CISA Identity and Access Management Best Practices' -Recommendation 'No action required.'
        } else {
            Add-AuditResult -Category 'Network Authentication & Credential Exposure' -Control 'Anonymous SAM/Share Enumeration Restriction' -Status 'FAIL' -Severity 'High' `
                -CurrentValue "RestrictAnonymous=$restrictAnon; RestrictAnonymousSAM=$restrictAnonSam" -RecommendedValue 'Both = 1' -CIS_Control 'CIS 18.3' `
                -NIST_Control 'AC-6, IA-5' -MITRE_Technique 'T1087 (Account Discovery), T1135 (Network Share Discovery)' -ISO27001_Control 'A.8.3' -NIS2_Article 'Art.21(2)(i)' `
                -NSA_Guidance 'NSA/CISA Identity and Access Management Best Practices' `
                -Recommendation 'Enable "Network access: Do not allow anonymous enumeration of SAM accounts" and "...SAM accounts and shares" (RestrictAnonymousSAM=1, RestrictAnonymous=1) to prevent unauthenticated account/share reconnaissance.'
        }

        if ([int]$everyoneIncludesAnon -eq 0) {
            Add-AuditResult -Category 'Network Authentication & Credential Exposure' -Control 'Everyone Permissions Applied to Anonymous Users' -Status 'PASS' -Severity 'Medium' `
                -CurrentValue 'EveryoneIncludesAnonymous=0 (Disabled)' -RecommendedValue '0' -CIS_Control 'CIS 18.3' -NIST_Control 'AC-6' `
                -MITRE_Technique 'T1087 (Account Discovery)' -ISO27001_Control 'A.8.3' -NIS2_Article 'Art.21(2)(i)' -Recommendation 'No action required.'
        } else {
            Add-AuditResult -Category 'Network Authentication & Credential Exposure' -Control 'Everyone Permissions Applied to Anonymous Users' -Status 'FAIL' -Severity 'Medium' `
                -CurrentValue 'EveryoneIncludesAnonymous=1 (Enabled)' -RecommendedValue '0' -CIS_Control 'CIS 18.3' -NIST_Control 'AC-6' -MITRE_Technique 'T1087 (Account Discovery)' `
                -ISO27001_Control 'A.8.3' -NIS2_Article 'Art.21(2)(i)' `
                -Recommendation 'Disable "Network access: Let Everyone permissions apply to anonymous users" (EveryoneIncludesAnonymous=0) so anonymous connections do not inherit Everyone-group ACL access.'
        }
    } catch {
        Add-AuditResult -Category 'Network Authentication & Credential Exposure' -Control 'NTLM & Anonymous Access Hardening' -Status 'WARN' -Severity 'Low' `
            -CurrentValue 'Query failed' -Recommendation "Unable to complete NTLM/anonymous-access audit: $($_.Exception.Message)"
    }
}

function Test-SMBInsecureGuestLogon {
    <#
        Audits the SMB client "insecure guest logon" setting, which if enabled allows the
        client to fall back to unauthenticated/unsigned guest sessions against rogue or
        compromised SMB servers - a common ransomware staging and lateral-movement vector.
    #>
    Write-SectionBanner 'Network Authentication - SMB Insecure Guest Logon'
    try {
        $path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation'
        $allowInsecureGuest = Get-RegistryValueSafe -Path $path -Name 'AllowInsecureGuestAuth' -DefaultValue $null

        if ($allowInsecureGuest -eq 0) {
            Add-AuditResult -Category 'Network Authentication & Credential Exposure' -Control 'SMB Insecure Guest Logon' -Status 'PASS' -Severity 'High' `
                -CurrentValue 'Disabled' -RecommendedValue 'Disabled' -CIS_Control 'CIS 18.3' -NIST_Control 'IA-2, SC-8' `
                -MITRE_Technique 'T1021.002 (SMB/Windows Admin Shares), T1557 (Adversary-in-the-Middle)' -ISO27001_Control 'A.8.20' -NIS2_Article 'Art.21(2)(d)' `
                -NSA_Guidance 'NSA/CISA Guidance on SMB Signing' -Recommendation 'No action required.'
        } else {
            Add-AuditResult -Category 'Network Authentication & Credential Exposure' -Control 'SMB Insecure Guest Logon' -Status 'FAIL' -Severity 'High' `
                -CurrentValue 'Enabled / Not Configured' -RecommendedValue 'Disabled' -CIS_Control 'CIS 18.3' -NIST_Control 'IA-2, SC-8' `
                -MITRE_Technique 'T1021.002 (SMB/Windows Admin Shares), T1557 (Adversary-in-the-Middle)' -ISO27001_Control 'A.8.20' -NIS2_Article 'Art.21(2)(d)' `
                -NSA_Guidance 'NSA/CISA Guidance on SMB Signing' `
                -Recommendation 'Set GPO "Enable insecure guest logons" (Computer Configuration > Administrative Templates > Network > Lanman Workstation) to Disabled, writing AllowInsecureGuestAuth=0.'
        }
    } catch {
        Add-AuditResult -Category 'Network Authentication & Credential Exposure' -Control 'SMB Insecure Guest Logon' -Status 'WARN' -Severity 'Low' `
            -CurrentValue 'Query failed' -Recommendation "Unable to determine insecure guest logon state: $($_.Exception.Message)"
    }
}

function Test-RestrictNTLMUsage {
    <#
        Audits the "Restrict NTLM" policy pair that governs outgoing NTLM authentication to
        remote servers and incoming NTLM authentication accepted by this host - a Zero Trust
        control that pushes authentication toward Kerberos.
    #>
    Write-SectionBanner 'Network Authentication - Restrict NTLM'
    try {
        $ntlmPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'
        $outgoing = Get-RegistryValueSafe -Path $ntlmPath -Name 'RestrictSendingNTLMTraffic' -DefaultValue $null
        $incoming = Get-RegistryValueSafe -Path $ntlmPath -Name 'RestrictReceivingNTLMTraffic' -DefaultValue $null

        if ($null -ne $outgoing -and [int]$outgoing -ge 1) {
            Add-AuditResult -Category 'Network Authentication & Credential Exposure' -Control 'Restrict NTLM - Outgoing Traffic' -Status 'PASS' -Severity 'Medium' `
                -CurrentValue "RestrictSendingNTLMTraffic=$outgoing" -RecommendedValue '>=1 (Audit or Deny All)' -CIS_Control 'CIS 18.3' -NIST_Control 'IA-2, AC-17' `
                -MITRE_Technique 'T1550 (Use Alternate Authentication Material), T1557 (Adversary-in-the-Middle)' -ISO27001_Control 'A.8.5' -NIS2_Article 'Art.21(2)(i)' `
                -NSA_Guidance 'NSA/CISA Advancing Zero Trust Maturity - Device Pillar' -Recommendation 'No action required.'
        } else {
            Add-AuditResult -Category 'Network Authentication & Credential Exposure' -Control 'Restrict NTLM - Outgoing Traffic' -Status 'INFO' -Severity 'Informational' `
                -CurrentValue 'Not Configured (NTLM outgoing unrestricted)' -RecommendedValue 'Audit, then Deny All once exception list is validated' -CIS_Control 'CIS 18.3' `
                -NIST_Control 'IA-2, AC-17' -ISO27001_Control 'A.8.5' -NIS2_Article 'Art.21(2)(i)' -NSA_Guidance 'NSA/CISA Advancing Zero Trust Maturity - Device Pillar' `
                -Recommendation 'Consider "Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers" starting in Audit mode to build an exception list, then move to Deny All in mature Kerberos-first environments.'
        }

        if ($null -ne $incoming -and [int]$incoming -ge 1) {
            Add-AuditResult -Category 'Network Authentication & Credential Exposure' -Control 'Restrict NTLM - Incoming Traffic' -Status 'PASS' -Severity 'Medium' `
                -CurrentValue "RestrictReceivingNTLMTraffic=$incoming" -RecommendedValue '>=1 (Deny domain accounts or Deny All)' -CIS_Control 'CIS 18.3' -NIST_Control 'IA-2, AC-17' `
                -MITRE_Technique 'T1550 (Use Alternate Authentication Material)' -ISO27001_Control 'A.8.5' -NIS2_Article 'Art.21(2)(i)' `
                -NSA_Guidance 'NSA/CISA Advancing Zero Trust Maturity - Device Pillar' -Recommendation 'No action required.'
        } else {
            Add-AuditResult -Category 'Network Authentication & Credential Exposure' -Control 'Restrict NTLM - Incoming Traffic' -Status 'INFO' -Severity 'Informational' `
                -CurrentValue 'Not Configured (NTLM incoming unrestricted)' -RecommendedValue 'Deny domain accounts or Deny All once validated' -CIS_Control 'CIS 18.3' `
                -NIST_Control 'IA-2, AC-17' -ISO27001_Control 'A.8.5' -NIS2_Article 'Art.21(2)(i)' -NSA_Guidance 'NSA/CISA Advancing Zero Trust Maturity - Device Pillar' `
                -Recommendation 'Consider "Network security: Restrict NTLM: Incoming NTLM traffic" to reduce this host''s acceptance of legacy NTLM authentication as part of a Zero Trust, Kerberos-first posture.'
        }
    } catch {
        Add-AuditResult -Category 'Network Authentication & Credential Exposure' -Control 'Restrict NTLM Usage' -Status 'WARN' -Severity 'Low' `
            -CurrentValue 'Query failed' -Recommendation "Unable to determine Restrict NTLM policy state: $($_.Exception.Message)"
    }
}

#endregion

#region ============================== 13. PRIVILEGED ACCESS, USER RIGHTS & SESSION HARDENING ==============================

function Test-UserRightsAssignment {
    <#
        Audits a high-value subset of User Rights Assignment via secedit export: that Guest
        and unauthenticated principals are explicitly denied network/remote-interactive logon,
        and that SeDebugPrivilege (which permits reading/writing the memory of any process,
        including LSASS) is restricted to Administrators only.
    #>
    Write-SectionBanner 'Privileged Access - User Rights Assignment'
    $tempCfg = Join-Path -Path $env:TEMP -ChildPath "EndpointPostureCheck_urasecedit_$PID.cfg"
    try {
        $null = & secedit.exe /export /cfg $tempCfg /areas USER_RIGHTS /quiet 2>$null
        if (-not (Test-Path -LiteralPath $tempCfg)) { throw 'secedit export failed to produce output file' }
        $cfg = Get-Content -LiteralPath $tempCfg -ErrorAction Stop

        function Get-PrivilegeLine {
            param($lines, $key)
            $line = $lines | Where-Object { $_ -match "^\s*$key\s*=" } | Select-Object -First 1
            if ($line) { return ($line -split '=', 2)[1].Trim() }
            return ''
        }

        $guestSid = 'S-1-5-32-546'
        $denyNetwork = Get-PrivilegeLine $cfg 'SeDenyNetworkLogonRight'
        $denyRemoteInteractive = Get-PrivilegeLine $cfg 'SeDenyRemoteInteractiveLogonRight'
        $debugPrivilege = Get-PrivilegeLine $cfg 'SeDebugPrivilege'

        if ($denyNetwork -match [regex]::Escape($guestSid)) {
            Add-AuditResult -Category 'Identity, Privilege Management & Access Control' -Control 'User Right - Deny Network Logon for Guest' -Status 'PASS' -Severity 'Medium' `
                -CurrentValue 'Guests group present in SeDenyNetworkLogonRight' -RecommendedValue 'Guests group present' -CIS_Control 'CIS 5.2' -NIST_Control 'AC-6, AC-2' `
                -MITRE_Technique 'T1078.001 (Default Accounts)' -ISO27001_Control 'A.8.2' -NIS2_Article 'Art.21(2)(i)' `
                -NSA_Guidance 'NSA/CISA Identity and Access Management Best Practices' -Recommendation 'No action required.'
        } else {
            Add-AuditResult -Category 'Identity, Privilege Management & Access Control' -Control 'User Right - Deny Network Logon for Guest' -Status 'FAIL' -Severity 'Medium' `
                -CurrentValue 'Guests group NOT present in SeDenyNetworkLogonRight' -RecommendedValue 'Guests group present' -CIS_Control 'CIS 5.2' -NIST_Control 'AC-6, AC-2' `
                -MITRE_Technique 'T1078.001 (Default Accounts)' -ISO27001_Control 'A.8.2' -NIS2_Article 'Art.21(2)(i)' `
                -NSA_Guidance 'NSA/CISA Identity and Access Management Best Practices' `
                -Recommendation 'Add the Guests group to "Deny access to this computer from the network" (SeDenyNetworkLogonRight) via Local Security Policy > User Rights Assignment.'
        }

        if ($denyRemoteInteractive -match [regex]::Escape($guestSid)) {
            Add-AuditResult -Category 'Identity, Privilege Management & Access Control' -Control 'User Right - Deny Remote Interactive Logon for Guest' -Status 'PASS' -Severity 'Medium' `
                -CurrentValue 'Guests group present in SeDenyRemoteInteractiveLogonRight' -RecommendedValue 'Guests group present' -CIS_Control 'CIS 5.2' -NIST_Control 'AC-6, AC-17' `
                -MITRE_Technique 'T1078.001 (Default Accounts), T1021.001 (Remote Desktop Protocol)' -ISO27001_Control 'A.8.2' -NIS2_Article 'Art.21(2)(i)' `
                -NSA_Guidance 'NSA/CISA Identity and Access Management Best Practices' -Recommendation 'No action required.'
        } else {
            Add-AuditResult -Category 'Identity, Privilege Management & Access Control' -Control 'User Right - Deny Remote Interactive Logon for Guest' -Status 'FAIL' -Severity 'Medium' `
                -CurrentValue 'Guests group NOT present in SeDenyRemoteInteractiveLogonRight' -RecommendedValue 'Guests group present' -CIS_Control 'CIS 5.2' -NIST_Control 'AC-6, AC-17' `
                -MITRE_Technique 'T1078.001 (Default Accounts), T1021.001 (Remote Desktop Protocol)' -ISO27001_Control 'A.8.2' -NIS2_Article 'Art.21(2)(i)' `
                -NSA_Guidance 'NSA/CISA Identity and Access Management Best Practices' `
                -Recommendation 'Add the Guests group to "Deny log on through Remote Desktop Services" (SeDenyRemoteInteractiveLogonRight) via Local Security Policy > User Rights Assignment.'
        }

        $debugAssignees = ($debugPrivilege -split ',') | Where-Object { $_ -ne '' }
        $debugRestrictedToAdmins = ($debugAssignees.Count -le 1) -and ($debugPrivilege -match 'S-1-5-32-544' -or $debugPrivilege -eq '')
        if ($debugRestrictedToAdmins) {
            Add-AuditResult -Category 'Identity, Privilege Management & Access Control' -Control 'User Right - Debug Programs (SeDebugPrivilege)' -Status 'PASS' -Severity 'High' `
                -CurrentValue 'Restricted to Administrators (or unassigned)' -RecommendedValue 'Administrators only' -CIS_Control 'CIS 5.2' -NIST_Control 'AC-6' `
                -MITRE_Technique 'T1003.001 (LSASS Memory), T1055 (Process Injection)' -ISO27001_Control 'A.8.2' -NIS2_Article 'Art.21(2)(i)' `
                -NSA_Guidance 'NSA CSI: Mitigating Credential Theft' -Recommendation 'No action required.'
        } else {
            Add-AuditResult -Category 'Identity, Privilege Management & Access Control' -Control 'User Right - Debug Programs (SeDebugPrivilege)' -Status 'FAIL' -Severity 'High' `
                -CurrentValue "Assigned to $($debugAssignees.Count) principal(s) beyond Administrators" -RecommendedValue 'Administrators only' -CIS_Control 'CIS 5.2' -NIST_Control 'AC-6' `
                -MITRE_Technique 'T1003.001 (LSASS Memory), T1055 (Process Injection)' -ISO27001_Control 'A.8.2' -NIS2_Article 'Art.21(2)(i)' `
                -NSA_Guidance 'NSA CSI: Mitigating Credential Theft' `
                -Recommendation 'Restrict "Debug programs" (SeDebugPrivilege) to the Administrators group only via Local Security Policy > User Rights Assignment. This right allows reading/writing the memory of any process, including LSASS.'
        }
    } catch {
        Add-AuditResult -Category 'Identity, Privilege Management & Access Control' -Control 'User Rights Assignment' -Status 'WARN' -Severity 'Low' `
            -CurrentValue 'Query failed' -Recommendation "Unable to export/parse user rights via secedit: $($_.Exception.Message)"
    } finally {
        if (Test-Path -LiteralPath $tempCfg) { Remove-Item -LiteralPath $tempCfg -Force -ErrorAction SilentlyContinue }
    }
}

function Test-PrivilegedGroupMembership {
    <#
        Enumerates local Administrators group membership as a least-privilege drift signal.
        This is an awareness/hygiene control (WARN, not FAIL) since a larger membership can
        be legitimate depending on device role; the point is to surface it for review.
    #>
    Write-SectionBanner 'Privileged Access - Local Administrators Group Membership'
    try {
        $members = Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop
        $memberList = ($members | ForEach-Object { $_.Name }) -join ', '
        $count = @($members).Count

        if ($count -le 3) {
            Add-AuditResult -Category 'Identity, Privilege Management & Access Control' -Control 'Local Administrators Group Membership' -Status 'PASS' -Severity 'Medium' `
                -CurrentValue "$count member(s): $memberList" -RecommendedValue 'Minimal, justified membership (break-glass account + LAPS-managed local admin)' `
                -CIS_Control 'CIS 5.4' -NIST_Control 'AC-6' -MITRE_Technique 'T1078 (Valid Accounts), T1136 (Create Account)' -ISO27001_Control 'A.5.18' `
                -NIS2_Article 'Art.21(2)(i)' -NSA_Guidance 'NSA/CISA Identity and Access Management Best Practices' -Recommendation 'No action required; periodically re-review.'
        } else {
            Add-AuditResult -Category 'Identity, Privilege Management & Access Control' -Control 'Local Administrators Group Membership' -Status 'WARN' -Severity 'Medium' `
                -CurrentValue "$count member(s): $memberList" -RecommendedValue 'Minimal, justified membership (break-glass account + LAPS-managed local admin)' `
                -CIS_Control 'CIS 5.4' -NIST_Control 'AC-6' -MITRE_Technique 'T1078 (Valid Accounts), T1136 (Create Account)' -ISO27001_Control 'A.5.18' `
                -NIS2_Article 'Art.21(2)(i)' -NSA_Guidance 'NSA/CISA Identity and Access Management Best Practices' `
                -Recommendation 'Review the full membership list above against least-privilege expectations for this device role. Remove standing personal admin accounts in favor of just-in-time elevation (e.g. Entra PIM, LAPS) where feasible.'
        }
    } catch {
        Add-AuditResult -Category 'Identity, Privilege Management & Access Control' -Control 'Local Administrators Group Membership' -Status 'WARN' -Severity 'Low' `
            -CurrentValue 'Query failed' -Recommendation "Unable to enumerate local Administrators group membership: $($_.Exception.Message)"
    }
}

function Test-InteractiveLogonHardening {
    <#
        Audits machine inactivity lock timeout, suppression of the last signed-in username on
        the logon screen, and the number of cached domain credentials retained for offline
        logon.
    #>
    Write-SectionBanner 'Privileged Access - Interactive Logon Hardening'
    try {
        $sysPolicyPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
        $inactivityTimeout = Get-RegistryValueSafe -Path $sysPolicyPath -Name 'InactivityTimeoutSecs' -DefaultValue $null
        $dontDisplayLastUser = Get-RegistryValueSafe -Path $sysPolicyPath -Name 'DontDisplayLastUserName' -DefaultValue 0
        $cachedLogons = Get-RegistryValueSafe -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'CachedLogonsCount' -DefaultValue '10'

        if ($null -ne $inactivityTimeout -and [int]$inactivityTimeout -gt 0 -and [int]$inactivityTimeout -le 900) {
            Add-AuditResult -Category 'Identity, Privilege Management & Access Control' -Control 'Machine Inactivity Lock Timeout' -Status 'PASS' -Severity 'Medium' `
                -CurrentValue "$inactivityTimeout seconds" -RecommendedValue '<= 900 seconds (15 minutes)' -CIS_Control 'CIS 4.10' -NIST_Control 'AC-11' `
                -MITRE_Technique 'T1078 (Valid Accounts)' -ISO27001_Control 'A.8.1' -NIS2_Article 'Art.21(2)(i)' -Recommendation 'No action required.'
        } else {
            Add-AuditResult -Category 'Identity, Privilege Management & Access Control' -Control 'Machine Inactivity Lock Timeout' -Status 'FAIL' -Severity 'Medium' `
                -CurrentValue $(if ($null -ne $inactivityTimeout) { "$inactivityTimeout seconds" } else { 'Not Configured' }) -RecommendedValue '<= 900 seconds (15 minutes)' `
                -CIS_Control 'CIS 4.10' -NIST_Control 'AC-11' -MITRE_Technique 'T1078 (Valid Accounts)' -ISO27001_Control 'A.8.1' -NIS2_Article 'Art.21(2)(i)' `
                -Recommendation 'Set "Interactive logon: Machine inactivity limit" to 900 seconds or less so unattended, unlocked sessions auto-lock.'
        }

        if ([int]$dontDisplayLastUser -eq 1) {
            Add-AuditResult -Category 'Identity, Privilege Management & Access Control' -Control 'Suppress Last Signed-In Username at Logon' -Status 'PASS' -Severity 'Low' `
                -CurrentValue 'Enabled' -RecommendedValue 'Enabled' -CIS_Control 'CIS 4.10' -NIST_Control 'AC-6, IA-6' -MITRE_Technique 'T1589 (Gather Victim Identity Information)' `
                -ISO27001_Control 'A.8.1' -NIS2_Article 'Art.21(2)(i)' -Recommendation 'No action required.'
        } else {
            Add-AuditResult -Category 'Identity, Privilege Management & Access Control' -Control 'Suppress Last Signed-In Username at Logon' -Status 'FAIL' -Severity 'Low' `
                -CurrentValue 'Disabled' -RecommendedValue 'Enabled' -CIS_Control 'CIS 4.10' -NIST_Control 'AC-6, IA-6' -MITRE_Technique 'T1589 (Gather Victim Identity Information)' `
                -ISO27001_Control 'A.8.1' -NIS2_Article 'Art.21(2)(i)' `
                -Recommendation 'Enable "Interactive logon: Do not display last signed-in user" to prevent shoulder-surfing/username disclosure on shared or public-facing devices.'
        }

        $cachedLogonsInt = 10
        [void][int]::TryParse([string]$cachedLogons, [ref]$cachedLogonsInt)
        if ($cachedLogonsInt -le 4) {
            Add-AuditResult -Category 'Identity, Privilege Management & Access Control' -Control 'Cached Domain Credentials Count' -Status 'PASS' -Severity 'Low' `
                -CurrentValue "$cachedLogonsInt cached logon(s)" -RecommendedValue '<= 4 (0-2 for high-security endpoints)' -CIS_Control 'CIS 18.3' -NIST_Control 'IA-5' `
                -MITRE_Technique 'T1003 (OS Credential Dumping)' -ISO27001_Control 'A.8.5' -NIS2_Article 'Art.21(2)(i)' -Recommendation 'No action required.'
        } else {
            Add-AuditResult -Category 'Identity, Privilege Management & Access Control' -Control 'Cached Domain Credentials Count' -Status 'WARN' -Severity 'Low' `
                -CurrentValue "$cachedLogonsInt cached logon(s)" -RecommendedValue '<= 4 (0-2 for high-security endpoints)' -CIS_Control 'CIS 18.3' -NIST_Control 'IA-5' `
                -MITRE_Technique 'T1003 (OS Credential Dumping)' -ISO27001_Control 'A.8.5' -NIS2_Article 'Art.21(2)(i)' `
                -Recommendation 'Reduce "Interactive logon: Number of previous logons to cache" to 4 or fewer via GPO (CachedLogonsCount) to limit the offline-crackable credential cache footprint on this device.'
        }
    } catch {
        Add-AuditResult -Category 'Identity, Privilege Management & Access Control' -Control 'Interactive Logon Hardening' -Status 'WARN' -Severity 'Low' `
            -CurrentValue 'Query failed' -Recommendation "Unable to complete interactive logon audit: $($_.Exception.Message)"
    }
}

#endregion

#region ============================== 14. LEGACY SERVICE EXPOSURE & REMOTE MANAGEMENT HARDENING ==============================

function Test-PrintSpoolerExposure {
    <#
        Audits the Print Spooler service (the vector for the "PrintNightmare" vulnerability
        class, CVE-2021-34527/CVE-2021-1675) and Point-and-Print driver installation policy.
    #>
    Write-SectionBanner 'Legacy Service Exposure - Print Spooler'
    try {
        $spooler = Get-Service -Name 'Spooler' -ErrorAction SilentlyContinue
        if ($spooler -and $spooler.Status -eq 'Running') {
            Add-AuditResult -Category 'Attack Surface Reduction & Exploit Prevention' -Control 'Print Spooler Service Exposure' -Status 'WARN' -Severity 'High' `
                -CurrentValue 'Running' -RecommendedValue 'Disabled on workstations without a local/shared-printing business need' -CIS_Control 'CIS 4.1' `
                -NIST_Control 'CM-7, SI-2' -MITRE_Technique 'T1547.012 (Print Processors), T1210 (Exploitation of Remote Services)' -ISO27001_Control 'A.8.9' `
                -NIS2_Article 'Art.21(2)(e)' -NSA_Guidance 'CISA Advisory: PrintNightmare Mitigations' `
                -Recommendation 'If this endpoint does not need to print or share printers, disable the Spooler service: Stop-Service Spooler -Force; Set-Service Spooler -StartupType Disabled. If printing is required, apply the Point-and-Print restriction below rather than disabling the service outright.'
        } elseif ($spooler) {
            Add-AuditResult -Category 'Attack Surface Reduction & Exploit Prevention' -Control 'Print Spooler Service Exposure' -Status 'PASS' -Severity 'High' `
                -CurrentValue "$($spooler.Status) / StartType=$($spooler.StartType)" -RecommendedValue 'Disabled or Stopped where not required' -CIS_Control 'CIS 4.1' `
                -NIST_Control 'CM-7, SI-2' -MITRE_Technique 'T1547.012 (Print Processors)' -ISO27001_Control 'A.8.9' -NIS2_Article 'Art.21(2)(e)' `
                -NSA_Guidance 'CISA Advisory: PrintNightmare Mitigations' -Recommendation 'No action required.'
        } else {
            Add-AuditResult -Category 'Attack Surface Reduction & Exploit Prevention' -Control 'Print Spooler Service Exposure' -Status 'INFO' -Severity 'Informational' `
                -CurrentValue 'Service not found' -Recommendation 'Spooler service not present on this build/SKU.'
        }

        $pnpPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint'
        $restrictDriverInstall = Get-RegistryValueSafe -Path $pnpPath -Name 'RestrictDriverInstallationToAdministrators' -DefaultValue $null

        if ($restrictDriverInstall -eq 1) {
            Add-AuditResult -Category 'Attack Surface Reduction & Exploit Prevention' -Control 'Point-and-Print Driver Installation Restriction' -Status 'PASS' -Severity 'High' `
                -CurrentValue 'Restricted to Administrators' -RecommendedValue 'Restricted to Administrators' -CIS_Control 'CIS 4.1' -NIST_Control 'CM-7, AC-6' `
                -MITRE_Technique 'T1547.012 (Print Processors)' -ISO27001_Control 'A.8.9' -NIS2_Article 'Art.21(2)(e)' -NSA_Guidance 'CISA Advisory: PrintNightmare Mitigations' `
                -Recommendation 'No action required.'
        } else {
            Add-AuditResult -Category 'Attack Surface Reduction & Exploit Prevention' -Control 'Point-and-Print Driver Installation Restriction' -Status 'FAIL' -Severity 'High' `
                -CurrentValue 'Not Restricted' -RecommendedValue 'Restricted to Administrators' -CIS_Control 'CIS 4.1' -NIST_Control 'CM-7, AC-6' `
                -MITRE_Technique 'T1547.012 (Print Processors)' -ISO27001_Control 'A.8.9' -NIS2_Article 'Art.21(2)(e)' -NSA_Guidance 'CISA Advisory: PrintNightmare Mitigations' `
                -Recommendation 'Set the "Point and Print Restrictions" GPO to require Administrator approval for both driver installation and update (RestrictDriverInstallationToAdministrators=1) - directly closes the PrintNightmare local/remote privilege escalation path.'
        }
    } catch {
        Add-AuditResult -Category 'Attack Surface Reduction & Exploit Prevention' -Control 'Print Spooler Exposure' -Status 'WARN' -Severity 'Low' `
            -CurrentValue 'Query failed' -Recommendation "Unable to complete Print Spooler audit: $($_.Exception.Message)"
    }
}

function Test-WinRMHardening {
    <#
        Audits Windows Remote Management (WinRM) exposure: service state, unencrypted
        traffic allowance, and Basic authentication allowance on the service (server) side.
    #>
    Write-SectionBanner 'Legacy Service Exposure - WinRM / PowerShell Remoting'
    try {
        $winrm = Get-Service -Name 'WinRM' -ErrorAction SilentlyContinue
        if ($winrm -and $winrm.Status -ne 'Running') {
            Add-AuditResult -Category 'Network Architecture & Protocol Hardening' -Control 'WinRM Service Exposure' -Status 'PASS' -Severity 'Medium' `
                -CurrentValue "$($winrm.Status)" -RecommendedValue 'Stopped/Disabled unless remoting is required; if required, HTTPS + encrypted + non-Basic auth' `
                -CIS_Control 'CIS 4.1' -NIST_Control 'AC-17, SC-8' -MITRE_Technique 'T1021.006 (Windows Remote Management)' -ISO27001_Control 'A.8.20' `
                -NIS2_Article 'Art.21(2)(j)' -NSA_Guidance 'NSA/CISA Selecting Secure Remote Access Solutions' -Recommendation 'No action required.'
        } elseif ($winrm) {
            $svcPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'
            $allowUnencrypted = Get-RegistryValueSafe -Path $svcPath -Name 'AllowUnencryptedTraffic' -DefaultValue 0
            $allowBasic = Get-RegistryValueSafe -Path $svcPath -Name 'AllowBasic' -DefaultValue 1

            if ([int]$allowUnencrypted -eq 0) {
                Add-AuditResult -Category 'Network Architecture & Protocol Hardening' -Control 'WinRM Unencrypted Traffic' -Status 'PASS' -Severity 'High' `
                    -CurrentValue 'Disallowed' -RecommendedValue 'Disallowed' -CIS_Control 'CIS 4.1' -NIST_Control 'SC-8' -MITRE_Technique 'T1021.006 (Windows Remote Management)' `
                    -ISO27001_Control 'A.8.24' -NIS2_Article 'Art.21(2)(j)' -Recommendation 'No action required.'
            } else {
                Add-AuditResult -Category 'Network Architecture & Protocol Hardening' -Control 'WinRM Unencrypted Traffic' -Status 'FAIL' -Severity 'High' `
                    -CurrentValue 'Allowed' -RecommendedValue 'Disallowed' -CIS_Control 'CIS 4.1' -NIST_Control 'SC-8' -MITRE_Technique 'T1021.006 (Windows Remote Management)' `
                    -ISO27001_Control 'A.8.24' -NIS2_Article 'Art.21(2)(j)' `
                    -Recommendation 'Set GPO "Allow unencrypted traffic" under WinRM Service to Disabled (AllowUnencryptedTraffic=0).'
            }

            if ([int]$allowBasic -eq 0) {
                Add-AuditResult -Category 'Network Architecture & Protocol Hardening' -Control 'WinRM Basic Authentication (Service)' -Status 'PASS' -Severity 'Medium' `
                    -CurrentValue 'Disallowed' -RecommendedValue 'Disallowed' -CIS_Control 'CIS 4.1' -NIST_Control 'IA-2, SC-8' -MITRE_Technique 'T1110 (Brute Force)' `
                    -ISO27001_Control 'A.8.5' -NIS2_Article 'Art.21(2)(j)' -Recommendation 'No action required.'
            } else {
                Add-AuditResult -Category 'Network Architecture & Protocol Hardening' -Control 'WinRM Basic Authentication (Service)' -Status 'FAIL' -Severity 'Medium' `
                    -CurrentValue 'Allowed' -RecommendedValue 'Disallowed' -CIS_Control 'CIS 4.1' -NIST_Control 'IA-2, SC-8' -MITRE_Technique 'T1110 (Brute Force)' `
                    -ISO27001_Control 'A.8.5' -NIS2_Article 'Art.21(2)(j)' `
                    -Recommendation 'Set GPO "Allow Basic authentication" under WinRM Service to Disabled (AllowBasic=0); Basic auth transmits credentials with weak protection compared to Kerberos/Negotiate.'
            }
        } else {
            Add-AuditResult -Category 'Network Architecture & Protocol Hardening' -Control 'WinRM Service Exposure' -Status 'INFO' -Severity 'Informational' `
                -CurrentValue 'Service not found' -Recommendation 'WinRM service not present on this build/SKU.'
        }
    } catch {
        Add-AuditResult -Category 'Network Architecture & Protocol Hardening' -Control 'WinRM Hardening' -Status 'WARN' -Severity 'Low' `
            -CurrentValue 'Query failed' -Recommendation "Unable to complete WinRM audit: $($_.Exception.Message)"
    }
}

function Test-RemoteRegistryService {
    <#
        Audits the Remote Registry service, which - when running - allows any principal with
        appropriate credentials to remotely read/modify this host's registry.
    #>
    Write-SectionBanner 'Legacy Service Exposure - Remote Registry'
    try {
        $svc = Get-Service -Name 'RemoteRegistry' -ErrorAction SilentlyContinue
        if (-not $svc -or $svc.StartType -eq 'Disabled') {
            Add-AuditResult -Category 'Network Architecture & Protocol Hardening' -Control 'Remote Registry Service' -Status 'PASS' -Severity 'Medium' `
                -CurrentValue $(if ($svc) { 'Disabled' } else { 'Not present' }) -RecommendedValue 'Disabled' -CIS_Control 'CIS 4.1' -NIST_Control 'CM-7, AC-17' `
                -MITRE_Technique 'T1112 (Modify Registry), T1021 (Remote Services)' -ISO27001_Control 'A.8.9' -NIS2_Article 'Art.21(2)(d)' -Recommendation 'No action required.'
        } else {
            Add-AuditResult -Category 'Network Architecture & Protocol Hardening' -Control 'Remote Registry Service' -Status 'FAIL' -Severity 'Medium' `
                -CurrentValue "StartType=$($svc.StartType); Status=$($svc.Status)" -RecommendedValue 'Disabled' -CIS_Control 'CIS 4.1' -NIST_Control 'CM-7, AC-17' `
                -MITRE_Technique 'T1112 (Modify Registry), T1021 (Remote Services)' -ISO27001_Control 'A.8.9' -NIS2_Article 'Art.21(2)(d)' `
                -Recommendation 'Set-Service -Name RemoteRegistry -StartupType Disabled; Stop-Service -Name RemoteRegistry -Force. Enterprise management tooling (SCCM/Intune) does not require this legacy service on modern fleets.'
        }
    } catch {
        Add-AuditResult -Category 'Network Architecture & Protocol Hardening' -Control 'Remote Registry Service' -Status 'WARN' -Severity 'Low' `
            -CurrentValue 'Query failed' -Recommendation "Unable to query Remote Registry service state: $($_.Exception.Message)"
    }
}

#endregion

#region ============================== 15. REMOVABLE MEDIA, APP EXECUTION & MODERN THREAT SURFACE ==============================

function Test-RemovableMediaControl {
    <#
        Audits USB mass-storage class availability, Autorun/Autoplay behavior, and
        removable-drive BitLocker (BitLocker To Go) write-access enforcement.
    #>
    Write-SectionBanner 'Removable Media & Device Control'
    try {
        $usbStorStart = Get-RegistryValueSafe -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR' -Name 'Start' -DefaultValue 3
        if ([int]$usbStorStart -eq 4) {
            Add-AuditResult -Category 'Removable Media & Device Control' -Control 'USB Mass Storage Class' -Status 'PASS' -Severity 'Medium' `
                -CurrentValue 'Disabled (Start=4)' -RecommendedValue 'Disabled where not operationally required, or restricted via Intune/GPO removable storage policy' `
                -CIS_Control 'CIS 10.3' -NIST_Control 'MP-7, SC-41' -MITRE_Technique 'T1052.001 (Exfiltration over USB), T1091 (Replication Through Removable Media)' `
                -ISO27001_Control 'A.7.10' -NIS2_Article 'Art.21(2)(g)' -NSA_Guidance 'NSA/CISA Reduce Exposure - Removable Media Controls' -Recommendation 'No action required.'
        } else {
            Add-AuditResult -Category 'Removable Media & Device Control' -Control 'USB Mass Storage Class' -Status 'INFO' -Severity 'Informational' `
                -CurrentValue 'Enabled (default)' -RecommendedValue 'Restrict via Intune/GPO removable storage policy if not operationally required' `
                -CIS_Control 'CIS 10.3' -NIST_Control 'MP-7, SC-41' -MITRE_Technique 'T1052.001 (Exfiltration over USB), T1091 (Replication Through Removable Media)' `
                -ISO27001_Control 'A.7.10' -NIS2_Article 'Art.21(2)(g)' -NSA_Guidance 'NSA/CISA Reduce Exposure - Removable Media Controls' `
                -Recommendation 'USB mass storage is enabled by default, which is normal for most knowledge-worker endpoints. On high-sensitivity devices, restrict via "Removable Storage Access" GPO/Intune policy or set USBSTOR Start=4 to fully disable the class driver.'
        }

        $autorunPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
        $noDriveTypeAutoRun = Get-RegistryValueSafe -Path $autorunPath -Name 'NoDriveTypeAutoRun' -DefaultValue $null
        if ($noDriveTypeAutoRun -eq 255) {
            Add-AuditResult -Category 'Removable Media & Device Control' -Control 'Autorun/Autoplay for Removable Drives' -Status 'PASS' -Severity 'Medium' `
                -CurrentValue 'Disabled on all drive types (255)' -RecommendedValue '255 (disabled on all drive types)' -CIS_Control 'CIS 10.3' -NIST_Control 'CM-7, SC-41' `
                -MITRE_Technique 'T1091 (Replication Through Removable Media)' -ISO27001_Control 'A.7.10' -NIS2_Article 'Art.21(2)(g)' -Recommendation 'No action required.'
        } else {
            Add-AuditResult -Category 'Removable Media & Device Control' -Control 'Autorun/Autoplay for Removable Drives' -Status 'FAIL' -Severity 'Medium' `
                -CurrentValue $(if ($null -ne $noDriveTypeAutoRun) { "NoDriveTypeAutoRun=$noDriveTypeAutoRun" } else { 'Not Configured' }) -RecommendedValue '255 (disabled on all drive types)' `
                -CIS_Control 'CIS 10.3' -NIST_Control 'CM-7, SC-41' -MITRE_Technique 'T1091 (Replication Through Removable Media)' -ISO27001_Control 'A.7.10' -NIS2_Article 'Art.21(2)(g)' `
                -Recommendation 'Set "Turn off Autoplay" GPO to Enabled, All Drives (NoDriveTypeAutoRun=255) to prevent auto-execution of malicious autorun.inf payloads from removable media.'
        }

        $fvePath = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE'
        $rdvDenyWrite = Get-RegistryValueSafe -Path $fvePath -Name 'RDVDenyWriteAccess' -DefaultValue $null
        if ($rdvDenyWrite -eq 1) {
            Add-AuditResult -Category 'Removable Media & Device Control' -Control 'BitLocker To Go - Deny Write Access to Unprotected Removable Drives' -Status 'PASS' -Severity 'Medium' `
                -CurrentValue 'Enabled' -RecommendedValue 'Enabled' -CIS_Control 'CIS 10.3' -NIST_Control 'SC-28, MP-7' -MITRE_Technique 'T1052.001 (Exfiltration over USB)' `
                -ISO27001_Control 'A.8.24' -NIS2_Article 'Art.21(2)(h)' -Recommendation 'No action required.'
        } else {
            Add-AuditResult -Category 'Removable Media & Device Control' -Control 'BitLocker To Go - Deny Write Access to Unprotected Removable Drives' -Status 'WARN' -Severity 'Medium' `
                -CurrentValue 'Not Configured' -RecommendedValue 'Enabled' -CIS_Control 'CIS 10.3' -NIST_Control 'SC-28, MP-7' -MITRE_Technique 'T1052.001 (Exfiltration over USB)' `
                -ISO27001_Control 'A.8.24' -NIS2_Article 'Art.21(2)(h)' `
                -Recommendation 'Enable "Deny write access to removable drives not protected by BitLocker" (RDVDenyWriteAccess=1) so data cannot be copied to unencrypted USB drives, mitigating data-at-rest exposure if the media is lost or stolen.'
        }
    } catch {
        Add-AuditResult -Category 'Removable Media & Device Control' -Control 'Removable Media & Device Control' -Status 'WARN' -Severity 'Low' `
            -CurrentValue 'Query failed' -Recommendation "Unable to complete removable media audit: $($_.Exception.Message)"
    }
}

function Test-SmartScreenAndSmartAppControl {
    <#
        Audits Windows Defender SmartScreen (Explorer-level reputation checking for
        downloaded/unrecognized executables) and Smart App Control (Windows 11 22H2+
        reputation-based application execution control built on WDAC).
    #>
    Write-SectionBanner 'Modern Threat Surface - SmartScreen & Smart App Control'
    try {
        $ssPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
        $enableSmartScreen = Get-RegistryValueSafe -Path $ssPath -Name 'EnableSmartScreen' -DefaultValue $null
        $smartScreenLevel = Get-RegistryValueSafe -Path $ssPath -Name 'ShellSmartScreenLevel' -DefaultValue $null

        if ($enableSmartScreen -eq 1) {
            Add-AuditResult -Category 'Next-Gen Antivirus & EDR' -Control 'Windows Defender SmartScreen (Explorer/Apps)' -Status 'PASS' -Severity 'High' `
                -CurrentValue "Enabled; Level=$smartScreenLevel" -RecommendedValue 'Enabled; Level=Block' -CIS_Control 'CIS 9.3' -NIST_Control 'SI-3, SC-7' `
                -MITRE_Technique 'T1204 (User Execution), T1566 (Phishing)' -ISO27001_Control 'A.8.7' -NIS2_Article 'Art.21(2)(b)' `
                -NSA_Guidance 'NSA/CISA Guidance on Endpoint Detection and Response' -Recommendation 'No action required.'
        } else {
            Add-AuditResult -Category 'Next-Gen Antivirus & EDR' -Control 'Windows Defender SmartScreen (Explorer/Apps)' -Status 'FAIL' -Severity 'High' `
                -CurrentValue 'Disabled / Not Configured' -RecommendedValue 'Enabled; Level=Block' -CIS_Control 'CIS 9.3' -NIST_Control 'SI-3, SC-7' `
                -MITRE_Technique 'T1204 (User Execution), T1566 (Phishing)' -ISO27001_Control 'A.8.7' -NIS2_Article 'Art.21(2)(b)' `
                -NSA_Guidance 'NSA/CISA Guidance on Endpoint Detection and Response' `
                -Recommendation 'Enable GPO "Configure Windows Defender SmartScreen" (Administrative Templates > Windows Components > File Explorer) with warn-and-prevent-bypass (Block), so unrecognized downloaded executables are checked against Microsoft reputation data before running.'
        }

        $ciPolicyPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy'
        $sacState = Get-RegistryValueSafe -Path $ciPolicyPath -Name 'VerifiedAndReputablePolicyState' -DefaultValue $null
        if ($null -ne $sacState) {
            $sacMap = @{ 0 = 'Off'; 1 = 'On (Enforced)'; 2 = 'Evaluation Mode' }
            $sacDesc = $sacMap[[int]$sacState]
            if ([int]$sacState -eq 1) {
                Add-AuditResult -Category 'Application Control & Software Whitelisting' -Control 'Smart App Control' -Status 'PASS' -Severity 'Medium' `
                    -CurrentValue $sacDesc -RecommendedValue 'On (Enforced)' -CIS_Control 'CIS 2.5' -NIST_Control 'CM-7, SI-7' `
                    -MITRE_Technique 'T1204 (User Execution), T1195 (Supply Chain Compromise)' -ISO27001_Control 'A.8.19' -NIS2_Article 'Art.21(2)(e)' `
                    -NSA_Guidance 'NSA/CISA Application Allowlisting Guidance' -Recommendation 'No action required.'
            } else {
                Add-AuditResult -Category 'Application Control & Software Whitelisting' -Control 'Smart App Control' -Status 'WARN' -Severity 'Low' `
                    -CurrentValue $sacDesc -RecommendedValue 'On (Enforced)' -CIS_Control 'CIS 2.5' -NIST_Control 'CM-7, SI-7' -ISO27001_Control 'A.8.19' `
                    -NIS2_Article 'Art.21(2)(e)' -NSA_Guidance 'NSA/CISA Application Allowlisting Guidance' `
                    -Recommendation 'Smart App Control can only be turned ON via a clean install of Windows 11 (it cannot be re-enabled once turned off on an existing install). Where feasible on new deployments, leave it enabled for reputation-based execution control layered on top of WDAC.'
            }
        } else {
            Add-AuditResult -Category 'Application Control & Software Whitelisting' -Control 'Smart App Control' -Status 'INFO' -Severity 'Informational' `
                -CurrentValue 'Not reported (older build, or disabled prior to this OS install)' -RecommendedValue 'On (Enforced), new deployments only' `
                -Recommendation 'Smart App Control availability depends on Windows 11 build/install history. Not present or already permanently disabled on this device is common and not independently actionable.'
        }
    } catch {
        Add-AuditResult -Category 'Next-Gen Antivirus & EDR' -Control 'SmartScreen & Smart App Control' -Status 'WARN' -Severity 'Low' `
            -CurrentValue 'Query failed' -Recommendation "Unable to complete SmartScreen/Smart App Control audit: $($_.Exception.Message)"
    }
}

function Test-WindowsRecallControl {
    <#
        Audits the Windows 11 24H2+ "Recall" AI snapshot feature, which by default (on
        supported Copilot+ hardware) periodically captures screen snapshots for local
        semantic search. This is a material data-exposure consideration flagged by
        CISA/NCSC-style guidance and is checked here for currency with modern Windows 11
        releases; it is reported as informational/not-applicable on builds that predate it.
    #>
    Write-SectionBanner 'Modern Threat Surface - Windows Recall / AI Data Analysis'
    try {
        $buildNumber = 0
        try { $buildNumber = [int](Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop).BuildNumber } catch { $buildNumber = 0 }

        if ($buildNumber -lt 26100) {
            Add-AuditResult -Category 'Removable Media & Device Control' -Control 'Windows Recall / AI Data Analysis Control' -Status 'INFO' -Severity 'Informational' `
                -CurrentValue "OS Build $buildNumber (pre-24H2)" -RecommendedValue 'Not applicable on this build' `
                -Recommendation 'Windows Recall was introduced in Windows 11 24H2 (build 26100+) on supported Copilot+ hardware. Not applicable to this build.'
            return
        }

        $aiPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI'
        $disableAiAnalysis = Get-RegistryValueSafe -Path $aiPath -Name 'DisableAIDataAnalysis' -DefaultValue $null

        if ($disableAiAnalysis -eq 1) {
            Add-AuditResult -Category 'Removable Media & Device Control' -Control 'Windows Recall / AI Data Analysis Control' -Status 'PASS' -Severity 'Medium' `
                -CurrentValue 'Disabled via policy (DisableAIDataAnalysis=1)' -RecommendedValue 'Disabled, or enabled only with an approved data-handling/DLP review' `
                -CIS_Control 'CIS 10.3' -NIST_Control 'SC-28, PT-2' -MITRE_Technique 'T1113 (Screen Capture), T1005 (Data from Local System)' -ISO27001_Control 'A.8.11' `
                -NIS2_Article 'Art.21(2)(h)' -NSA_Guidance 'NSA/CISA Advancing Zero Trust Maturity - Device Pillar' -Recommendation 'No action required.'
        } else {
            Add-AuditResult -Category 'Removable Media & Device Control' -Control 'Windows Recall / AI Data Analysis Control' -Status 'WARN' -Severity 'Medium' `
                -CurrentValue 'Not explicitly disabled by policy' -RecommendedValue 'Disabled, or enabled only with an approved data-handling/DLP review' `
                -CIS_Control 'CIS 10.3' -NIST_Control 'SC-28, PT-2' -MITRE_Technique 'T1113 (Screen Capture), T1005 (Data from Local System)' -ISO27001_Control 'A.8.11' `
                -NIS2_Article 'Art.21(2)(h)' -NSA_Guidance 'NSA/CISA Advancing Zero Trust Maturity - Device Pillar' `
                -Recommendation 'On Copilot+ hardware, Recall continuously captures local screenshots (including of sensitive on-screen content such as credentials or regulated data) for semantic search. Set the "Turn off saving snapshots for use with AI features" GPO (DisableAIDataAnalysis=1) unless the organization has completed a data-protection review and business justification for enabling it.'
        }
    } catch {
        Add-AuditResult -Category 'Removable Media & Device Control' -Control 'Windows Recall / AI Data Analysis Control' -Status 'WARN' -Severity 'Low' `
            -CurrentValue 'Query failed' -Recommendation "Unable to determine Windows Recall policy state: $($_.Exception.Message)"
    }
}

#endregion

#region ============================== 16. ZERO TRUST DEVICE IDENTITY, PATCH & TIME INTEGRITY ==============================

function Test-DeviceIdentityAndJoinState {
    <#
        Audits device identity anchoring (Entra ID / Hybrid / Domain / Workplace join) via
        dsregcmd.exe, a foundational Zero Trust Device Pillar control: an endpoint with no
        identity-provider-known device record cannot be evaluated by Conditional Access or
        device compliance policy.
    #>
    Write-SectionBanner 'Zero Trust - Device Identity & Join State'
    try {
        $dsregOutput = & dsregcmd.exe /status 2>$null
        if (-not $dsregOutput) { throw 'dsregcmd.exe returned no output' }

        function Get-DsregValue {
            param($lines, $key)
            $line = $lines | Where-Object { $_ -match "^\s*$key\s*:" } | Select-Object -First 1
            if ($line) { return ($line -split ':', 2)[1].Trim() }
            return 'Unknown'
        }

        $azureAdJoined = Get-DsregValue $dsregOutput 'AzureAdJoined'
        $domainJoined = Get-DsregValue $dsregOutput 'DomainJoined'
        $enterpriseJoined = Get-DsregValue $dsregOutput 'EnterpriseJoined'
        $workplaceJoined = Get-DsregValue $dsregOutput 'WorkplaceJoined'

        $hasIdentityAnchor = ($azureAdJoined -eq 'YES') -or ($domainJoined -eq 'YES') -or ($enterpriseJoined -eq 'YES')
        $joinSummary = "AzureAdJoined=$azureAdJoined; DomainJoined=$domainJoined; EnterpriseJoined=$enterpriseJoined; WorkplaceJoined=$workplaceJoined"

        if ($hasIdentityAnchor) {
            Add-AuditResult -Category 'Identity, Privilege Management & Access Control' -Control 'Zero Trust Device Identity Anchor' -Status 'PASS' -Severity 'High' `
                -CurrentValue $joinSummary -RecommendedValue 'AzureAdJoined=YES and/or DomainJoined=YES, enabling Conditional Access / device compliance evaluation' `
                -CIS_Control 'CIS 5.1' -NIST_Control 'IA-3, AC-19' -MITRE_Technique 'T1078 (Valid Accounts)' -ISO27001_Control 'A.8.1' -NIS2_Article 'Art.21(2)(i)' `
                -NSA_Guidance 'NSA/CISA Advancing Zero Trust Maturity - Device Pillar' -Recommendation 'No action required.'
        } else {
            Add-AuditResult -Category 'Identity, Privilege Management & Access Control' -Control 'Zero Trust Device Identity Anchor' -Status 'WARN' -Severity 'High' `
                -CurrentValue $joinSummary -RecommendedValue 'AzureAdJoined=YES and/or DomainJoined=YES, enabling Conditional Access / device compliance evaluation' `
                -CIS_Control 'CIS 5.1' -NIST_Control 'IA-3, AC-19' -MITRE_Technique 'T1078 (Valid Accounts)' -ISO27001_Control 'A.8.1' -NIS2_Article 'Art.21(2)(i)' `
                -NSA_Guidance 'NSA/CISA Advancing Zero Trust Maturity - Device Pillar' `
                -Recommendation 'This device has no Entra ID, Hybrid, or on-premises Active Directory join recorded. Without an identity-provider-known device record, Conditional Access, device compliance policy, and centralized attestation cannot evaluate this endpoint - join it to Entra ID/AD per organizational standard.'
        }
    } catch {
        Add-AuditResult -Category 'Identity, Privilege Management & Access Control' -Control 'Zero Trust Device Identity Anchor' -Status 'WARN' -Severity 'Low' `
            -CurrentValue 'Query failed' -Recommendation "Unable to run dsregcmd.exe /status: $($_.Exception.Message)"
    }
}

function Test-WindowsUpdateCompliance {
    <#
        Audits Windows Update service health, presence of a pending-reboot condition, and
        recency of the last installed update - unpatched endpoints are one of the highest-
        value initial-access vectors (MITRE T1190).
    #>
    Write-SectionBanner 'Zero Trust - Windows Update / Patch Compliance'
    try {
        $wuauserv = Get-Service -Name 'wuauserv' -ErrorAction SilentlyContinue
        if ($wuauserv -and $wuauserv.StartType -ne 'Disabled') {
            Add-AuditResult -Category 'Advanced Security Auditing & Event Logging' -Control 'Windows Update Service Health' -Status 'PASS' -Severity 'High' `
                -CurrentValue "StartType=$($wuauserv.StartType); Status=$($wuauserv.Status)" -RecommendedValue 'Not Disabled' -CIS_Control 'CIS 7.1' -NIST_Control 'SI-2' `
                -MITRE_Technique 'T1190 (Exploit Public-Facing Application), T1210 (Exploitation of Remote Services)' -ISO27001_Control 'A.8.8' -NIS2_Article 'Art.21(2)(e)' `
                -NSA_Guidance 'CISA Known Exploited Vulnerabilities Catalog - Patch Timelines' -Recommendation 'No action required.'
        } else {
            Add-AuditResult -Category 'Advanced Security Auditing & Event Logging' -Control 'Windows Update Service Health' -Status 'FAIL' -Severity 'High' `
                -CurrentValue $(if ($wuauserv) { "StartType=$($wuauserv.StartType)" } else { 'Service not found' }) -RecommendedValue 'Not Disabled' -CIS_Control 'CIS 7.1' `
                -NIST_Control 'SI-2' -MITRE_Technique 'T1190 (Exploit Public-Facing Application), T1562.001 (Disable or Modify Tools)' -ISO27001_Control 'A.8.8' `
                -NIS2_Article 'Art.21(2)(e)' -NSA_Guidance 'CISA Known Exploited Vulnerabilities Catalog - Patch Timelines' `
                -Recommendation 'Set-Service -Name wuauserv -StartupType Manual (or Automatic), then Start-Service wuauserv. A disabled Windows Update service prevents this endpoint from receiving security patches entirely.'
        }

        $cbsRebootPending = Test-Path -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
        $wuRebootPending = Test-Path -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
        if ($cbsRebootPending -or $wuRebootPending) {
            Add-AuditResult -Category 'Advanced Security Auditing & Event Logging' -Control 'Pending Reboot for Security Updates' -Status 'WARN' -Severity 'Medium' `
                -CurrentValue 'Reboot pending' -RecommendedValue 'No reboot pending' -CIS_Control 'CIS 7.1' -NIST_Control 'SI-2' -MITRE_Technique 'T1190 (Exploit Public-Facing Application)' `
                -ISO27001_Control 'A.8.8' -NIS2_Article 'Art.21(2)(e)' -Recommendation 'A previously installed update is not yet active pending a reboot. Schedule a restart promptly so the patched code paths take effect.'
        } else {
            Add-AuditResult -Category 'Advanced Security Auditing & Event Logging' -Control 'Pending Reboot for Security Updates' -Status 'PASS' -Severity 'Medium' `
                -CurrentValue 'No reboot pending' -RecommendedValue 'No reboot pending' -CIS_Control 'CIS 7.1' -NIST_Control 'SI-2' -ISO27001_Control 'A.8.8' -NIS2_Article 'Art.21(2)(e)' `
                -Recommendation 'No action required.'
        }

        try {
            $latestHotfix = Get-HotFix -ErrorAction Stop | Where-Object { $_.InstalledOn } | Sort-Object -Property InstalledOn -Descending | Select-Object -First 1
            if ($latestHotfix) {
                $ageDays = (New-TimeSpan -Start $latestHotfix.InstalledOn -End (Get-Date)).Days
                if ($ageDays -le 45) {
                    Add-AuditResult -Category 'Advanced Security Auditing & Event Logging' -Control 'Patch Recency' -Status 'PASS' -Severity 'High' `
                        -CurrentValue "Last update ($($latestHotfix.HotFixID)) installed $ageDays day(s) ago" -RecommendedValue '<= 45 days since last installed update' `
                        -CIS_Control 'CIS 7.1' -NIST_Control 'SI-2' -MITRE_Technique 'T1190 (Exploit Public-Facing Application)' -ISO27001_Control 'A.8.8' -NIS2_Article 'Art.21(2)(e)' `
                        -NSA_Guidance 'CISA Known Exploited Vulnerabilities Catalog - Patch Timelines' -Recommendation 'No action required.'
                } else {
                    Add-AuditResult -Category 'Advanced Security Auditing & Event Logging' -Control 'Patch Recency' -Status 'FAIL' -Severity 'High' `
                        -CurrentValue "Last update ($($latestHotfix.HotFixID)) installed $ageDays day(s) ago" -RecommendedValue '<= 45 days since last installed update' `
                        -CIS_Control 'CIS 7.1' -NIST_Control 'SI-2' -MITRE_Technique 'T1190 (Exploit Public-Facing Application)' -ISO27001_Control 'A.8.8' -NIS2_Article 'Art.21(2)(e)' `
                        -NSA_Guidance 'CISA Known Exploited Vulnerabilities Catalog - Patch Timelines' `
                        -Recommendation 'Investigate why security updates have not installed recently: verify WSUS/Intune/Windows Update connectivity, check for stuck updates, and manually trigger a scan/install (Settings > Windows Update > Check for updates).'
                }
            } else {
                Add-AuditResult -Category 'Advanced Security Auditing & Event Logging' -Control 'Patch Recency' -Status 'WARN' -Severity 'Medium' `
                    -CurrentValue 'No hotfix install history returned' -RecommendedValue '<= 45 days since last installed update' -CIS_Control 'CIS 7.1' -NIST_Control 'SI-2' `
                    -ISO27001_Control 'A.8.8' -NIS2_Article 'Art.21(2)(e)' -Recommendation 'Verify patch history manually via Settings > Windows Update > Update history; Get-HotFix may under-report cumulative updates on some builds.'
            }
        } catch {
            Add-AuditResult -Category 'Advanced Security Auditing & Event Logging' -Control 'Patch Recency' -Status 'WARN' -Severity 'Low' `
                -CurrentValue 'Query failed' -Recommendation "Unable to enumerate installed hotfix history: $($_.Exception.Message)"
        }
    } catch {
        Add-AuditResult -Category 'Advanced Security Auditing & Event Logging' -Control 'Windows Update / Patch Compliance' -Status 'WARN' -Severity 'Low' `
            -CurrentValue 'Query failed' -Recommendation "Unable to complete patch compliance audit: $($_.Exception.Message)"
    }
}

function Test-TimeSyncIntegrity {
    <#
        Audits the Windows Time service and its configured source. Reliable, externally
        anchored time is a prerequisite for Kerberos ticket validity (5-minute default skew
        tolerance) and for trustworthy cross-system event-log correlation during incident
        response.
    #>
    Write-SectionBanner 'Zero Trust - Time Synchronization Integrity'
    try {
        $w32time = Get-Service -Name 'W32Time' -ErrorAction SilentlyContinue
        if ($w32time -and $w32time.Status -eq 'Running') {
            Add-AuditResult -Category 'Advanced Security Auditing & Event Logging' -Control 'Windows Time Service State' -Status 'PASS' -Severity 'Medium' `
                -CurrentValue 'Running' -RecommendedValue 'Running' -CIS_Control 'CIS 8.4' -NIST_Control 'AU-8' -MITRE_Technique 'T1070 (Indicator Removal), T1550 (Use Alternate Authentication Material)' `
                -ISO27001_Control 'A.8.17' -NIS2_Article 'Art.21(2)(b)' -Recommendation 'No action required.'
        } else {
            Add-AuditResult -Category 'Advanced Security Auditing & Event Logging' -Control 'Windows Time Service State' -Status 'FAIL' -Severity 'Medium' `
                -CurrentValue $(if ($w32time) { "$($w32time.Status)" } else { 'Not found' }) -RecommendedValue 'Running' -CIS_Control 'CIS 8.4' -NIST_Control 'AU-8' `
                -MITRE_Technique 'T1070 (Indicator Removal), T1550 (Use Alternate Authentication Material)' -ISO27001_Control 'A.8.17' -NIS2_Article 'Art.21(2)(b)' `
                -Recommendation 'Start-Service W32Time; Set-Service W32Time -StartupType Automatic. Clock drift beyond the Kerberos 5-minute skew tolerance causes authentication failures, and unsynchronized clocks undermine event-log timeline correlation during incident response.'
        }

        try {
            $timeSourceRaw = & w32tm.exe /query /source 2>$null
            $timeSource = if ($timeSourceRaw) { ($timeSourceRaw | Select-Object -First 1).ToString().Trim() } else { 'Unknown' }
            if ($timeSource -match 'Local CMOS Clock|Free-running') {
                Add-AuditResult -Category 'Advanced Security Auditing & Event Logging' -Control 'Time Source Configuration' -Status 'FAIL' -Severity 'Medium' `
                    -CurrentValue $timeSource -RecommendedValue 'Domain hierarchy (NT5DS) or an authoritative external/internal NTP server' -CIS_Control 'CIS 8.4' -NIST_Control 'AU-8' `
                    -MITRE_Technique 'T1070 (Indicator Removal)' -ISO27001_Control 'A.8.17' -NIS2_Article 'Art.21(2)(b)' `
                    -Recommendation 'This endpoint is using its unsynchronized local hardware clock as the time source. Configure NTP via domain hierarchy (default for domain-joined devices) or w32tm /config /manualpeerlist:"<trusted-ntp-server>" /syncfromflags:manual /reliable:yes /update.'
            } else {
                Add-AuditResult -Category 'Advanced Security Auditing & Event Logging' -Control 'Time Source Configuration' -Status 'PASS' -Severity 'Medium' `
                    -CurrentValue $timeSource -RecommendedValue 'Domain hierarchy (NT5DS) or an authoritative external/internal NTP server' -CIS_Control 'CIS 8.4' -NIST_Control 'AU-8' `
                    -ISO27001_Control 'A.8.17' -NIS2_Article 'Art.21(2)(b)' -Recommendation 'No action required.'
            }
        } catch {
            Add-AuditResult -Category 'Advanced Security Auditing & Event Logging' -Control 'Time Source Configuration' -Status 'WARN' -Severity 'Low' `
                -CurrentValue 'Query failed' -Recommendation "Unable to query configured time source via w32tm.exe: $($_.Exception.Message)"
        }
    } catch {
        Add-AuditResult -Category 'Advanced Security Auditing & Event Logging' -Control 'Time Synchronization Integrity' -Status 'WARN' -Severity 'Low' `
            -CurrentValue 'Query failed' -Recommendation "Unable to complete time synchronization audit: $($_.Exception.Message)"
    }
}

function Test-EventLogConfiguration {
    <#
        Audits maximum size configuration for the core Windows event logs. An undersized log
        with a circular/overwrite retention policy silently loses forensic evidence during a
        high-volume incident - a frequent CIS/STIG finding that is trivial to miss.
    #>
    Write-SectionBanner 'Event Log Infrastructure - Size & Retention'
    $logRequirements = @(
        @{ Name = 'Security'; MinKB = 196608 }
        @{ Name = 'Application'; MinKB = 32768 }
        @{ Name = 'System'; MinKB = 32768 }
        @{ Name = 'Setup'; MinKB = 32768 }
    )
    foreach ($logReq in $logRequirements) {
        try {
            $log = Get-WinEvent -ListLog $logReq.Name -ErrorAction Stop
            $maxSizeKb = [math]::Round($log.MaximumSizeInBytes / 1KB, 0)
            if ($maxSizeKb -ge $logReq.MinKB) {
                Add-AuditResult -Category 'Advanced Security Auditing & Event Logging' -Control "Event Log Maximum Size - $($logReq.Name)" -Status 'PASS' -Severity 'Medium' `
                    -CurrentValue "$maxSizeKb KB" -RecommendedValue ">= $($logReq.MinKB) KB" -CIS_Control 'CIS 8.3' -NIST_Control 'AU-4, AU-11' `
                    -MITRE_Technique 'T1070.001 (Clear Windows Event Logs)' -ISO27001_Control 'A.8.15' -NIS2_Article 'Art.21(2)(b)' `
                    -NSA_Guidance 'NSA/CISA Audit Logging Best Practices' -Recommendation 'No action required.'
            } else {
                Add-AuditResult -Category 'Advanced Security Auditing & Event Logging' -Control "Event Log Maximum Size - $($logReq.Name)" -Status 'FAIL' -Severity 'Medium' `
                    -CurrentValue "$maxSizeKb KB" -RecommendedValue ">= $($logReq.MinKB) KB" -CIS_Control 'CIS 8.3' -NIST_Control 'AU-4, AU-11' `
                    -MITRE_Technique 'T1070.001 (Clear Windows Event Logs)' -ISO27001_Control 'A.8.15' -NIS2_Article 'Art.21(2)(b)' `
                    -NSA_Guidance 'NSA/CISA Audit Logging Best Practices' `
                    -Recommendation "Increase the $($logReq.Name) log maximum size: Limit-EventLog -LogName $($logReq.Name) -MaximumSize $($logReq.MinKB)KB, or via GPO Event Log Service settings, so high-volume periods do not silently roll off forensic evidence."
            }
        } catch {
            Add-AuditResult -Category 'Advanced Security Auditing & Event Logging' -Control "Event Log Maximum Size - $($logReq.Name)" -Status 'WARN' -Severity 'Low' `
                -CurrentValue 'Query failed' -Recommendation "Unable to query the $($logReq.Name) event log configuration: $($_.Exception.Message)"
        }
    }
}

#endregion

#region ============================== 17. ADVANCED HARDWARE MITIGATIONS & DNS SECURITY ==============================

function Test-HardwareStackProtection {
    <#
        Audits Hardware-Enforced Stack Protection (Intel CET / AMD Shadow Stack), a
        Windows 11 exploit mitigation that blocks return-oriented-programming (ROP) style
        control-flow hijacking at the CPU level. Surfaced via the UserShadowStack mitigation
        set on hardware/firmware that supports it.
    #>
    Write-SectionBanner 'Advanced Exploit Mitigation - Hardware-Enforced Stack Protection (CET)'
    try {
        $mitigations = Get-ProcessMitigation -System -ErrorAction Stop
        $shadowStackEnabled = $false
        if ($mitigations.PSObject.Properties.Name -contains 'UserShadowStack') {
            $shadowStackEnabled = $mitigations.UserShadowStack.Enable -eq 'ON' -or $mitigations.UserShadowStack.Enable -eq $true
        }

        if ($mitigations.PSObject.Properties.Name -notcontains 'UserShadowStack') {
            Add-AuditResult -Category 'Attack Surface Reduction & Exploit Prevention' -Control 'Hardware-Enforced Stack Protection (CET)' -Status 'INFO' -Severity 'Informational' `
                -CurrentValue 'Not reported by this OS build/CPU' -RecommendedValue 'Enabled where CPU supports Intel CET / AMD Shadow Stack' -CIS_Control 'CIS 10.1' `
                -NIST_Control 'SI-16, SC-39' -MITRE_Technique 'T1055 (Process Injection), T1203 (Exploitation for Client Execution)' -ISO27001_Control 'A.8.7' `
                -NIS2_Article 'Art.21(2)(b)' -Recommendation 'Hardware-enforced stack protection requires a CET-capable CPU (Intel 11th Gen+/Tiger Lake or later, AMD Zen 3+) and firmware support. Not reported here typically means the hardware/OS build does not support it.'
        } elseif ($shadowStackEnabled) {
            Add-AuditResult -Category 'Attack Surface Reduction & Exploit Prevention' -Control 'Hardware-Enforced Stack Protection (CET)' -Status 'PASS' -Severity 'Medium' `
                -CurrentValue 'Enabled' -RecommendedValue 'Enabled' -CIS_Control 'CIS 10.1' -NIST_Control 'SI-16, SC-39' `
                -MITRE_Technique 'T1055 (Process Injection), T1203 (Exploitation for Client Execution)' -ISO27001_Control 'A.8.7' -NIS2_Article 'Art.21(2)(b)' `
                -NSA_Guidance 'NSA Hardening Guidance for Windows 11' -Recommendation 'No action required.'
        } else {
            Add-AuditResult -Category 'Attack Surface Reduction & Exploit Prevention' -Control 'Hardware-Enforced Stack Protection (CET)' -Status 'WARN' -Severity 'Medium' `
                -CurrentValue 'Disabled or not enabled system-wide' -RecommendedValue 'Enabled where CPU supports Intel CET / AMD Shadow Stack' -CIS_Control 'CIS 10.1' `
                -NIST_Control 'SI-16, SC-39' -MITRE_Technique 'T1055 (Process Injection)' -ISO27001_Control 'A.8.7' -NIS2_Article 'Art.21(2)(b)' `
                -NSA_Guidance 'NSA Hardening Guidance for Windows 11' `
                -Recommendation 'Enable "Windows Security > Device Security > Core Isolation" hardware-enforced stack protection compatible-mode setting, or Set-ProcessMitigation -System -Enable UserShadowStack on CET-capable hardware, to gain CPU-level ROP/JOP exploit mitigation.'
        }
    } catch {
        Add-AuditResult -Category 'Attack Surface Reduction & Exploit Prevention' -Control 'Hardware-Enforced Stack Protection (CET)' -Status 'WARN' -Severity 'Low' `
            -CurrentValue 'Query failed' -Recommendation "Unable to query hardware stack protection state: $($_.Exception.Message)"
    }
}

function Test-DNSSecurity {
    <#
        Audits the DNS-over-HTTPS (DoH) client policy, which protects DNS query
        confidentiality/integrity against on-path observation and tampering - relevant to
        both privacy and DNS-poisoning-based redirection attacks.
    #>
    Write-SectionBanner 'Network Architecture - DNS-over-HTTPS (DoH)'
    try {
        $dnsPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters'
        $dohPolicy = Get-RegistryValueSafe -Path $dnsPath -Name 'EnableAutoDoh' -DefaultValue $null

        if ($null -ne $dohPolicy -and [int]$dohPolicy -ge 1) {
            $dohMap = @{ 1 = 'Allow DoH (opportunistic)'; 2 = 'Require DoH (strict)' }
            $desc = $dohMap[[int]$dohPolicy]
            if (-not $desc) { $desc = "Value $dohPolicy" }
            Add-AuditResult -Category 'Network Architecture & Protocol Hardening' -Control 'DNS-over-HTTPS (DoH)' -Status 'PASS' -Severity 'Medium' `
                -CurrentValue $desc -RecommendedValue 'Allow DoH or Require DoH, paired with a DoH-capable resolver' -CIS_Control 'CIS 4.7' -NIST_Control 'SC-8, SC-20' `
                -MITRE_Technique 'T1557 (Adversary-in-the-Middle), T1071.004 (DNS)' -ISO27001_Control 'A.8.20' -NIS2_Article 'Art.21(2)(d)' `
                -NSA_Guidance 'NSA/CISA Selecting a Protective DNS Service' -Recommendation 'No action required.'
        } else {
            Add-AuditResult -Category 'Network Architecture & Protocol Hardening' -Control 'DNS-over-HTTPS (DoH)' -Status 'INFO' -Severity 'Informational' `
                -CurrentValue 'Not Configured (plaintext DNS unless a third-party resolver client is in use)' -RecommendedValue 'Allow DoH or Require DoH, paired with a DoH-capable resolver' `
                -CIS_Control 'CIS 4.7' -NIST_Control 'SC-8, SC-20' -MITRE_Technique 'T1557 (Adversary-in-the-Middle), T1071.004 (DNS)' -ISO27001_Control 'A.8.20' `
                -NIS2_Article 'Art.21(2)(d)' -NSA_Guidance 'NSA/CISA Selecting a Protective DNS Service' `
                -Recommendation 'Consider enabling DNS-over-HTTPS via GPO/Intune ("Configure DNS over HTTPS (DoH) name resolution") pointed at an enterprise-approved protective DNS resolver, so DNS queries are encrypted and validated rather than sent in plaintext UDP/53.'
        }
    } catch {
        Add-AuditResult -Category 'Network Architecture & Protocol Hardening' -Control 'DNS-over-HTTPS (DoH)' -Status 'WARN' -Severity 'Low' `
            -CurrentValue 'Query failed' -Recommendation "Unable to determine DoH policy state: $($_.Exception.Message)"
    }
}

#endregion

#region ============================== LPE MODULE SHARED HELPERS ==============================

# Well-known low-privilege SIDs used throughout the privilege-escalation audit module.
$Script:LowPrivilegeSids = @('S-1-1-0', 'S-1-5-11', 'S-1-5-32-545')

function Test-LowPrivilegeWriteAccess {
    <#
        Inspects the ACL of a filesystem or registry path and reports whether Everyone,
        Authenticated Users, or the local Users group has been granted a write-capable
        right (Write/Modify/FullControl for files; SetValue/CreateSubKey/FullControl for
        registry keys). Shared by every ACL-based finding in the LPE module. Non-existent
        or inaccessible paths are reported as not-vulnerable (the caller decides whether
        existence itself is significant).
    #>
    param(
        [Parameter(Mandatory = $true)]  [string]$Path,
        [Parameter(Mandatory = $false)] [ValidateSet('FileSystem', 'Registry')] [string]$ObjectType = 'FileSystem'
    )
    $result = [PSCustomObject]@{ IsVulnerable = $false; Principals = [System.Collections.Generic.List[string]]::new() }
    try {
        $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
        foreach ($ace in $acl.Access) {
            if ($ace.AccessControlType -ne 'Allow') { continue }
            $sidValue = $null
            try {
                if ($ace.IdentityReference -is [System.Security.Principal.SecurityIdentifier]) {
                    $sidValue = $ace.IdentityReference.Value
                } else {
                    $sidValue = ($ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier])).Value
                }
            } catch { $sidValue = $null }

            if (-not $sidValue -or ($Script:LowPrivilegeSids -notcontains $sidValue)) { continue }

            $isDangerous = $false
            $rightsText = ''
            if ($ObjectType -eq 'FileSystem') {
                $rightsText = $ace.FileSystemRights.ToString()
                if ($rightsText -match 'Write|Modify|FullControl') { $isDangerous = $true }
            } else {
                $rightsText = $ace.RegistryRights.ToString()
                if ($rightsText -match 'SetValue|CreateSubKey|FullControl|WriteKey') { $isDangerous = $true }
            }
            if ($isDangerous) {
                $result.IsVulnerable = $true
                $result.Principals.Add("$($ace.IdentityReference) ($rightsText)")
            }
        }
    } catch {
        # Inaccessible/nonexistent path - treated as not-vulnerable; callers handle existence separately.
    }
    return $result
}

function Get-ServiceExecutablePath {
    <#
        Extracts the clean executable path from a Win32_Service PathName, handling both
        quoted paths and unquoted paths that may include trailing arguments.
    #>
    param([Parameter(Mandatory = $false)][string]$PathName)
    if ([string]::IsNullOrWhiteSpace($PathName)) { return $null }
    $p = $PathName.Trim()
    if ($p.StartsWith('"') -and ($p -match '^"([^"]+)"')) { return $Matches[1] }
    if ($p -match '(?i)^(.*?\.(exe|sys|dll))\b') { return $Matches[1] }
    return ($p -split ' ')[0]
}

function Get-UnquotedPathWritableBreakpoints {
    <#
        For an unquoted, space-containing service path, enumerates every CreateProcess
        parsing break point (the classic unquoted-service-path ambiguity: Windows will try
        "C:\Program.exe" before "C:\Program Files\Sub.exe" before the real target) and
        checks whether the parent directory at each break point grants low-privilege write
        access - i.e. whether an attacker could plant a decoy executable that gets launched
        instead of (or in addition to) the intended service binary.
    #>
    param([Parameter(Mandatory = $true)][string]$RawPath)
    $writableBreakpoints = [System.Collections.Generic.List[string]]::new()
    $trimmed = $RawPath.Trim()
    if ($trimmed.StartsWith('"')) { return $writableBreakpoints }
    if ($trimmed -notmatch '\s') { return $writableBreakpoints }

    $parts = $trimmed -split ' '
    for ($i = 0; $i -lt ($parts.Count - 1); $i++) {
        $candidate = ($parts[0..$i]) -join ' '
        $parentDir = $null
        try { $parentDir = Split-Path -Path $candidate -Parent -ErrorAction SilentlyContinue } catch { $parentDir = $null }
        if ($parentDir -and (Test-Path -LiteralPath $parentDir -PathType Container -ErrorAction SilentlyContinue)) {
            $check = Test-LowPrivilegeWriteAccess -Path $parentDir -ObjectType FileSystem
            if ($check.IsVulnerable) {
                $writableBreakpoints.Add("$parentDir [$($check.Principals -join '; ')]")
            }
        }
    }
    return ($writableBreakpoints | Select-Object -Unique)
}

function Get-ServiceInventoryCache {
    <# Central Win32_Service accessor shared across the LPE module's service-focused checks. #>
    if ($null -eq $Script:ServiceInventoryCache) {
        try { $Script:ServiceInventoryCache = @(Get-CimInstance -ClassName Win32_Service -ErrorAction Stop) } catch { $Script:ServiceInventoryCache = @() }
    }
    return $Script:ServiceInventoryCache
}

#endregion

#region ============================== 18. PRIVILEGE ESCALATION - SERVICE, FILE SYSTEM & DLL HIJACKING ==============================

function Test-UnquotedServicePathsWritable {
    <#
        Deep variant of the unquoted-service-path check: for every service with an
        unquoted, space-containing binary path, walks every CreateProcess parsing break
        point and flags any whose parent directory is writable by a low-privileged
        principal. Severity is elevated to Critical when the vulnerable service runs as
        LocalSystem, since a successful hijack yields immediate SYSTEM code execution.
    #>
    Write-SectionBanner 'Privilege Escalation - Unquoted Service Paths (Writable Break Points)'
    try {
        $services = Get-ServiceInventoryCache
        $vulnerableFound = $false
        foreach ($svc in $services) {
            if (-not $svc.PathName) { continue }
            if ($svc.PathName.Trim().StartsWith('"')) { continue }
            if ($svc.PathName -notmatch '\s') { continue }

            $breakpoints = Get-UnquotedPathWritableBreakpoints -RawPath $svc.PathName
            if ($breakpoints.Count -gt 0) {
                $vulnerableFound = $true
                $runsAsSystem = $svc.StartName -in @('LocalSystem', 'NT AUTHORITY\SYSTEM', $null, '')
                $severity = if ($runsAsSystem) { 'Critical' } else { 'High' }
                Add-AuditResult -Category 'Privilege Escalation - Service & File Permissions' -Control "Unquoted Service Path - Writable Break Point ($($svc.Name))" `
                    -Status 'FAIL' -Severity $severity -CurrentValue "Account=$($svc.StartName); Path=$($svc.PathName); Writable break point(s): $($breakpoints -join ' | ')" `
                    -RecommendedValue 'Path quoted, or no writable directory along the unquoted break-point chain' -CIS_Control 'CIS 4.8' -NIST_Control 'CM-7, AC-6' `
                    -MITRE_Technique 'T1574.009 (Path Interception by Unquoted Path)' -ISO27001_Control 'A.8.19' -NIS2_Article 'Art.21(2)(i)' `
                    -NSA_Guidance 'NSA/CISA Identity and Access Management Best Practices' `
                    -Recommendation "sc.exe config `"$($svc.Name)`" binPath= `"\`"<full path>\`"`" to quote the path, closing the CreateProcess parsing ambiguity. This service runs as $($svc.StartName) - a successful hijack yields code execution in that context."
            }
        }
        if (-not $vulnerableFound) {
            Add-AuditResult -Category 'Privilege Escalation - Service & File Permissions' -Control 'Unquoted Service Path - Writable Break Points' -Status 'PASS' -Severity 'High' `
                -CurrentValue 'No unquoted service paths with a writable break-point directory found' -RecommendedValue 'None found' -CIS_Control 'CIS 4.8' `
                -NIST_Control 'CM-7, AC-6' -MITRE_Technique 'T1574.009 (Path Interception by Unquoted Path)' -ISO27001_Control 'A.8.19' -NIS2_Article 'Art.21(2)(i)' `
                -Recommendation 'No action required.'
        }
    } catch {
        Add-AuditResult -Category 'Privilege Escalation - Service & File Permissions' -Control 'Unquoted Service Path - Writable Break Points' -Status 'WARN' -Severity 'Low' `
            -CurrentValue 'Query failed' -Recommendation "Unable to complete deep unquoted-service-path audit: $($_.Exception.Message)"
    }
}

function Test-ServiceExecutableACLs {
    <#
        Audits every service's binary (or driver) file for write/modify ACL grants to
        low-privileged principals. If a standard user can overwrite a SYSTEM-run service's
        executable, they can trojan it for guaranteed privileged code execution on next
        start/reboot.
    #>
    Write-SectionBanner 'Privilege Escalation - Service Executable ACLs'
    try {
        $services = Get-ServiceInventoryCache
        $vulnerableFound = $false
        foreach ($svc in $services) {
            $exePath = Get-ServiceExecutablePath -PathName $svc.PathName
            if (-not $exePath -or -not (Test-Path -LiteralPath $exePath -ErrorAction SilentlyContinue)) { continue }

            $check = Test-LowPrivilegeWriteAccess -Path $exePath -ObjectType FileSystem
            if ($check.IsVulnerable) {
                $vulnerableFound = $true
                $runsAsSystem = $svc.StartName -in @('LocalSystem', 'NT AUTHORITY\SYSTEM', $null, '')
                $severity = if ($runsAsSystem) { 'Critical' } else { 'High' }
                Add-AuditResult -Category 'Privilege Escalation - Service & File Permissions' -Control "Service Executable ACL - Writable by Low-Privilege User ($($svc.Name))" `
                    -Status 'FAIL' -Severity $severity -CurrentValue "Account=$($svc.StartName); File=$exePath; Grants: $($check.Principals -join '; ')" `
                    -RecommendedValue 'No Write/Modify/FullControl grant to Everyone, Authenticated Users, or Users' -CIS_Control 'CIS 4.8' -NIST_Control 'CM-7, AC-6' `
                    -MITRE_Technique 'T1574 (Hijack Execution Flow), T1543.003 (Windows Service)' -ISO27001_Control 'A.8.19' -NIS2_Article 'Art.21(2)(i)' `
                    -NSA_Guidance 'NSA/CISA Identity and Access Management Best Practices' `
                    -Recommendation "Tighten the ACL on `"$exePath`": icacls `"$exePath`" /remove:g `"Everyone`" `"Authenticated Users`" `"Users`" - then verify the service still starts correctly."
            }
        }
        if (-not $vulnerableFound) {
            Add-AuditResult -Category 'Privilege Escalation - Service & File Permissions' -Control 'Service Executable ACLs' -Status 'PASS' -Severity 'High' `
                -CurrentValue 'No service executables writable by low-privilege principals' -RecommendedValue 'None found' -CIS_Control 'CIS 4.8' -NIST_Control 'CM-7, AC-6' `
                -MITRE_Technique 'T1574 (Hijack Execution Flow)' -ISO27001_Control 'A.8.19' -NIS2_Article 'Art.21(2)(i)' -Recommendation 'No action required.'
        }
    } catch {
        Add-AuditResult -Category 'Privilege Escalation - Service & File Permissions' -Control 'Service Executable ACLs' -Status 'WARN' -Severity 'Low' `
            -CurrentValue 'Query failed' -Recommendation "Unable to complete service executable ACL audit: $($_.Exception.Message)"
    }
}

function Test-ServiceRegistryKeyACLs {
    <#
        Audits the registry security descriptor on every service's Services\<Name> key.
        A low-privileged principal with SetValue/CreateSubKey/FullControl there can
        repoint ImagePath to an attacker-controlled binary, achieving the same outcome as
        an executable-file hijack without needing filesystem write access.
    #>
    Write-SectionBanner 'Privilege Escalation - Service Registry Key ACLs'
    try {
        $services = Get-ServiceInventoryCache
        $vulnerableFound = $false
        foreach ($svc in $services) {
            $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$($svc.Name)"
            if (-not (Test-Path -LiteralPath $regPath -ErrorAction SilentlyContinue)) { continue }
            $check = Test-LowPrivilegeWriteAccess -Path $regPath -ObjectType Registry
            if ($check.IsVulnerable) {
                $vulnerableFound = $true
                $runsAsSystem = $svc.StartName -in @('LocalSystem', 'NT AUTHORITY\SYSTEM', $null, '')
                $severity = if ($runsAsSystem) { 'Critical' } else { 'High' }
                Add-AuditResult -Category 'Privilege Escalation - Service & File Permissions' -Control "Service Registry Key ACL - Writable by Low-Privilege User ($($svc.Name))" `
                    -Status 'FAIL' -Severity $severity -CurrentValue "Account=$($svc.StartName); Key=$regPath; Grants: $($check.Principals -join '; ')" `
                    -RecommendedValue 'No SetValue/CreateSubKey/FullControl grant to Everyone, Authenticated Users, or Users' -CIS_Control 'CIS 4.8' -NIST_Control 'CM-7, AC-6' `
                    -MITRE_Technique 'T1574.011 (Services Registry Permissions Weakness)' -ISO27001_Control 'A.8.19' -NIS2_Article 'Art.21(2)(i)' `
                    -NSA_Guidance 'NSA/CISA Identity and Access Management Best Practices' `
                    -Recommendation "Remove the low-privilege grant from `"$regPath`" via regedit/PowerShell Set-Acl, restoring the standard Windows default (SYSTEM/Administrators Full Control, Authenticated Users Read-only)."
            }
        }
        if (-not $vulnerableFound) {
            Add-AuditResult -Category 'Privilege Escalation - Service & File Permissions' -Control 'Service Registry Key ACLs' -Status 'PASS' -Severity 'High' `
                -CurrentValue 'No service registry keys writable by low-privilege principals' -RecommendedValue 'None found' -CIS_Control 'CIS 4.8' -NIST_Control 'CM-7, AC-6' `
                -MITRE_Technique 'T1574.011 (Services Registry Permissions Weakness)' -ISO27001_Control 'A.8.19' -NIS2_Article 'Art.21(2)(i)' -Recommendation 'No action required.'
        }
    } catch {
        Add-AuditResult -Category 'Privilege Escalation - Service & File Permissions' -Control 'Service Registry Key ACLs' -Status 'WARN' -Severity 'Low' `
            -CurrentValue 'Query failed' -Recommendation "Unable to complete service registry key ACL audit: $($_.Exception.Message)"
    }
}

function Test-WritablePathDirectories {
    <#
        Audits every directory listed in the system PATH environment variable for
        low-privilege write access. A writable PATH directory lets a standard user plant a
        trojan binary that gets resolved and executed ahead of (or instead of) the
        legitimate tool whenever an unqualified command name is invoked by a higher-
        privileged process or scheduled task.
    #>
    Write-SectionBanner 'Privilege Escalation - Writable PATH Directories (DLL/EXE Search Order)'
    try {
        $pathDirs = ($env:Path -split ';') | Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Container -ErrorAction SilentlyContinue) } | Select-Object -Unique
        $vulnerableDirs = [System.Collections.Generic.List[string]]::new()
        foreach ($dir in $pathDirs) {
            $check = Test-LowPrivilegeWriteAccess -Path $dir -ObjectType FileSystem
            if ($check.IsVulnerable) { $vulnerableDirs.Add("$dir [$($check.Principals -join '; ')]") }
        }

        if ($vulnerableDirs.Count -eq 0) {
            Add-AuditResult -Category 'Privilege Escalation - Service & File Permissions' -Control 'Writable PATH Directories' -Status 'PASS' -Severity 'High' `
                -CurrentValue "$($pathDirs.Count) PATH director(y/ies) checked; none writable by low-privilege principals" -RecommendedValue 'No writable PATH directories' `
                -CIS_Control 'CIS 4.8' -NIST_Control 'CM-7, AC-6' -MITRE_Technique 'T1574.007 (Path Interception by PATH Environment Variable)' -ISO27001_Control 'A.8.19' `
                -NIS2_Article 'Art.21(2)(i)' -Recommendation 'No action required.'
        } else {
            Add-AuditResult -Category 'Privilege Escalation - Service & File Permissions' -Control 'Writable PATH Directories' -Status 'FAIL' -Severity 'High' `
                -CurrentValue "$($vulnerableDirs.Count) writable PATH director(y/ies): $($vulnerableDirs -join ' | ')" -RecommendedValue 'No writable PATH directories' `
                -CIS_Control 'CIS 4.8' -NIST_Control 'CM-7, AC-6' -MITRE_Technique 'T1574.007 (Path Interception by PATH Environment Variable)' -ISO27001_Control 'A.8.19' `
                -NIS2_Article 'Art.21(2)(i)' -NSA_Guidance 'NSA/CISA Identity and Access Management Best Practices' `
                -Recommendation 'Remove low-privilege write grants from every listed PATH directory, or remove the directory from PATH entirely if it is not a legitimate, admin-controlled tool location. A writable PATH entry lets any standard user plant binaries that shadow legitimate system tools.'
        }
    } catch {
        Add-AuditResult -Category 'Privilege Escalation - Service & File Permissions' -Control 'Writable PATH Directories' -Status 'WARN' -Severity 'Low' `
            -CurrentValue 'Query failed' -Recommendation "Unable to complete PATH directory ACL audit: $($_.Exception.Message)"
    }
}

function Test-CriticalDirectoryPermissions {
    <#
        Audits a curated set of sensitive, frequently-abused system directories for
        low-privilege write access: the volume root, ProgramData, the Windows Temp
        directory, the Public user profile, the Scheduled Tasks store, and the legacy
        color-profile directory (a historical DLL-planting target).
    #>
    Write-SectionBanner 'Privilege Escalation - Critical Directory Permissions'
    $criticalDirs = @(
        'C:\'
        (Join-Path $env:ProgramData '')
        (Join-Path $env:WINDIR 'Temp')
        'C:\Users\Public'
        (Join-Path $env:WINDIR 'System32\Tasks')
        (Join-Path $env:WINDIR 'System32\spool\drivers\color')
    ) | Select-Object -Unique

    foreach ($dir in $criticalDirs) {
        try {
            if (-not (Test-Path -LiteralPath $dir -PathType Container -ErrorAction SilentlyContinue)) { continue }
            $check = Test-LowPrivilegeWriteAccess -Path $dir -ObjectType FileSystem
            if ($check.IsVulnerable) {
                Add-AuditResult -Category 'Privilege Escalation - Service & File Permissions' -Control "Critical Directory ACL - $dir" -Status 'WARN' -Severity 'Medium' `
                    -CurrentValue "Grants: $($check.Principals -join '; ')" -RecommendedValue 'No low-privilege write grant beyond intended user-writable scope (e.g. C:\Users\Public\Downloads)' `
                    -CIS_Control 'CIS 4.8' -NIST_Control 'CM-7, AC-6' -MITRE_Technique 'T1574 (Hijack Execution Flow)' -ISO27001_Control 'A.8.19' -NIS2_Article 'Art.21(2)(i)' `
                    -Recommendation "Review the ACL on `"$dir`" - some write access here is by design (e.g. ProgramData subfolders, Public), but broad Everyone/Authenticated Users write at the folder root itself is a common privilege-escalation staging ground. Tighten with icacls if the grant is broader than intended."
            } else {
                Add-AuditResult -Category 'Privilege Escalation - Service & File Permissions' -Control "Critical Directory ACL - $dir" -Status 'PASS' -Severity 'Medium' `
                    -CurrentValue 'No low-privilege write grant at directory root' -RecommendedValue 'No low-privilege write grant at directory root' -CIS_Control 'CIS 4.8' `
                    -NIST_Control 'CM-7, AC-6' -ISO27001_Control 'A.8.19' -NIS2_Article 'Art.21(2)(i)' -Recommendation 'No action required.'
            }
        } catch {
            Add-AuditResult -Category 'Privilege Escalation - Service & File Permissions' -Control "Critical Directory ACL - $dir" -Status 'WARN' -Severity 'Low' `
                -CurrentValue 'Query failed' -Recommendation "Unable to audit ACL for ${dir}: $($_.Exception.Message)"
        }
    }
}

#endregion

#region ============================== 19. CREDENTIAL THEFT & LSASS EXPOSURE ==============================

function Test-LSASSAccessAuditing {
    <#
        Audits the "Audit Handle Manipulation" subcategory, the audit-policy prerequisite
        for Event ID 4656/4658 handle-access telemetry. Note this subcategory alone does
        not scope logging to LSASS specifically - a resource SACL must also be applied to
        the lsass.exe process object (via auditpol /resourceSACL) for LSASS handle-open
        attempts to generate events. LSA Protection (RunAsPPL) and Credential Guard, which
        provide preventive rather than detective control here, are audited separately.
    #>
    Write-SectionBanner 'Credential Exposure - LSASS Access Auditing'
    try {
        $auditCsv = & auditpol.exe /get /subcategory:"Handle Manipulation" /r 2>$null | ConvertFrom-Csv
        $setting = if ($auditCsv) { ($auditCsv | Select-Object -First 1).'Inclusion Setting' } else { $null }
        $isConfigured = $setting -match 'Success' -or $setting -match 'Failure'

        if ($isConfigured) {
            Add-AuditResult -Category 'Credential Exposure & Secret Leaks' -Control 'LSASS Handle Access Auditing Prerequisite' -Status 'PASS' -Severity 'Medium' `
                -CurrentValue "Audit Handle Manipulation = $setting" -RecommendedValue 'Success and Failure, plus a resource SACL on lsass.exe' -CIS_Control 'CIS 8.5' `
                -NIST_Control 'AU-2, AU-12' -MITRE_Technique 'T1003.001 (LSASS Memory)' -ISO27001_Control 'A.8.15' -NIS2_Article 'Art.21(2)(b)' `
                -NSA_Guidance 'NSA CSI: Mitigating Credential Theft' `
                -Recommendation 'The audit-policy prerequisite is enabled. Confirm a resource SACL is also applied to lsass.exe (auditpol /resourceSACL /set /type:Process /success /failure /user:Everyone) so Event ID 4656 actually fires for LSASS handle-open attempts, not just that the subcategory is capable of logging them.'
        } else {
            Add-AuditResult -Category 'Credential Exposure & Secret Leaks' -Control 'LSASS Handle Access Auditing Prerequisite' -Status 'FAIL' -Severity 'Medium' `
                -CurrentValue "Audit Handle Manipulation = $setting" -RecommendedValue 'Success and Failure, plus a resource SACL on lsass.exe' -CIS_Control 'CIS 8.5' `
                -NIST_Control 'AU-2, AU-12' -MITRE_Technique 'T1003.001 (LSASS Memory)' -ISO27001_Control 'A.8.15' -NIS2_Article 'Art.21(2)(b)' `
                -NSA_Guidance 'NSA CSI: Mitigating Credential Theft' `
                -Recommendation 'Enable via: auditpol /set /subcategory:"Handle Manipulation" /success:enable /failure:enable, then apply a resource SACL to lsass.exe so credential-dumping tool handle requests against LSASS are captured as Event ID 4656.'
        }
    } catch {
        Add-AuditResult -Category 'Credential Exposure & Secret Leaks' -Control 'LSASS Handle Access Auditing Prerequisite' -Status 'WARN' -Severity 'Low' `
            -CurrentValue 'Query failed' -Recommendation "Unable to query Handle Manipulation audit subcategory: $($_.Exception.Message)"
    }
}

function Test-WDigestCredentialCaching {
    <#
        Audits the WDigest authentication provider's UseLogonCredential setting. When
        enabled (the pre-KB2871997 default), WDigest caches the user's plaintext-equivalent
        password in LSASS memory purely to support a legacy HTTP Digest auth scheme - this
        is precisely what tools like Mimikatz's "sekurlsa::wdigest" module harvest.
    #>
    Write-SectionBanner 'Credential Exposure - WDigest Plaintext Credential Caching'
    try {
        $wdigestPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'
        $useLogonCredential = Get-RegistryValueSafe -Path $wdigestPath -Name 'UseLogonCredential' -DefaultValue 0

        if ([int]$useLogonCredential -eq 0) {
            Add-AuditResult -Category 'Credential Exposure & Secret Leaks' -Control 'WDigest Plaintext Credential Caching' -Status 'PASS' -Severity 'Critical' `
                -CurrentValue 'UseLogonCredential=0 (Disabled)' -RecommendedValue '0' -CIS_Control 'CIS 18.3' -NIST_Control 'IA-5, SC-28' `
                -MITRE_Technique 'T1003.001 (LSASS Memory)' -ISO27001_Control 'A.8.5' -NIS2_Article 'Art.21(2)(h)' -NSA_Guidance 'NSA CSI: Mitigating Credential Theft' `
                -Recommendation 'No action required.'
        } else {
            Add-AuditResult -Category 'Credential Exposure & Secret Leaks' -Control 'WDigest Plaintext Credential Caching' -Status 'FAIL' -Severity 'Critical' `
                -CurrentValue 'UseLogonCredential=1 (Enabled)' -RecommendedValue '0' -CIS_Control 'CIS 18.3' -NIST_Control 'IA-5, SC-28' `
                -MITRE_Technique 'T1003.001 (LSASS Memory)' -ISO27001_Control 'A.8.5' -NIS2_Article 'Art.21(2)(h)' -NSA_Guidance 'NSA CSI: Mitigating Credential Theft' `
                -Recommendation 'Set HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential (DWORD) = 0. With this enabled, any LSASS memory dump yields plaintext-equivalent passwords for every logged-on user, regardless of LSA Protection status.'
        }
    } catch {
        Add-AuditResult -Category 'Credential Exposure & Secret Leaks' -Control 'WDigest Plaintext Credential Caching' -Status 'WARN' -Severity 'Low' `
            -CurrentValue 'Query failed' -Recommendation "Unable to query WDigest configuration: $($_.Exception.Message)"
    }
}

function Test-PlaintextAutologonCredentials {
    <#
        Audits the Winlogon AutoAdminLogon mechanism for a plaintext DefaultPassword value.
        The Winlogon registry key is readable by any authenticated local user by default,
        so a stored plaintext password here is immediately exposed to every account on the
        box.
    #>
    Write-SectionBanner 'Credential Exposure - Plaintext Autologon Credentials'
    try {
        $winlogonPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
        $autoAdminLogon = Get-RegistryValueSafe -Path $winlogonPath -Name 'AutoAdminLogon' -DefaultValue '0'
        $defaultPassword = Get-RegistryValueSafe -Path $winlogonPath -Name 'DefaultPassword' -DefaultValue $null
        $defaultUserName = Get-RegistryValueSafe -Path $winlogonPath -Name 'DefaultUserName' -DefaultValue $null

        if ([string]$autoAdminLogon -eq '1' -and -not [string]::IsNullOrWhiteSpace($defaultPassword)) {
            Add-AuditResult -Category 'Credential Exposure & Secret Leaks' -Control 'Plaintext Autologon Credentials in Registry' -Status 'FAIL' -Severity 'Critical' `
                -CurrentValue "AutoAdminLogon=1; DefaultUserName=$defaultUserName; DefaultPassword=<present, redacted>" -RecommendedValue 'AutoAdminLogon=0, no DefaultPassword value present' `
                -CIS_Control 'CIS 18.3' -NIST_Control 'IA-5, SC-28' -MITRE_Technique 'T1552.002 (Credentials in Registry)' -ISO27001_Control 'A.8.5' -NIS2_Article 'Art.21(2)(h)' `
                -NSA_Guidance 'NSA CSI: Mitigating Credential Theft' `
                -Recommendation 'Remove DefaultPassword from HKLM:\...\Winlogon and disable AutoAdminLogon (set to 0). This registry key is world-readable, exposing the plaintext password to every local account. Use a credential vault or Autologon (Sysinternals), which stores the secret via LSA Secrets rather than plaintext, if autologon is truly required.'
        } elseif ([string]$autoAdminLogon -eq '1') {
            Add-AuditResult -Category 'Credential Exposure & Secret Leaks' -Control 'Plaintext Autologon Credentials in Registry' -Status 'WARN' -Severity 'Medium' `
                -CurrentValue "AutoAdminLogon=1; DefaultUserName=$defaultUserName; no plaintext DefaultPassword found in this key" -RecommendedValue 'AutoAdminLogon=0' `
                -CIS_Control 'CIS 18.3' -NIST_Control 'IA-5, SC-28' -MITRE_Technique 'T1552.002 (Credentials in Registry)' -ISO27001_Control 'A.8.5' -NIS2_Article 'Art.21(2)(h)' `
                -Recommendation 'AutoAdminLogon is enabled without a plaintext DefaultPassword value present (the credential may be stored via LSA Secrets instead, which is less exposed but still bypasses interactive authentication). Disable autologon unless there is a specific, documented business justification (e.g. a kiosk device).'
        } else {
            Add-AuditResult -Category 'Credential Exposure & Secret Leaks' -Control 'Plaintext Autologon Credentials in Registry' -Status 'PASS' -Severity 'Critical' `
                -CurrentValue 'AutoAdminLogon not enabled' -RecommendedValue 'AutoAdminLogon=0' -CIS_Control 'CIS 18.3' -NIST_Control 'IA-5, SC-28' `
                -MITRE_Technique 'T1552.002 (Credentials in Registry)' -ISO27001_Control 'A.8.5' -NIS2_Article 'Art.21(2)(h)' -Recommendation 'No action required.'
        }
    } catch {
        Add-AuditResult -Category 'Credential Exposure & Secret Leaks' -Control 'Plaintext Autologon Credentials in Registry' -Status 'WARN' -Severity 'Low' `
            -CurrentValue 'Query failed' -Recommendation "Unable to query Winlogon autologon configuration: $($_.Exception.Message)"
    }
}

function Test-UnattendedInstallFiles {
    <#
        Searches standard OS deployment staging locations for leftover unattended-install
        answer files (Unattend.xml, Sysprep.inf/.xml), which historically embed local
        Administrator and/or domain-join credentials - in plaintext or trivially reversible
        Base64 - and are frequently never cleaned up after imaging.
    #>
    Write-SectionBanner 'Credential Exposure - Unattended Installation Files'
    $candidatePaths = @(
        (Join-Path $env:WINDIR 'Panther\Unattend.xml')
        (Join-Path $env:WINDIR 'Panther\Unattend\Unattend.xml')
        (Join-Path $env:WINDIR 'Panther\Unattended.xml')
        (Join-Path $env:WINDIR 'System32\Sysprep\Sysprep.inf')
        (Join-Path $env:WINDIR 'System32\Sysprep\Sysprep.xml')
        (Join-Path $env:WINDIR 'System32\Sysprep\Panther\Unattend.xml')
        'C:\Unattend.xml'
        'C:\autounattend.xml'
    ) | Select-Object -Unique

    $foundAny = $false
    foreach ($file in $candidatePaths) {
        try {
            if (-not (Test-Path -LiteralPath $file -PathType Leaf -ErrorAction SilentlyContinue)) { continue }
            $foundAny = $true
            $content = Get-Content -LiteralPath $file -Raw -ErrorAction SilentlyContinue
            $hasCredentialPattern = $content -and ($content -match '(?i)<Password>|<AdministratorPassword>|cpassword\s*=|Password\s*=\s*"')

            if ($hasCredentialPattern) {
                Add-AuditResult -Category 'Credential Exposure & Secret Leaks' -Control "Unattended Install File with Embedded Credential - $file" -Status 'FAIL' -Severity 'Critical' `
                    -CurrentValue 'File present, contains a password-like XML node' -RecommendedValue 'File removed after imaging' -CIS_Control 'CIS 3.3' -NIST_Control 'IA-5, SC-28' `
                    -MITRE_Technique 'T1552.001 (Credentials In Files)' -ISO27001_Control 'A.8.5' -NIS2_Article 'Art.21(2)(h)' -NSA_Guidance 'NSA CSI: Mitigating Credential Theft' `
                    -Recommendation "Delete `"$file`" immediately - unattend/sysprep answer files commonly store the local Administrator password (and sometimes domain-join credentials) in Base64, which is trivially reversible, not encrypted."
            } else {
                Add-AuditResult -Category 'Credential Exposure & Secret Leaks' -Control "Unattended Install File Present - $file" -Status 'WARN' -Severity 'Low' `
                    -CurrentValue 'File present, no obvious password node detected' -RecommendedValue 'File removed after imaging' -CIS_Control 'CIS 3.3' -NIST_Control 'IA-5, SC-28' `
                    -MITRE_Technique 'T1552.001 (Credentials In Files)' -ISO27001_Control 'A.8.5' -NIS2_Article 'Art.21(2)(h)' `
                    -Recommendation "Delete `"$file`" as standard post-imaging hygiene, even though no password node was detected by this scan - these files can still disclose build/infrastructure details useful for reconnaissance."
            }
        } catch {
            # Inaccessible file - skip silently, this is a best-effort presence sweep.
        }
    }

    if (-not $foundAny) {
        Add-AuditResult -Category 'Credential Exposure & Secret Leaks' -Control 'Unattended Installation Files' -Status 'PASS' -Severity 'Critical' `
            -CurrentValue 'No unattend/sysprep answer files found in standard staging locations' -RecommendedValue 'None present' -CIS_Control 'CIS 3.3' -NIST_Control 'IA-5, SC-28' `
            -MITRE_Technique 'T1552.001 (Credentials In Files)' -ISO27001_Control 'A.8.5' -NIS2_Article 'Art.21(2)(h)' -Recommendation 'No action required.'
    }
}

function Test-GPPCachedCredentials {
    <#
        Searches the local Group Policy Preferences client-side extension cache for XML
        files containing a "cpassword" attribute - the (crackable, since the AES key was
        published by Microsoft in MSDN documentation) encrypted password format historically
        used by GPP for local account creation, drive mapping, and scheduled task
        credentials (patched off by default since MS14-025, but pre-existing cached copies
        can persist).
    #>
    Write-SectionBanner 'Credential Exposure - Group Policy Preferences (GPP) Cached Credentials'
    try {
        $gppHistoryPath = Join-Path $env:ProgramData 'Microsoft\Group Policy\History'
        $foundFiles = @()
        if (Test-Path -LiteralPath $gppHistoryPath) {
            $xmlFiles = Get-ChildItem -LiteralPath $gppHistoryPath -Filter '*.xml' -Recurse -ErrorAction SilentlyContinue
            foreach ($xf in $xmlFiles) {
                try {
                    $content = Get-Content -LiteralPath $xf.FullName -Raw -ErrorAction SilentlyContinue
                    if ($content -match '(?i)cpassword\s*=\s*"[^"]+"') { $foundFiles += $xf.FullName }
                } catch { }
            }
        }

        if ($foundFiles.Count -eq 0) {
            Add-AuditResult -Category 'Credential Exposure & Secret Leaks' -Control 'GPP Cached Credentials (cpassword)' -Status 'PASS' -Severity 'Critical' `
                -CurrentValue 'No cpassword-bearing files found in the local GPP history cache' -RecommendedValue 'None present' -CIS_Control 'CIS 18.3' -NIST_Control 'IA-5, SC-28' `
                -MITRE_Technique 'T1552.006 (Group Policy Preferences)' -ISO27001_Control 'A.8.5' -NIS2_Article 'Art.21(2)(h)' -NSA_Guidance 'NSA CSI: Mitigating Credential Theft' `
                -Recommendation 'No action required locally. This check only covers the local CSE cache - if the organization still deploys GPP-based credentials from SYSVOL, that must be remediated centrally at the domain level (MS14-025) regardless of this endpoint''s result.'
        } else {
            Add-AuditResult -Category 'Credential Exposure & Secret Leaks' -Control 'GPP Cached Credentials (cpassword)' -Status 'FAIL' -Severity 'Critical' `
                -CurrentValue "$($foundFiles.Count) file(s) with a cpassword attribute: $($foundFiles -join ' | ')" -RecommendedValue 'None present' -CIS_Control 'CIS 18.3' `
                -NIST_Control 'IA-5, SC-28' -MITRE_Technique 'T1552.006 (Group Policy Preferences)' -ISO27001_Control 'A.8.5' -NIS2_Article 'Art.21(2)(h)' `
                -NSA_Guidance 'NSA CSI: Mitigating Credential Theft' `
                -Recommendation 'The AES key Microsoft used to encrypt GPP cpassword values has been public since 2012 (MS14-025); any cpassword value is equivalent to a plaintext password. Remove the offending GPP policy at the domain level (Group Policy Preferences credential-based items), then purge this local cache and rotate every credential that was ever distributed this way.'
        }
    } catch {
        Add-AuditResult -Category 'Credential Exposure & Secret Leaks' -Control 'GPP Cached Credentials (cpassword)' -Status 'WARN' -Severity 'Low' `
            -CurrentValue 'Query failed' -Recommendation "Unable to search the local GPP history cache: $($_.Exception.Message)"
    }
}

function Test-SAMSystemHiveProtection {
    <#
        Audits filesystem ACLs on the live SAM, SYSTEM, and SECURITY registry hive files,
        and notes the presence of Volume Shadow Copies (a well-known avenue for extracting
        older, potentially less-protected copies of these hives via "vssadmin" + "reg save").
    #>
    Write-SectionBanner 'Credential Exposure - SAM/SYSTEM/SECURITY Hive Protection'
    $hiveFiles = @('SAM', 'SYSTEM', 'SECURITY') | ForEach-Object { Join-Path $env:WINDIR "System32\config\$_" }
    $anyVulnerable = $false
    $anyHiveFound = $false
    foreach ($hive in $hiveFiles) {
        try {
            if (-not (Test-Path -LiteralPath $hive -ErrorAction SilentlyContinue)) { continue }
            $anyHiveFound = $true
            $check = Test-LowPrivilegeWriteAccess -Path $hive -ObjectType FileSystem
            if ($check.IsVulnerable) {
                $anyVulnerable = $true
                Add-AuditResult -Category 'Credential Exposure & Secret Leaks' -Control "Registry Hive File Permissions - $(Split-Path $hive -Leaf)" -Status 'FAIL' -Severity 'Critical' `
                    -CurrentValue "Grants: $($check.Principals -join '; ')" -RecommendedValue 'No Everyone/Authenticated Users/Users grant' -CIS_Control 'CIS 18.3' -NIST_Control 'AC-6, SC-28' `
                    -MITRE_Technique 'T1003.002 (Security Account Manager)' -ISO27001_Control 'A.8.5' -NIS2_Article 'Art.21(2)(h)' -NSA_Guidance 'NSA CSI: Mitigating Credential Theft' `
                    -Recommendation "Restore default NTFS permissions on `"$hive`" (SYSTEM/Administrators only): icacls `"$hive`" /reset, then re-apply inheritance from the parent System32\config folder."
            } else {
                Add-AuditResult -Category 'Credential Exposure & Secret Leaks' -Control "Registry Hive File Permissions - $(Split-Path $hive -Leaf)" -Status 'PASS' -Severity 'Critical' `
                    -CurrentValue 'Default-restrictive ACL (no low-privilege grant found)' -RecommendedValue 'No Everyone/Authenticated Users/Users grant' -CIS_Control 'CIS 18.3' `
                    -NIST_Control 'AC-6, SC-28' -MITRE_Technique 'T1003.002 (Security Account Manager)' -ISO27001_Control 'A.8.5' -NIS2_Article 'Art.21(2)(h)' -Recommendation 'No action required.'
            }
        } catch {
            Add-AuditResult -Category 'Credential Exposure & Secret Leaks' -Control "Registry Hive File Permissions - $(Split-Path $hive -Leaf)" -Status 'WARN' -Severity 'Low' `
                -CurrentValue 'Query failed' -Recommendation "Unable to audit ACL for ${hive}: $($_.Exception.Message)"
        }
    }

    if (-not $anyHiveFound) {
        Add-AuditResult -Category 'Credential Exposure & Secret Leaks' -Control 'Registry Hive File Permissions (SAM/SYSTEM/SECURITY)' -Status 'WARN' -Severity 'Low' `
            -CurrentValue 'None of SAM, SYSTEM, or SECURITY were found at the standard System32\config path' -RecommendedValue 'Hive files present with default-restrictive ACLs' `
            -CIS_Control 'CIS 18.3' -NIST_Control 'AC-6, SC-28' -Recommendation 'Unexpected on a standard Windows 11 installation - verify this endpoint''s System32\config directory is intact, or that this scan is not running inside a restricted/virtualized context that hides the path.'
    }

    try {
        $shadowOutput = & vssadmin.exe list shadows /for=C: 2>$null
        $shadowCount = 0
        if ($shadowOutput) { $shadowCount = @($shadowOutput | Select-String -Pattern 'Shadow Copy ID' -SimpleMatch).Count }
        if ($shadowCount -gt 0) {
            Add-AuditResult -Category 'Credential Exposure & Secret Leaks' -Control 'Volume Shadow Copy Exposure (SAM/SYSTEM Backup Vector)' -Status 'INFO' -Severity 'Informational' `
                -CurrentValue "$shadowCount shadow copy/copies present on C:" -RecommendedValue 'Awareness item - not inherently a misconfiguration' -CIS_Control 'CIS 18.3' `
                -NIST_Control 'AC-6, SC-28' -MITRE_Technique 'T1003.002 (Security Account Manager)' -ISO27001_Control 'A.8.5' -NIS2_Article 'Art.21(2)(h)' `
                -Recommendation 'Shadow copies can be used to extract SAM/SYSTEM/NTDS.dit via "reg save" against a mounted shadow copy path, bypassing the live-file lock. This is expected on many systems (System Restore/backup software) - ensure only Administrators can invoke vssadmin/wmic shadowcopy and that EDR alerts on shadow-copy-based hive extraction attempts.'
        }
    } catch {
        # vssadmin unavailable or restricted - not a failure condition for this awareness check.
    }

    if (-not $anyVulnerable) {
        Write-Host '  (No SAM/SYSTEM/SECURITY hive ACL vulnerabilities found)' -ForegroundColor Green
    }
}

function Test-LSASecurityPackages {
    <#
        Compares the Security Support Providers and Authentication Packages registered
        under LSA control against a broad known-legitimate baseline, flagging any
        unrecognized entry for manual review. Malicious SSP registration (e.g. a custom DLL
        that logs every plaintext credential passed through LSA) is a known LSASS-adjacent
        persistence/collection technique.
    #>
    Write-SectionBanner 'Credential Exposure - LSA Security Package Registration'
    try {
        $knownSecurityPackages = @('kerberos', 'msv1_0', 'schannel', 'wdigest', 'tspkg', 'pku2u', 'cloudap', 'negoexts', 'livessp', 'eap', '"kerberos"', '"msv1_0"')
        $knownAuthPackages = @('msv1_0', 'kerberos', 'negotiate', 'wdigest', 'schannel', 'pku2u')

        $lsaPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
        $securityPackages = @()
        $authPackages = @()
        try { $securityPackages = @((Get-ItemProperty -LiteralPath $lsaPath -Name 'Security Packages' -ErrorAction Stop).'Security Packages') } catch { $securityPackages = @() }
        try { $authPackages = @((Get-ItemProperty -LiteralPath $lsaPath -Name 'Authentication Packages' -ErrorAction Stop).'Authentication Packages') } catch { $authPackages = @() }

        $unexpectedSecurity = @($securityPackages | Where-Object { $_ -and ($_.Trim() -ne '') -and ($knownSecurityPackages -notcontains $_.Trim().ToLower()) })
        $unexpectedAuth = @($authPackages | Where-Object { $_ -and ($_.Trim() -ne '') -and ($knownAuthPackages -notcontains $_.Trim().ToLower()) })

        if ($unexpectedSecurity.Count -eq 0 -and $unexpectedAuth.Count -eq 0) {
            Add-AuditResult -Category 'Credential Exposure & Secret Leaks' -Control 'LSA Security Package / Authentication Package Registration' -Status 'PASS' -Severity 'High' `
                -CurrentValue "Security Packages: $($securityPackages -join ', '); Authentication Packages: $($authPackages -join ', ')" -RecommendedValue 'Only known Microsoft-provided packages registered' `
                -CIS_Control 'CIS 18.3' -NIST_Control 'CM-7, SI-7' -MITRE_Technique 'T1556.002 (Security Support Provider)' -ISO27001_Control 'A.8.19' -NIS2_Article 'Art.21(2)(e)' `
                -NSA_Guidance 'NSA CSI: Mitigating Credential Theft' -Recommendation 'No action required.'
        } else {
            Add-AuditResult -Category 'Credential Exposure & Secret Leaks' -Control 'LSA Security Package / Authentication Package Registration' -Status 'WARN' -Severity 'High' `
                -CurrentValue "Unexpected Security Packages: $($unexpectedSecurity -join ', '); Unexpected Authentication Packages: $($unexpectedAuth -join ', ')" `
                -RecommendedValue 'Only known Microsoft-provided packages registered' -CIS_Control 'CIS 18.3' -NIST_Control 'CM-7, SI-7' -MITRE_Technique 'T1556.002 (Security Support Provider)' `
                -ISO27001_Control 'A.8.19' -NIS2_Article 'Art.21(2)(e)' -NSA_Guidance 'NSA CSI: Mitigating Credential Theft' `
                -Recommendation 'Investigate each unrecognized package: locate its backing DLL (via the corresponding value under HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\SecurityProviders or the package''s own registration key), verify it is signed by a trusted vendor (smartcard middleware, VPN clients, and some AV suites legitimately register SSPs), and remove it if it cannot be attributed to approved software - malicious SSPs can intercept every credential that passes through LSA in plaintext.'
        }
    } catch {
        Add-AuditResult -Category 'Credential Exposure & Secret Leaks' -Control 'LSA Security Package / Authentication Package Registration' -Status 'WARN' -Severity 'Low' `
            -CurrentValue 'Query failed' -Recommendation "Unable to enumerate registered LSA packages: $($_.Exception.Message)"
    }
}

#endregion

#region ============================== 20. PRIVILEGED TOKEN, PROCESS & COM HIJACKING ==============================

function Test-DangerousPrivilegeAssignments {
    <#
        Audits nine high-risk User Rights Assignment privileges against a baseline of the
        principals Windows grants them to by default, flagging any additional principal.
        This deliberately does NOT flag the default assignments (e.g. SeImpersonatePrivilege
        is legitimately granted to LOCAL SERVICE/NETWORK SERVICE/SERVICE on every stock
        Windows install - that is how the "Potato" attack family abuses an EXISTING default,
        not a misconfiguration). The actionable signal is an unexpected extra principal.
    #>
    Write-SectionBanner 'Privileged Token Abuse - Dangerous Privilege Assignments'
    $tempCfg = Join-Path -Path $env:TEMP -ChildPath "EndpointPostureCheck_privaudit_$PID.cfg"
    try {
        $null = & secedit.exe /export /cfg $tempCfg /areas USER_RIGHTS /quiet 2>$null
        if (-not (Test-Path -LiteralPath $tempCfg)) { throw 'secedit export failed to produce output file' }
        $cfg = Get-Content -LiteralPath $tempCfg -ErrorAction Stop

        function Get-PrivLineLocal {
            param($lines, $key)
            $line = $lines | Where-Object { $_ -match "^\s*$key\s*=" } | Select-Object -First 1
            if ($line) { return (($line -split '=', 2)[1].Trim()) }
            return ''
        }

        $privilegeBaseline = @(
            @{ Name = 'SeImpersonatePrivilege';       Baseline = @('S-1-5-32-544','S-1-5-19','S-1-5-20','S-1-5-6'); Severity = 'High';     Mitre = 'T1134 (Access Token Manipulation), T1068 (Exploitation for Privilege Escalation) - "Potato" family' }
            @{ Name = 'SeAssignPrimaryTokenPrivilege'; Baseline = @('S-1-5-19','S-1-5-20');                        Severity = 'High';     Mitre = 'T1134 (Access Token Manipulation)' }
            @{ Name = 'SeDebugPrivilege';              Baseline = @('S-1-5-32-544');                              Severity = 'Critical'; Mitre = 'T1003.001 (LSASS Memory), T1055 (Process Injection)' }
            @{ Name = 'SeBackupPrivilege';             Baseline = @('S-1-5-32-544','S-1-5-32-551');                Severity = 'High';     Mitre = 'T1003.002 (Security Account Manager)' }
            @{ Name = 'SeRestorePrivilege';            Baseline = @('S-1-5-32-544','S-1-5-32-551');                Severity = 'High';     Mitre = 'T1222 (File and Directory Permissions Modification)' }
            @{ Name = 'SeTakeOwnershipPrivilege';      Baseline = @('S-1-5-32-544');                              Severity = 'High';     Mitre = 'T1222 (File and Directory Permissions Modification)' }
            @{ Name = 'SeLoadDriverPrivilege';         Baseline = @('S-1-5-32-544');                              Severity = 'Critical'; Mitre = 'T1068 (Exploitation for Privilege Escalation) - BYOVD' }
            @{ Name = 'SeTcbPrivilege';                Baseline = @();                                            Severity = 'Critical'; Mitre = 'T1134 (Access Token Manipulation)' }
            @{ Name = 'SeCreateTokenPrivilege';        Baseline = @();                                            Severity = 'Critical'; Mitre = 'T1134.002 (Create Process with Token)' }
        )

        foreach ($priv in $privilegeBaseline) {
            $rawLine = Get-PrivLineLocal $cfg $priv.Name
            $assignedSids = @($rawLine -split ',' | ForEach-Object { $_.Trim().TrimStart('*') } | Where-Object { $_ -ne '' })
            $extraSids = @($assignedSids | Where-Object { $priv.Baseline -notcontains $_ })

            if ($extraSids.Count -eq 0) {
                Add-AuditResult -Category 'Privilege Escalation - Token & Privilege Abuse' -Control "Dangerous Privilege Assignment - $($priv.Name)" -Status 'PASS' -Severity $priv.Severity `
                    -CurrentValue 'Assigned only to expected default principals' -RecommendedValue 'No principals beyond the Windows-default baseline' -CIS_Control 'CIS 5.2' `
                    -NIST_Control 'AC-6' -MITRE_Technique $priv.Mitre -ISO27001_Control 'A.8.2' -NIS2_Article 'Art.21(2)(i)' -NSA_Guidance 'NSA/CISA Identity and Access Management Best Practices' `
                    -Recommendation 'No action required.'
            } else {
                $resolvedNames = $extraSids | ForEach-Object {
                    $sid = $_
                    try { (New-Object System.Security.Principal.SecurityIdentifier($sid)).Translate([System.Security.Principal.NTAccount]).Value }
                    catch { $sid }
                }
                Add-AuditResult -Category 'Privilege Escalation - Token & Privilege Abuse' -Control "Dangerous Privilege Assignment - $($priv.Name)" -Status 'FAIL' -Severity $priv.Severity `
                    -CurrentValue "Also assigned to: $($resolvedNames -join ', ')" -RecommendedValue 'No principals beyond the Windows-default baseline' -CIS_Control 'CIS 5.2' `
                    -NIST_Control 'AC-6' -MITRE_Technique $priv.Mitre -ISO27001_Control 'A.8.2' -NIS2_Article 'Art.21(2)(i)' -NSA_Guidance 'NSA/CISA Identity and Access Management Best Practices' `
                    -Recommendation "Review why $($resolvedNames -join ', ') hold(s) `"$($priv.Name)`" beyond the Windows-default baseline. If unjustified, remove via Local Security Policy > User Rights Assignment. A non-default account holding this right is a common precondition for token-impersonation privilege escalation."
            }
        }
    } catch {
        Add-AuditResult -Category 'Privilege Escalation - Token & Privilege Abuse' -Control 'Dangerous Privilege Assignments' -Status 'WARN' -Severity 'Low' `
            -CurrentValue 'Query failed' -Recommendation "Unable to export/parse dangerous privilege assignments via secedit: $($_.Exception.Message)"
    } finally {
        if (Test-Path -LiteralPath $tempCfg) { Remove-Item -LiteralPath $tempCfg -Force -ErrorAction SilentlyContinue }
    }
}

function Test-COMCLSIDHijacking {
    <#
        Compares CLSIDs registered under the per-user HKCU:\Software\Classes\CLSID hive
        against the system-wide HKLM class registry. HKCU overlap with HKLM is common and
        legitimate (many installers register per-user COM customizations by design), so
        this check narrows to the actionable signal: an overlapping CLSID whose HKCU
        InprocServer32 default value points at a non-standard, user-writable location
        (Temp, Downloads, Desktop) rather than a normal installed-application path.
    #>
    Write-SectionBanner 'Privileged Token Abuse - COM CLSID Hijacking'
    try {
        $hkcuClsidPath = 'HKCU:\Software\Classes\CLSID'
        $hklmClsidPath = 'HKLM:\SOFTWARE\Classes\CLSID'
        if (-not (Test-Path -LiteralPath $hkcuClsidPath)) {
            Add-AuditResult -Category 'Privilege Escalation - Token & Privilege Abuse' -Control 'COM CLSID Hijacking (HKCU Override)' -Status 'PASS' -Severity 'Medium' `
                -CurrentValue 'No per-user CLSID registrations present' -RecommendedValue 'No suspicious HKCU CLSID overrides' -CIS_Control 'CIS 2.5' -NIST_Control 'CM-7, SI-7' `
                -MITRE_Technique 'T1546.015 (Component Object Model Hijacking)' -ISO27001_Control 'A.8.19' -NIS2_Article 'Art.21(2)(e)' -Recommendation 'No action required.'
            return
        }

        $hklmSet = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        if (Test-Path -LiteralPath $hklmClsidPath) {
            Get-ChildItem -LiteralPath $hklmClsidPath -ErrorAction SilentlyContinue | ForEach-Object { [void]$hklmSet.Add($_.PSChildName) }
        }

        $suspicious = [System.Collections.Generic.List[string]]::new()
        $overlapCount = 0
        Get-ChildItem -LiteralPath $hkcuClsidPath -ErrorAction SilentlyContinue | ForEach-Object {
            $clsid = $_.PSChildName
            if (-not $hklmSet.Contains($clsid)) { return }
            $overlapCount++
            $inprocPath = Join-Path $_.PSPath 'InprocServer32'
            $dllPath = $null
            try { $dllPath = (Get-ItemProperty -LiteralPath $inprocPath -Name '(default)' -ErrorAction Stop).'(default)' } catch { $dllPath = $null }
            if ($dllPath -and ($dllPath -match '(?i)\\(Temp|Downloads|Desktop)\\')) {
                $suspicious.Add("$clsid -> $dllPath")
            }
        }

        if ($suspicious.Count -gt 0) {
            Add-AuditResult -Category 'Privilege Escalation - Token & Privilege Abuse' -Control 'COM CLSID Hijacking (HKCU Override)' -Status 'FAIL' -Severity 'High' `
                -CurrentValue "$($suspicious.Count) HKCU CLSID override(s) pointing to a Temp/Downloads/Desktop path: $($suspicious -join ' | ')" `
                -RecommendedValue 'No HKCU CLSID override resolving to a Temp/Downloads/Desktop path' -CIS_Control 'CIS 2.5' -NIST_Control 'CM-7, SI-7' `
                -MITRE_Technique 'T1546.015 (Component Object Model Hijacking)' -ISO27001_Control 'A.8.19' -NIS2_Article 'Art.21(2)(e)' `
                -Recommendation 'These CLSIDs also exist at the system level (HKLM) but have been overridden per-user to load a DLL from a non-standard, easily-writable location. Inspect the listed DLL(s); if illegitimate, remove the HKCU:\Software\Classes\CLSID\<GUID> key and investigate how it was created (this is a documented persistence/hijack technique that silently redirects any process instantiating that COM object, including elevated callers under some UAC auto-elevation paths).'
        } elseif ($overlapCount -gt 0) {
            Add-AuditResult -Category 'Privilege Escalation - Token & Privilege Abuse' -Control 'COM CLSID Hijacking (HKCU Override)' -Status 'PASS' -Severity 'Medium' `
                -CurrentValue "$overlapCount HKCU/HKLM CLSID overlap(s) found; none resolve to a Temp/Downloads/Desktop path" -RecommendedValue 'No suspicious HKCU CLSID overrides' `
                -CIS_Control 'CIS 2.5' -NIST_Control 'CM-7, SI-7' -MITRE_Technique 'T1546.015 (Component Object Model Hijacking)' -ISO27001_Control 'A.8.19' -NIS2_Article 'Art.21(2)(e)' `
                -Recommendation 'HKCU/HKLM CLSID overlap is common and often legitimate (per-user application customization). No action required; the elevated Temp/Downloads/Desktop-path signal, which would indicate active hijacking, was not observed.'
        } else {
            Add-AuditResult -Category 'Privilege Escalation - Token & Privilege Abuse' -Control 'COM CLSID Hijacking (HKCU Override)' -Status 'PASS' -Severity 'Medium' `
                -CurrentValue 'No HKCU/HKLM CLSID overlap found' -RecommendedValue 'No suspicious HKCU CLSID overrides' -CIS_Control 'CIS 2.5' -NIST_Control 'CM-7, SI-7' `
                -MITRE_Technique 'T1546.015 (Component Object Model Hijacking)' -ISO27001_Control 'A.8.19' -NIS2_Article 'Art.21(2)(e)' -Recommendation 'No action required.'
        }
    } catch {
        Add-AuditResult -Category 'Privilege Escalation - Token & Privilege Abuse' -Control 'COM CLSID Hijacking (HKCU Override)' -Status 'WARN' -Severity 'Low' `
            -CurrentValue 'Query failed' -Recommendation "Unable to complete COM CLSID hijacking audit: $($_.Exception.Message)"
    }
}

function Test-OrphanedPrivilegedScheduledTasks {
    <#
        Audits scheduled tasks that run as SYSTEM or at the highest run level for two
        distinct hijack preconditions: the target executable is missing entirely (an
        attacker can plant a replacement at that exact path and wait for the task to fire),
        or the target resides in a directory writable by a low-privileged principal.
    #>
    Write-SectionBanner 'Privileged Token Abuse - Orphaned/Hijackable Privileged Scheduled Tasks'
    try {
        $tasks = Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.State -ne 'Disabled' }
        $orphaned = [System.Collections.Generic.List[string]]::new()
        $writableTarget = [System.Collections.Generic.List[string]]::new()

        foreach ($task in $tasks) {
            $principal = $task.Principal
            $runAsUser = [string]$principal.UserId
            $isPrivileged = ($runAsUser -match '(?i)SYSTEM|TrustedInstaller|Administrators') -or ($principal.RunLevel -eq 'Highest')
            if (-not $isPrivileged) { continue }

            foreach ($action in $task.Actions) {
                if (-not $action.Execute) { continue }
                $rawExecute = [Environment]::ExpandEnvironmentVariables($action.Execute)
                $taskLabel = "$($task.TaskPath)$($task.TaskName) (Runs as: $runAsUser)"

                $resolved = $null
                if (Test-Path -LiteralPath $rawExecute -ErrorAction SilentlyContinue) {
                    $resolved = $rawExecute
                } elseif ($rawExecute -notmatch '[\\/]') {
                    $cmd = Get-Command $rawExecute -ErrorAction SilentlyContinue
                    if ($cmd) { $resolved = $cmd.Source }
                }

                if (-not $resolved) {
                    $orphaned.Add("$taskLabel -> $rawExecute [target not found]")
                } else {
                    $check = Test-LowPrivilegeWriteAccess -Path $resolved -ObjectType FileSystem
                    if ($check.IsVulnerable) {
                        $writableTarget.Add("$taskLabel -> $resolved [$($check.Principals -join '; ')]")
                    }
                }
            }
        }

        if ($orphaned.Count -eq 0) {
            Add-AuditResult -Category 'Privilege Escalation - Token & Privilege Abuse' -Control 'Orphaned Privileged Scheduled Tasks' -Status 'PASS' -Severity 'High' `
                -CurrentValue 'No privileged scheduled task references a missing target executable' -RecommendedValue 'None found' -CIS_Control 'CIS 4.8' -NIST_Control 'CM-7, AC-6' `
                -MITRE_Technique 'T1053.005 (Scheduled Task)' -ISO27001_Control 'A.8.19' -NIS2_Article 'Art.21(2)(i)' -Recommendation 'No action required.'
        } else {
            Add-AuditResult -Category 'Privilege Escalation - Token & Privilege Abuse' -Control 'Orphaned Privileged Scheduled Tasks' -Status 'FAIL' -Severity 'High' `
                -CurrentValue "$($orphaned.Count) task(s) reference a missing target: $($orphaned -join ' | ')" -RecommendedValue 'None found' -CIS_Control 'CIS 4.8' `
                -NIST_Control 'CM-7, AC-6' -MITRE_Technique 'T1053.005 (Scheduled Task)' -ISO27001_Control 'A.8.19' -NIS2_Article 'Art.21(2)(i)' `
                -Recommendation 'For each listed task, either disable/delete it if it is stale leftover from removed software, or restore the missing binary. A privileged scheduled task pointing at a nonexistent path lets any user who can write to that exact location gain code execution in the task''s context on next trigger.'
        }

        if ($writableTarget.Count -eq 0) {
            Add-AuditResult -Category 'Privilege Escalation - Token & Privilege Abuse' -Control 'Privileged Scheduled Task Target ACLs' -Status 'PASS' -Severity 'High' `
                -CurrentValue 'No privileged scheduled task target is writable by a low-privilege principal' -RecommendedValue 'None found' -CIS_Control 'CIS 4.8' -NIST_Control 'CM-7, AC-6' `
                -MITRE_Technique 'T1053.005 (Scheduled Task)' -ISO27001_Control 'A.8.19' -NIS2_Article 'Art.21(2)(i)' -Recommendation 'No action required.'
        } else {
            Add-AuditResult -Category 'Privilege Escalation - Token & Privilege Abuse' -Control 'Privileged Scheduled Task Target ACLs' -Status 'FAIL' -Severity 'Critical' `
                -CurrentValue "$($writableTarget.Count) task target(s) writable by a low-privilege principal: $($writableTarget -join ' | ')" -RecommendedValue 'None found' -CIS_Control 'CIS 4.8' `
                -NIST_Control 'CM-7, AC-6' -MITRE_Technique 'T1053.005 (Scheduled Task)' -ISO27001_Control 'A.8.19' -NIS2_Article 'Art.21(2)(i)' `
                -Recommendation 'Tighten the ACL on each listed target so it is not writable by Everyone/Authenticated Users/Users. A low-privileged user can overwrite the binary a SYSTEM-context task will execute on its next scheduled run - a direct and reliable local privilege escalation path.'
        }
    } catch {
        Add-AuditResult -Category 'Privilege Escalation - Token & Privilege Abuse' -Control 'Orphaned/Hijackable Privileged Scheduled Tasks' -Status 'WARN' -Severity 'Low' `
            -CurrentValue 'Query failed' -Recommendation "Unable to enumerate scheduled tasks: $($_.Exception.Message)"
    }
}

function Test-UACInstallerDetection {
    <#
        Audits the "User Account Control: Detect application installations and prompt for
        elevation" policy. Its correct posture is environment-dependent: recommended ON for
        unmanaged/standalone systems (the safety net that prompts when a legacy installer
        tries to write to protected locations without a manifest), and commonly turned OFF
        in centrally managed enterprises that deploy signed packages via Intune/SCCM - so
        this is reported without an unconditional PASS/FAIL judgement.
    #>
    Write-SectionBanner 'Privileged Token Abuse - UAC Installer Detection'
    try {
        $uacPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
        $installerDetection = Get-RegistryValueSafe -Path $uacPath -Name 'EnableInstallerDetection' -DefaultValue 1

        if ([int]$installerDetection -eq 1) {
            Add-AuditResult -Category 'Privilege Escalation - Token & Privilege Abuse' -Control 'UAC Installer Detection' -Status 'PASS' -Severity 'Low' `
                -CurrentValue 'Enabled' -RecommendedValue 'Enabled (standalone/unmanaged); acceptable Disabled in a managed enterprise deploying signed packages via Intune/SCCM' `
                -CIS_Control 'CIS 5.4' -NIST_Control 'AC-6, CM-7' -MITRE_Technique 'T1548.002 (Bypass User Account Control)' -ISO27001_Control 'A.8.2' -NIS2_Article 'Art.21(2)(i)' `
                -Recommendation 'No action required.'
        } else {
            Add-AuditResult -Category 'Privilege Escalation - Token & Privilege Abuse' -Control 'UAC Installer Detection' -Status 'INFO' -Severity 'Informational' `
                -CurrentValue 'Disabled' -RecommendedValue 'Enabled (standalone/unmanaged); acceptable Disabled in a managed enterprise deploying signed packages via Intune/SCCM' `
                -CIS_Control 'CIS 5.4' -NIST_Control 'AC-6, CM-7' -ISO27001_Control 'A.8.2' -NIS2_Article 'Art.21(2)(i)' `
                -Recommendation 'Disabled is an accepted, common posture on domain/Intune-managed enterprise fleets where software is deployed through a controlled, signed pipeline rather than ad hoc legacy installers. Confirm this device is centrally managed; if it is a standalone/unmanaged endpoint, re-enable this setting.'
        }
    } catch {
        Add-AuditResult -Category 'Privilege Escalation - Token & Privilege Abuse' -Control 'UAC Installer Detection' -Status 'WARN' -Severity 'Low' `
            -CurrentValue 'Query failed' -Recommendation "Unable to query UAC installer detection policy: $($_.Exception.Message)"
    }
}

#endregion

#region ============================== 21. KERNEL & DRIVER SECURITY ==============================

function Test-VulnerableDriverProtections {
    <#
        Audits three independent kernel-attack-surface controls: the Microsoft Vulnerable
        Driver Blocklist (blocks known-exploitable signed drivers regardless of HVCI state),
        kernel-mode Test Signing mode (which - if enabled - permits unsigned/test-signed
        drivers to load and should never be on outside a driver-development machine), and
        Authenticode signature validity across all currently loaded kernel drivers.
    #>
    Write-SectionBanner 'Kernel & Driver Security - Vulnerable Driver Protections (BYOVD)'
    try {
        $blocklistPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config'
        $blocklistEnabled = Get-RegistryValueSafe -Path $blocklistPath -Name 'VulnerableDriverBlocklistEnable' -DefaultValue $null

        if ($blocklistEnabled -eq 1) {
            Add-AuditResult -Category 'Kernel & Driver Security' -Control 'Microsoft Vulnerable Driver Blocklist' -Status 'PASS' -Severity 'High' `
                -CurrentValue 'Enabled' -RecommendedValue 'Enabled' -CIS_Control 'CIS 10.5' -NIST_Control 'SI-7, CM-7' `
                -MITRE_Technique 'T1068 (Exploitation for Privilege Escalation) - Bring Your Own Vulnerable Driver (BYOVD)' -ISO27001_Control 'A.8.7' -NIS2_Article 'Art.21(2)(e)' `
                -NSA_Guidance 'NSA/CISA Advisory: Identity and Access Management for BYOVD Mitigation' -Recommendation 'No action required.'
        } else {
            Add-AuditResult -Category 'Kernel & Driver Security' -Control 'Microsoft Vulnerable Driver Blocklist' -Status 'FAIL' -Severity 'High' `
                -CurrentValue 'Not explicitly enabled' -RecommendedValue 'Enabled' -CIS_Control 'CIS 10.5' -NIST_Control 'SI-7, CM-7' `
                -MITRE_Technique 'T1068 (Exploitation for Privilege Escalation) - BYOVD' -ISO27001_Control 'A.8.7' -NIS2_Article 'Art.21(2)(e)' `
                -Recommendation 'Enable "Windows Security > Device Security > Core isolation > Memory integrity" (HVCI enables it automatically) or set HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config\VulnerableDriverBlocklistEnable (DWORD) = 1 directly. This blocks known-vulnerable signed drivers commonly abused for kernel-mode code execution (BYOVD attacks used by ransomware crews to disable EDR).'
        }

        $testSigningOn = $false
        try {
            $bcdOutput = & bcdedit.exe /enum '{current}' 2>$null
            if ($bcdOutput) {
                $tsLine = $bcdOutput | Where-Object { $_ -match '(?i)testsigning' } | Select-Object -First 1
                if ($tsLine -and $tsLine -match '(?i)Yes') { $testSigningOn = $true }
            }
        } catch { }

        if ($testSigningOn) {
            Add-AuditResult -Category 'Kernel & Driver Security' -Control 'Kernel-Mode Test Signing' -Status 'FAIL' -Severity 'Critical' `
                -CurrentValue 'Enabled' -RecommendedValue 'Disabled (No)' -CIS_Control 'CIS 10.5' -NIST_Control 'SI-7, CM-7' `
                -MITRE_Technique 'T1068 (Exploitation for Privilege Escalation), T1014 (Rootkit)' -ISO27001_Control 'A.8.7' -NIS2_Article 'Art.21(2)(e)' `
                -Recommendation 'Run "bcdedit /set testsigning off" and reboot. Test Signing mode permits unsigned or self-signed kernel drivers to load - a common precondition for kernel rootkits and should only ever be present on a driver-development VM, never a production endpoint.'
        } else {
            Add-AuditResult -Category 'Kernel & Driver Security' -Control 'Kernel-Mode Test Signing' -Status 'PASS' -Severity 'Critical' `
                -CurrentValue 'Disabled' -RecommendedValue 'Disabled (No)' -CIS_Control 'CIS 10.5' -NIST_Control 'SI-7, CM-7' -ISO27001_Control 'A.8.7' -NIS2_Article 'Art.21(2)(e)' `
                -Recommendation 'No action required.'
        }

        try {
            $runningDrivers = Get-CimInstance -ClassName Win32_SystemDriver -Filter "State='Running'" -ErrorAction Stop | Where-Object { $_.PathName }
            $unsignedDrivers = [System.Collections.Generic.List[string]]::new()
            $checkedPaths = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
            foreach ($drv in $runningDrivers) {
                $drvPath = $drv.PathName -replace '^\\\?\?\\', ''
                if (-not (Test-Path -LiteralPath $drvPath -ErrorAction SilentlyContinue)) { continue }
                if (-not $checkedPaths.Add($drvPath)) { continue }
                try {
                    $sig = Get-AuthenticodeSignature -LiteralPath $drvPath -ErrorAction Stop
                    if ($sig.Status -ne 'Valid') { $unsignedDrivers.Add("$($drv.Name) ($drvPath) [$($sig.Status)]") }
                } catch { }
            }

            if ($unsignedDrivers.Count -eq 0) {
                Add-AuditResult -Category 'Kernel & Driver Security' -Control 'Loaded Kernel Driver Signature Validity' -Status 'PASS' -Severity 'High' `
                    -CurrentValue "$($checkedPaths.Count) running driver(s) checked; all have a valid Authenticode signature" -RecommendedValue 'All running drivers validly signed' `
                    -CIS_Control 'CIS 10.5' -NIST_Control 'SI-7, CM-7' -MITRE_Technique 'T1014 (Rootkit)' -ISO27001_Control 'A.8.7' -NIS2_Article 'Art.21(2)(e)' -Recommendation 'No action required.'
            } else {
                Add-AuditResult -Category 'Kernel & Driver Security' -Control 'Loaded Kernel Driver Signature Validity' -Status 'FAIL' -Severity 'Critical' `
                    -CurrentValue "$($unsignedDrivers.Count) running driver(s) with an invalid/missing signature: $(($unsignedDrivers | Select-Object -First 10) -join ' | ')" `
                    -RecommendedValue 'All running drivers validly signed' -CIS_Control 'CIS 10.5' -NIST_Control 'SI-7, CM-7' -MITRE_Technique 'T1014 (Rootkit), T1068 (Exploitation for Privilege Escalation)' `
                    -ISO27001_Control 'A.8.7' -NIS2_Article 'Art.21(2)(e)' `
                    -Recommendation 'Investigate each listed driver: an invalid, expired-without-timestamping, or missing signature on a currently-loaded kernel driver is a strong rootkit/BYOVD indicator. Correlate with Microsoft Defender/MDE alerts and consider offline forensic imaging if the driver cannot be attributed to legitimate, expected hardware/software.'
            }
        } catch {
            Add-AuditResult -Category 'Kernel & Driver Security' -Control 'Loaded Kernel Driver Signature Validity' -Status 'WARN' -Severity 'Low' `
                -CurrentValue 'Query failed' -Recommendation "Unable to enumerate/verify loaded kernel drivers: $($_.Exception.Message)"
        }
    } catch {
        Add-AuditResult -Category 'Kernel & Driver Security' -Control 'Vulnerable Driver Protections' -Status 'WARN' -Severity 'Low' `
            -CurrentValue 'Query failed' -Recommendation "Unable to complete vulnerable driver protection audit: $($_.Exception.Message)"
    }
}

#endregion

#region ============================== 22. PERSISTENCE MECHANISMS & UNAUTHORIZED AUTO-RUNS ==============================

function Test-RegistryAutorunPersistence {
    <#
        Audits the registry ACL on the machine-wide Run/RunOnce autostart keys (a
        low-privilege write grant there lets ANY standard user plant an entry that executes
        for every user who logs on, including administrators), the Winlogon Shell/Userinit
        values against their expected exact defaults, and AppInit_DLLs - a legacy but still
        functional DLL-injection persistence mechanism.
    #>
    Write-SectionBanner 'Persistence - Registry Autorun Locations'
    try {
        $runKeys = @(
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
        )
        foreach ($key in $runKeys) {
            if (-not (Test-Path -LiteralPath $key)) { continue }
            $check = Test-LowPrivilegeWriteAccess -Path $key -ObjectType Registry
            $entries = @()
            try { $entries = @((Get-Item -LiteralPath $key -ErrorAction Stop).Property) } catch { $entries = @() }
            if ($check.IsVulnerable) {
                Add-AuditResult -Category 'Persistence & Post-Exploitation Vectors' -Control "Registry Autorun Key ACL - $key" -Status 'FAIL' -Severity 'Critical' `
                    -CurrentValue "Grants: $($check.Principals -join '; '); Current entries: $($entries -join ', ')" -RecommendedValue 'No low-privilege write grant' -CIS_Control 'CIS 4.8' `
                    -NIST_Control 'CM-7, AC-6' -MITRE_Technique 'T1547.001 (Registry Run Keys / Startup Folder)' -ISO27001_Control 'A.8.19' -NIS2_Article 'Art.21(2)(i)' `
                    -Recommendation "Remove the low-privilege write grant on `"$key`". Any standard user with write access here can plant a machine-wide autorun entry that executes at every user's logon, including administrators."
            } else {
                Add-AuditResult -Category 'Persistence & Post-Exploitation Vectors' -Control "Registry Autorun Key ACL - $key" -Status 'PASS' -Severity 'Critical' `
                    -CurrentValue "No low-privilege write grant; $($entries.Count) current entry/entries: $($entries -join ', ')" -RecommendedValue 'No low-privilege write grant' -CIS_Control 'CIS 4.8' `
                    -NIST_Control 'CM-7, AC-6' -MITRE_Technique 'T1547.001 (Registry Run Keys / Startup Folder)' -ISO27001_Control 'A.8.19' -NIS2_Article 'Art.21(2)(i)' `
                    -Recommendation 'No action required. Review the listed entries periodically for anything unrecognized.'
            }
        }

        $winlogonPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
        $shell = Get-RegistryValueSafe -Path $winlogonPath -Name 'Shell' -DefaultValue 'explorer.exe'
        $userinit = Get-RegistryValueSafe -Path $winlogonPath -Name 'Userinit' -DefaultValue 'C:\Windows\system32\userinit.exe,'

        if ([string]$shell -ieq 'explorer.exe') {
            Add-AuditResult -Category 'Persistence & Post-Exploitation Vectors' -Control 'Winlogon Shell Value' -Status 'PASS' -Severity 'Critical' `
                -CurrentValue $shell -RecommendedValue 'explorer.exe' -CIS_Control 'CIS 4.8' -NIST_Control 'CM-7' -MITRE_Technique 'T1547.004 (Winlogon Helper DLL)' `
                -ISO27001_Control 'A.8.19' -NIS2_Article 'Art.21(2)(i)' -Recommendation 'No action required.'
        } else {
            Add-AuditResult -Category 'Persistence & Post-Exploitation Vectors' -Control 'Winlogon Shell Value' -Status 'FAIL' -Severity 'Critical' `
                -CurrentValue $shell -RecommendedValue 'explorer.exe' -CIS_Control 'CIS 4.8' -NIST_Control 'CM-7' -MITRE_Technique 'T1547.004 (Winlogon Helper DLL)' `
                -ISO27001_Control 'A.8.19' -NIS2_Article 'Art.21(2)(i)' `
                -Recommendation "The Winlogon Shell value is `"$shell`" instead of the expected `"explorer.exe`". This is a classic persistence/hijack technique - Windows launches whatever is listed here at every interactive logon. Restore it to explorer.exe unless this is a deliberately locked-down kiosk configuration."
        }

        if ([string]$userinit -imatch '^C:\\Windows\\system32\\userinit\.exe,?\s*$') {
            Add-AuditResult -Category 'Persistence & Post-Exploitation Vectors' -Control 'Winlogon Userinit Value' -Status 'PASS' -Severity 'Critical' `
                -CurrentValue $userinit -RecommendedValue 'C:\Windows\system32\userinit.exe,' -CIS_Control 'CIS 4.8' -NIST_Control 'CM-7' -MITRE_Technique 'T1547.004 (Winlogon Helper DLL)' `
                -ISO27001_Control 'A.8.19' -NIS2_Article 'Art.21(2)(i)' -Recommendation 'No action required.'
        } else {
            Add-AuditResult -Category 'Persistence & Post-Exploitation Vectors' -Control 'Winlogon Userinit Value' -Status 'FAIL' -Severity 'Critical' `
                -CurrentValue $userinit -RecommendedValue 'C:\Windows\system32\userinit.exe,' -CIS_Control 'CIS 4.8' -NIST_Control 'CM-7' -MITRE_Technique 'T1547.004 (Winlogon Helper DLL)' `
                -ISO27001_Control 'A.8.19' -NIS2_Article 'Art.21(2)(i)' `
                -Recommendation "The Winlogon Userinit value is `"$userinit`" instead of the expected `"C:\Windows\system32\userinit.exe,`". Any additional appended executable here launches with the user's logon token - restore the default value unless a specific, documented reason exists for the addition."
        }

        $appInitPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows'
        $appInitDlls = Get-RegistryValueSafe -Path $appInitPath -Name 'AppInit_DLLs' -DefaultValue ''
        $loadAppInit = Get-RegistryValueSafe -Path $appInitPath -Name 'LoadAppInit_DLLs' -DefaultValue 0

        if ([string]::IsNullOrWhiteSpace($appInitDlls) -and [int]$loadAppInit -eq 0) {
            Add-AuditResult -Category 'Persistence & Post-Exploitation Vectors' -Control 'AppInit_DLLs Injection Mechanism' -Status 'PASS' -Severity 'High' `
                -CurrentValue 'Empty / Disabled' -RecommendedValue 'Empty / Disabled' -CIS_Control 'CIS 4.8' -NIST_Control 'CM-7, SI-7' `
                -MITRE_Technique 'T1546.010 (AppInit DLLs)' -ISO27001_Control 'A.8.19' -NIS2_Article 'Art.21(2)(i)' -Recommendation 'No action required.'
        } else {
            Add-AuditResult -Category 'Persistence & Post-Exploitation Vectors' -Control 'AppInit_DLLs Injection Mechanism' -Status 'FAIL' -Severity 'High' `
                -CurrentValue "AppInit_DLLs='$appInitDlls'; LoadAppInit_DLLs=$loadAppInit" -RecommendedValue 'Empty / Disabled' -CIS_Control 'CIS 4.8' -NIST_Control 'CM-7, SI-7' `
                -MITRE_Technique 'T1546.010 (AppInit DLLs)' -ISO27001_Control 'A.8.19' -NIS2_Article 'Art.21(2)(i)' `
                -Recommendation 'Clear the AppInit_DLLs value and set LoadAppInit_DLLs to 0, unless a specific, verified, legitimate product depends on it (rare on modern software - most vendors moved away from AppInit_DLLs after Windows 8 added Secure Boot/CIG conflicts). Every DLL listed here loads into EVERY user-mode process that links user32.dll.'
        }
    } catch {
        Add-AuditResult -Category 'Persistence & Post-Exploitation Vectors' -Control 'Registry Autorun Locations' -Status 'WARN' -Severity 'Low' `
            -CurrentValue 'Query failed' -Recommendation "Unable to complete registry autorun audit: $($_.Exception.Message)"
    }
}

function Test-IFEODebuggerHijacks {
    <#
        Enumerates Image File Execution Options subkeys with a "Debugger" value configured.
        IFEO Debugger redirection is a legitimate (if obscure) developer feature, but it is
        also the exact mechanism behind the classic "sticky keys" login-screen backdoor
        (redirecting sethc.exe to cmd.exe). Any accessibility-binary match is escalated to
        Critical; all others are surfaced for manual review since a small number of
        legitimate compatibility-shim Debugger entries can exist on developer workstations.
    #>
    Write-SectionBanner 'Persistence - IFEO Debugger Hijacks'
    try {
        $ifeoPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
        $accessibilityBinaries = @('sethc.exe', 'utilman.exe', 'osk.exe', 'magnify.exe', 'narrator.exe', 'displayswitch.exe')

        if (-not (Test-Path -LiteralPath $ifeoPath)) {
            Add-AuditResult -Category 'Persistence & Post-Exploitation Vectors' -Control 'IFEO Debugger Hijacks' -Status 'PASS' -Severity 'High' `
                -CurrentValue 'IFEO key not present' -RecommendedValue 'No unexpected Debugger values, especially on accessibility binaries' -CIS_Control 'CIS 4.8' `
                -NIST_Control 'CM-7, SI-7' -MITRE_Technique 'T1546.012 (Image File Execution Options Injection)' -ISO27001_Control 'A.8.19' -NIS2_Article 'Art.21(2)(i)' `
                -Recommendation 'No action required.'
            return
        }

        $accessibilityHijacks = [System.Collections.Generic.List[string]]::new()
        $otherDebuggers = [System.Collections.Generic.List[string]]::new()

        Get-ChildItem -LiteralPath $ifeoPath -ErrorAction SilentlyContinue | ForEach-Object {
            $imageName = $_.PSChildName
            $debuggerVal = $null
            try { $debuggerVal = (Get-ItemProperty -LiteralPath $_.PSPath -Name 'Debugger' -ErrorAction Stop).Debugger } catch { $debuggerVal = $null }
            if ([string]::IsNullOrWhiteSpace($debuggerVal)) { return }

            if ($accessibilityBinaries -contains $imageName.ToLower()) {
                $accessibilityHijacks.Add("$imageName -> Debugger=$debuggerVal")
            } else {
                $otherDebuggers.Add("$imageName -> Debugger=$debuggerVal")
            }
        }

        if ($accessibilityHijacks.Count -gt 0) {
            Add-AuditResult -Category 'Persistence & Post-Exploitation Vectors' -Control 'IFEO Accessibility Binary Hijack (Sticky Keys Backdoor)' -Status 'FAIL' -Severity 'Critical' `
                -CurrentValue ($accessibilityHijacks -join ' | ') -RecommendedValue 'No Debugger value on any accessibility binary' -CIS_Control 'CIS 4.8' -NIST_Control 'CM-7, SI-7' `
                -MITRE_Technique 'T1546.008 (Accessibility Features), T1546.012 (IFEO Injection)' -ISO27001_Control 'A.8.19' -NIS2_Article 'Art.21(2)(i)' `
                -NSA_Guidance 'NSA CSI: Mitigating Credential Theft' `
                -Recommendation 'This is the classic "sticky keys" pre-authentication backdoor: pressing the accessibility hotkey at the LOCK SCREEN launches the Debugger-redirected program with SYSTEM privileges, no login required. Remove the Debugger value under each listed IFEO subkey immediately: Remove-ItemProperty -Path "HKLM:\...\Image File Execution Options\<binary>" -Name Debugger.'
        }

        if ($otherDebuggers.Count -gt 0) {
            Add-AuditResult -Category 'Persistence & Post-Exploitation Vectors' -Control 'IFEO Debugger Values (Non-Accessibility)' -Status 'WARN' -Severity 'Medium' `
                -CurrentValue ($otherDebuggers -join ' | ') -RecommendedValue 'Only verified, legitimate compatibility-shim or developer-debugger entries' -CIS_Control 'CIS 4.8' `
                -NIST_Control 'CM-7, SI-7' -MITRE_Technique 'T1546.012 (Image File Execution Options Injection)' -ISO27001_Control 'A.8.19' -NIS2_Article 'Art.21(2)(i)' `
                -Recommendation 'Review each listed IFEO Debugger redirection - a small number can be legitimate (application compatibility shims, developer tools), but each one silently replaces the named program with the Debugger target whenever it is launched. Remove any that cannot be attributed to known, approved software.'
        }

        if ($accessibilityHijacks.Count -eq 0 -and $otherDebuggers.Count -eq 0) {
            Add-AuditResult -Category 'Persistence & Post-Exploitation Vectors' -Control 'IFEO Debugger Hijacks' -Status 'PASS' -Severity 'High' `
                -CurrentValue 'No Debugger values configured under IFEO' -RecommendedValue 'No unexpected Debugger values' -CIS_Control 'CIS 4.8' -NIST_Control 'CM-7, SI-7' `
                -MITRE_Technique 'T1546.012 (Image File Execution Options Injection)' -ISO27001_Control 'A.8.19' -NIS2_Article 'Art.21(2)(i)' -Recommendation 'No action required.'
        }
    } catch {
        Add-AuditResult -Category 'Persistence & Post-Exploitation Vectors' -Control 'IFEO Debugger Hijacks' -Status 'WARN' -Severity 'Low' `
            -CurrentValue 'Query failed' -Recommendation "Unable to enumerate IFEO Debugger values: $($_.Exception.Message)"
    }
}

function Test-AccessibilityBinaryIntegrity {
    <#
        Verifies the on-disk accessibility binaries (sethc.exe, utilman.exe, osk.exe,
        magnify.exe, narrator.exe) carry a valid Microsoft Authenticode signature. This
        directly detects the classic "replace utilman.exe with cmd.exe" backdoor, which
        yields a SYSTEM-context command prompt at the lock screen without IFEO involvement.
    #>
    Write-SectionBanner 'Persistence - Accessibility Binary File Integrity'
    $binaries = @('sethc.exe', 'utilman.exe', 'osk.exe', 'magnify.exe', 'narrator.exe')
    $tampered = [System.Collections.Generic.List[string]]::new()
    $checkedCount = 0

    foreach ($binName in $binaries) {
        try {
            $fullPath = Join-Path $env:WINDIR "System32\$binName"
            if (-not (Test-Path -LiteralPath $fullPath -ErrorAction SilentlyContinue)) { continue }
            $checkedCount++
            $sig = Get-AuthenticodeSignature -LiteralPath $fullPath -ErrorAction Stop
            $isMicrosoftSigned = ($sig.Status -eq 'Valid') -and ($sig.SignerCertificate -and $sig.SignerCertificate.Subject -match '(?i)Microsoft')
            if (-not $isMicrosoftSigned) {
                $tampered.Add("$binName [Status=$($sig.Status); Subject=$(if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { 'None' })]")
            }
        } catch {
            $tampered.Add("$binName [signature check failed]")
        }
    }

    if ($tampered.Count -eq 0) {
        Add-AuditResult -Category 'Persistence & Post-Exploitation Vectors' -Control 'Accessibility Binary File Integrity' -Status 'PASS' -Severity 'Critical' `
            -CurrentValue "$checkedCount binarie(s) checked; all validly Microsoft-signed" -RecommendedValue 'All accessibility binaries carry a valid Microsoft Authenticode signature' `
            -CIS_Control 'CIS 4.8' -NIST_Control 'SI-7, CM-7' -MITRE_Technique 'T1546.008 (Accessibility Features)' -ISO27001_Control 'A.8.19' -NIS2_Article 'Art.21(2)(i)' `
            -NSA_Guidance 'NSA CSI: Mitigating Credential Theft' -Recommendation 'No action required.'
    } else {
        Add-AuditResult -Category 'Persistence & Post-Exploitation Vectors' -Control 'Accessibility Binary File Integrity' -Status 'FAIL' -Severity 'Critical' `
            -CurrentValue ($tampered -join ' | ') -RecommendedValue 'All accessibility binaries carry a valid Microsoft Authenticode signature' -CIS_Control 'CIS 4.8' `
            -NIST_Control 'SI-7, CM-7' -MITRE_Technique 'T1546.008 (Accessibility Features)' -ISO27001_Control 'A.8.19' -NIS2_Article 'Art.21(2)(i)' `
            -NSA_Guidance 'NSA CSI: Mitigating Credential Theft' `
            -Recommendation 'One or more accessibility binaries is not validly Microsoft-signed - a strong indicator the file has been replaced (classic technique: copying cmd.exe over utilman.exe/sethc.exe to obtain a SYSTEM shell at the lock screen without authenticating). Restore the genuine file immediately via "sfc /scannow" or DISM, and treat this endpoint as potentially compromised pending investigation.'
    }
}

function Test-StartupFolderPermissions {
    <#
        Audits the ACL on the All-Users (common) Startup folder. Anything placed there
        launches for every interactive user who logs on - a low-privilege write grant is a
        machine-wide persistence vector equivalent in impact to a writable HKLM Run key.
    #>
    Write-SectionBanner 'Persistence - Common Startup Folder Permissions'
    try {
        $startupPath = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\StartUp'
        if (-not (Test-Path -LiteralPath $startupPath -PathType Container)) {
            Add-AuditResult -Category 'Persistence & Post-Exploitation Vectors' -Control 'Common Startup Folder ACL' -Status 'WARN' -Severity 'Low' `
                -CurrentValue 'Folder not found at expected path' -RecommendedValue 'No low-privilege write grant' -Recommendation 'Verify the common Startup folder location for this OS build/locale.'
            return
        }
        $check = Test-LowPrivilegeWriteAccess -Path $startupPath -ObjectType FileSystem
        $items = @(Get-ChildItem -LiteralPath $startupPath -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name)

        if ($check.IsVulnerable) {
            Add-AuditResult -Category 'Persistence & Post-Exploitation Vectors' -Control 'Common Startup Folder ACL' -Status 'FAIL' -Severity 'Critical' `
                -CurrentValue "Grants: $($check.Principals -join '; '); Current items: $($items -join ', ')" -RecommendedValue 'No low-privilege write grant' -CIS_Control 'CIS 4.8' `
                -NIST_Control 'CM-7, AC-6' -MITRE_Technique 'T1547.001 (Registry Run Keys / Startup Folder)' -ISO27001_Control 'A.8.19' -NIS2_Article 'Art.21(2)(i)' `
                -Recommendation "Remove the low-privilege write grant on `"$startupPath`". Any standard user with write access can drop a shortcut/script here that runs for every user who logs on to this machine, including administrators."
        } else {
            Add-AuditResult -Category 'Persistence & Post-Exploitation Vectors' -Control 'Common Startup Folder ACL' -Status 'PASS' -Severity 'Critical' `
                -CurrentValue "No low-privilege write grant; $($items.Count) current item(s): $($items -join ', ')" -RecommendedValue 'No low-privilege write grant' -CIS_Control 'CIS 4.8' `
                -NIST_Control 'CM-7, AC-6' -MITRE_Technique 'T1547.001 (Registry Run Keys / Startup Folder)' -ISO27001_Control 'A.8.19' -NIS2_Article 'Art.21(2)(i)' `
                -Recommendation 'No action required. Review the listed items periodically for anything unrecognized.'
        }
    } catch {
        Add-AuditResult -Category 'Persistence & Post-Exploitation Vectors' -Control 'Common Startup Folder ACL' -Status 'WARN' -Severity 'Low' `
            -CurrentValue 'Query failed' -Recommendation "Unable to audit the common Startup folder: $($_.Exception.Message)"
    }
}

function Test-WMIEventSubscriptionPersistence {
    <#
        Enumerates WMI permanent event subscriptions (__EventFilter, CommandLineEventConsumer,
        ActiveScriptEventConsumer, __FilterToConsumerBinding) under root\subscription. A
        clean Windows 11 install ships with none; any presence warrants manual review since
        this is a well-documented fileless persistence technique, though some legitimate
        management/AV agents do register their own subscriptions.
    #>
    Write-SectionBanner 'Persistence - WMI Event Subscription Persistence'
    try {
        $filters = @(Get-CimInstance -Namespace 'root\subscription' -ClassName '__EventFilter' -ErrorAction SilentlyContinue)
        $cmdConsumers = @(Get-CimInstance -Namespace 'root\subscription' -ClassName 'CommandLineEventConsumer' -ErrorAction SilentlyContinue)
        $scriptConsumers = @(Get-CimInstance -Namespace 'root\subscription' -ClassName 'ActiveScriptEventConsumer' -ErrorAction SilentlyContinue)
        $bindings = @(Get-CimInstance -Namespace 'root\subscription' -ClassName '__FilterToConsumerBinding' -ErrorAction SilentlyContinue)

        $totalCount = $filters.Count + $cmdConsumers.Count + $scriptConsumers.Count + $bindings.Count

        if ($totalCount -eq 0) {
            Add-AuditResult -Category 'Persistence & Post-Exploitation Vectors' -Control 'WMI Permanent Event Subscriptions' -Status 'PASS' -Severity 'High' `
                -CurrentValue 'No permanent WMI event filters, consumers, or bindings found' -RecommendedValue 'None present, unless attributable to known management/AV tooling' `
                -CIS_Control 'CIS 4.8' -NIST_Control 'CM-7, SI-7' -MITRE_Technique 'T1546.003 (Windows Management Instrumentation Event Subscription)' -ISO27001_Control 'A.8.19' `
                -NIS2_Article 'Art.21(2)(i)' -NSA_Guidance 'NSA/CISA Guidance on Endpoint Detection and Response' -Recommendation 'No action required.'
        } else {
            $consumerDetails = [System.Collections.Generic.List[string]]::new()
            foreach ($c in $cmdConsumers) { $consumerDetails.Add("CommandLineEventConsumer: $($c.Name) -> $($c.CommandLineTemplate)") }
            foreach ($c in $scriptConsumers) { $consumerDetails.Add("ActiveScriptEventConsumer: $($c.Name) -> [$($c.ScriptingEngine)] $($c.ScriptText)") }

            Add-AuditResult -Category 'Persistence & Post-Exploitation Vectors' -Control 'WMI Permanent Event Subscriptions' -Status 'WARN' -Severity 'High' `
                -CurrentValue "Filters=$($filters.Count); CommandLineConsumers=$($cmdConsumers.Count); ScriptConsumers=$($scriptConsumers.Count); Bindings=$($bindings.Count). Details: $($consumerDetails -join ' | ')" `
                -RecommendedValue 'None present, unless attributable to known management/AV tooling' -CIS_Control 'CIS 4.8' -NIST_Control 'CM-7, SI-7' `
                -MITRE_Technique 'T1546.003 (Windows Management Instrumentation Event Subscription)' -ISO27001_Control 'A.8.19' -NIS2_Article 'Art.21(2)(i)' `
                -NSA_Guidance 'NSA/CISA Guidance on Endpoint Detection and Response' `
                -Recommendation 'Review each listed subscription. Some enterprise management/AV agents legitimately use WMI event subscriptions, but this is also a well-documented fileless persistence technique (notably used by APT29/others) - verify the CommandLineTemplate/ScriptText content and consumer/filter names against known-good tooling before dismissing. Remove with Remove-CimInstance if illegitimate.'
        }
    } catch {
        Add-AuditResult -Category 'Persistence & Post-Exploitation Vectors' -Control 'WMI Permanent Event Subscriptions' -Status 'WARN' -Severity 'Low' `
            -CurrentValue 'Query failed' -Recommendation "Unable to enumerate WMI event subscriptions: $($_.Exception.Message)"
    }
}

#endregion

#region ============================== 23. ACTIVE EXPLOITATION & SECURITY SUBVERSION CONTROLS ==============================

function Test-EventLogChannelACLTampering {
    <#
        Audits the channelAccess SDDL string on core event log channels via wevtutil.exe.
        By default, only SYSTEM, built-in Administrators, and a small set of well-known
        service SIDs (Event Log Readers, Network Service, Local Service) appear in this
        SDDL - the presence of the Everyone (WD) or Authenticated Users (AU) SDDL tokens
        with a non-read access grant would allow a low-privileged user to clear or tamper
        with the log, defeating detection/forensics.
    #>
    Write-SectionBanner 'Active Exploitation - Event Log Channel ACL Tampering'
    $logsToCheck = @('Security', 'System', 'Application', 'Microsoft-Windows-PowerShell/Operational')
    foreach ($logName in $logsToCheck) {
        try {
            $glOutput = & wevtutil.exe gl "$logName" 2>$null
            if (-not $glOutput) { throw "wevtutil returned no output for $logName" }
            $accessLine = $glOutput | Where-Object { $_ -match '(?i)channelAccess:' } | Select-Object -First 1
            $sddl = if ($accessLine) { ($accessLine -split ':', 2)[1].Trim() } else { 'Unknown' }

            $hasSuspiciousGrant = $sddl -match ';;;WD\)' -or $sddl -match ';;;AU\)'

            if (-not $hasSuspiciousGrant) {
                Add-AuditResult -Category 'Persistence & Post-Exploitation Vectors' -Control "Event Log Channel ACL - $logName" -Status 'PASS' -Severity 'High' `
                    -CurrentValue 'No Everyone/Authenticated Users grant found in channel ACL' -RecommendedValue 'Default-restrictive channelAccess SDDL (no WD/AU tokens)' -CIS_Control 'CIS 8.3' `
                    -NIST_Control 'AU-9, AC-6' -MITRE_Technique 'T1070.001 (Clear Windows Event Logs)' -ISO27001_Control 'A.8.15' -NIS2_Article 'Art.21(2)(b)' `
                    -NSA_Guidance 'NSA/CISA Audit Logging Best Practices' -Recommendation 'No action required.'
            } else {
                Add-AuditResult -Category 'Persistence & Post-Exploitation Vectors' -Control "Event Log Channel ACL - $logName" -Status 'WARN' -Severity 'High' `
                    -CurrentValue "channelAccess SDDL: $sddl" -RecommendedValue 'Default-restrictive channelAccess SDDL (no WD/AU tokens)' -CIS_Control 'CIS 8.3' -NIST_Control 'AU-9, AC-6' `
                    -MITRE_Technique 'T1070.001 (Clear Windows Event Logs)' -ISO27001_Control 'A.8.15' -NIS2_Article 'Art.21(2)(b)' -NSA_Guidance 'NSA/CISA Audit Logging Best Practices' `
                    -Recommendation "The $logName channel ACL includes an Everyone (WD) or Authenticated Users (AU) token. Review the exact access mask granted (raw SDDL shown above) - restore the default SDDL via `"wevtutil sl $logName /ca:<default-SDDL>`" if this grant is broader than intended. A tamperable log channel undermines incident-response evidence integrity."
            }
        } catch {
            Add-AuditResult -Category 'Persistence & Post-Exploitation Vectors' -Control "Event Log Channel ACL - $logName" -Status 'WARN' -Severity 'Low' `
                -CurrentValue 'Query failed' -Recommendation "Unable to query channel ACL for ${logName}: $($_.Exception.Message)"
        }
    }
}

function Test-UACBypassIndicators {
    <#
        Checks for the HKCU registry paths used by well-documented UAC auto-elevation
        bypass techniques (fodhelper.exe / computerdefaults.exe via the ms-settings ProgID,
        eventvwr.exe via the mscfile ProgID, sdclt.exe via the exefile "runas" verb). These
        keys do not exist on a clean, unexploited system - their mere presence is a strong
        indicator of an active or attempted UAC bypass and is treated as a compromise
        indicator (IOC) rather than a routine hardening gap.
    #>
    Write-SectionBanner 'Active Exploitation - UAC Auto-Elevation Bypass Indicators'
    $bypassPaths = @(
        @{ Path = 'HKCU:\Software\Classes\ms-settings\Shell\Open\command';              Technique = 'fodhelper.exe / computerdefaults.exe (ms-settings ProgID hijack)' }
        @{ Path = 'HKCU:\Software\Classes\mscfile\shell\open\command';                  Technique = 'eventvwr.exe (mscfile ProgID hijack)' }
        @{ Path = 'HKCU:\Software\Classes\exefile\shell\runas\command';                 Technique = 'sdclt.exe (exefile runas verb hijack)' }
        @{ Path = 'HKCU:\Software\Classes\Folder\shell\open\command';                   Technique = 'sdclt.exe / explorer auto-elevate variant (Folder ProgID hijack)' }
    )

    $found = [System.Collections.Generic.List[string]]::new()
    foreach ($bp in $bypassPaths) {
        try {
            if (Test-Path -LiteralPath $bp.Path) {
                $cmdValue = $null
                try { $cmdValue = (Get-ItemProperty -LiteralPath $bp.Path -Name '(default)' -ErrorAction Stop).'(default)' } catch { $cmdValue = '(unreadable)' }
                $found.Add("$($bp.Path) [Technique: $($bp.Technique)] -> Command=$cmdValue")
            }
        } catch { }
    }

    if ($found.Count -eq 0) {
        Add-AuditResult -Category 'Persistence & Post-Exploitation Vectors' -Control 'UAC Auto-Elevation Bypass Indicators' -Status 'PASS' -Severity 'Critical' `
            -CurrentValue 'None of the known UAC-bypass hijack registry paths are present' -RecommendedValue 'None present' -CIS_Control 'CIS 5.4' -NIST_Control 'AC-6, SI-4' `
            -MITRE_Technique 'T1548.002 (Bypass User Account Control)' -ISO27001_Control 'A.8.2' -NIS2_Article 'Art.21(2)(i)' -NSA_Guidance 'NSA/CISA Guidance on Endpoint Detection and Response' `
            -Recommendation 'No action required. This check covers a curated, well-documented subset of auto-elevate UAC bypass techniques (fodhelper/computerdefaults/eventvwr/sdclt); it is not an exhaustive list of every known or future bypass primitive.'
    } else {
        Add-AuditResult -Category 'Persistence & Post-Exploitation Vectors' -Control 'UAC Auto-Elevation Bypass Indicators' -Status 'FAIL' -Severity 'Critical' `
            -CurrentValue ($found -join ' | ') -RecommendedValue 'None present' -CIS_Control 'CIS 5.4' -NIST_Control 'AC-6, SI-4' -MITRE_Technique 'T1548.002 (Bypass User Account Control)' `
            -ISO27001_Control 'A.8.2' -NIS2_Article 'Art.21(2)(i)' -NSA_Guidance 'NSA/CISA Guidance on Endpoint Detection and Response' `
            -Recommendation 'These registry keys do not exist on a clean, unexploited Windows install - treat this as an active compromise indicator, not a routine hardening gap. Isolate the endpoint pending investigation, capture the listed command value(s) for forensic analysis before remediating, then remove the offending key(s) and rotate credentials used on this device.'
    }
}

#endregion

#region ============================== APPLOCKER MODULE SHARED HELPERS ==============================

function Get-AppLockerPolicyXmlCache {
    <#
        Central accessor for the effective AppLocker policy as XML, cached so the AppLocker
        module's ten checks only invoke Get-AppLockerPolicy once. Returns $false (not $null)
        on failure so the falsy/cached distinction in the calling pattern stays unambiguous.
    #>
    if ($null -eq $Script:AppLockerXmlCache) {
        try {
            $xmlString = Get-AppLockerPolicy -Effective -Xml -ErrorAction Stop
            if ([string]::IsNullOrWhiteSpace($xmlString)) { throw 'Empty AppLocker policy XML' }
            $Script:AppLockerXmlCache = [xml]$xmlString
        } catch {
            $Script:AppLockerXmlCache = $false
        }
    }
    return $Script:AppLockerXmlCache
}

function Get-AppLockerRuleCollectionNode {
    <# Returns the RuleCollection XML node for a given collection Type ('Exe','Msi','Script','Dll','Appx'), or $null. #>
    param([Parameter(Mandatory = $true)]$Xml, [Parameter(Mandatory = $true)][string]$CollectionType)
    if (-not $Xml) { return $null }
    try { return $Xml.SelectSingleNode("//RuleCollection[@Type='$CollectionType']") } catch { return $null }
}

function Get-AppLockerBroadDefaultRuleFlags {
    <#
        Scans the Exe and Dll rule collections for the literal default-rule-set path
        conditions (%WINDIR%\* / %SYSTEM32%\* and %PROGRAMFILES%\*). Used to decide whether
        a writable-directory finding elsewhere on disk is confirmed to be reachable through
        an active AppLocker allow rule (Critical) versus a general risk with unconfirmed
        AppLocker coverage (High).
    #>
    param([Parameter(Mandatory = $true)]$Xml)
    $flags = [PSCustomObject]@{ HasBroadWindowsRule = $false; HasBroadProgramFilesRule = $false }
    if (-not $Xml) { return $flags }
    try {
        $pathConditions = @($Xml.SelectNodes("//RuleCollection[@Type='Exe' or @Type='Dll']/FilePathRule/Conditions/FilePathCondition"))
        foreach ($cond in $pathConditions) {
            $p = $cond.GetAttribute('Path')
            if ($p -match '(?i)^%WINDIR%\\?\*?$' -or $p -match '(?i)^%SYSTEM32%\\?\*?$') { $flags.HasBroadWindowsRule = $true }
            if ($p -match '(?i)^%PROGRAMFILES%\\?\*?$') { $flags.HasBroadProgramFilesRule = $true }
        }
    } catch { }
    return $flags
}

function Get-AppLockerDenyRuleBinaryNames {
    <#
        Collects the leaf binary names covered by any Deny-action rule (Path, Publisher, or
        Hash) across every AppLocker rule collection, used to determine whether a specific
        LOLBAS binary has been explicitly denied despite the broad default allow rules.
    #>
    param([Parameter(Mandatory = $true)]$Xml)
    $names = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    if (-not $Xml) { return $names }
    try {
        foreach ($c in @($Xml.SelectNodes("//FilePathRule[@Action='Deny']/Conditions/FilePathCondition"))) {
            $p = $c.GetAttribute('Path')
            if ($p) { [void]$names.Add((Split-Path $p -Leaf)) }
        }
        foreach ($c in @($Xml.SelectNodes("//FilePublisherRule[@Action='Deny']/Conditions/FilePublisherCondition"))) {
            $bn = $c.GetAttribute('BinaryName')
            if ($bn -and $bn -ne '*') { [void]$names.Add($bn) }
        }
        foreach ($c in @($Xml.SelectNodes("//FileHashRule[@Action='Deny']/Conditions/FileHashCondition/FileHash"))) {
            $sf = $c.GetAttribute('SourceFileName')
            if ($sf) { [void]$names.Add($sf) }
        }
    } catch { }
    return $names
}

#endregion

#region ============================== 24. APPLOCKER ACL & BYPASS VULNERABILITY AUDIT ==============================

function Test-AppLockerEnforcementModeDeep {
    <#
        Audits enforcement mode across all five AppLocker rule collections. DLL rules are
        deliberately treated as WARN rather than FAIL when unconfigured: enabling them has
        real performance/compatibility overhead, so leaving them off is a common, defensible
        posture rather than an outright misconfiguration - but it is still flagged, since
        unmanaged DLL loading is a documented AppLocker bypass path.
    #>
    Write-SectionBanner 'AppLocker - Rule Collection Enforcement Mode (Deep)'
    try {
        $xml = Get-AppLockerPolicyXmlCache
        if (-not $xml) {
            Add-AuditResult -Category 'AppLocker - Policy & Enforcement Mode' -Control 'AppLocker Effective Policy Availability' -Status 'INFO' -Severity 'Informational' `
                -CurrentValue 'AppLocker unavailable (requires Windows 11 Enterprise/Education with an effective policy applied)' -RecommendedValue 'AppLocker configured on Enterprise/Education editions' `
                -Recommendation 'AppLocker requires Windows 11 Enterprise or Education. On Pro/Home editions, Windows Defender Application Control (WDAC) is the equivalent control and is audited separately in this report.'
            return
        }

        $collections = @(
            @{ Type = 'Exe';    Label = 'Executable Rules (EXE)' }
            @{ Type = 'Msi';    Label = 'Windows Installer Rules (MSI)' }
            @{ Type = 'Script'; Label = 'Script Rules (PS1/BAT/CMD/VBS/JS)' }
            @{ Type = 'Appx';   Label = 'Packaged App Rules (AppX)' }
            @{ Type = 'Dll';    Label = 'DLL Rules' }
        )

        foreach ($c in $collections) {
            $node = Get-AppLockerRuleCollectionNode -Xml $xml -CollectionType $c.Type
            $mode = if ($node) { $node.EnforcementMode } else { $null }
            if ([string]::IsNullOrWhiteSpace($mode)) { $mode = 'NotConfigured' }

            if ($mode -eq 'Enabled') {
                Add-AuditResult -Category 'AppLocker - Policy & Enforcement Mode' -Control "AppLocker Enforcement - $($c.Label)" -Status 'PASS' -Severity 'High' `
                    -CurrentValue 'Enabled' -RecommendedValue 'Enabled' -CIS_Control 'CIS 2.5' -NIST_Control 'CM-7' -MITRE_Technique 'T1218 (System Binary Proxy Execution)' `
                    -ISO27001_Control 'A.8.19' -NIS2_Article 'Art.21(2)(e)' -NSA_Guidance 'NSA/CISA Application Allowlisting Guidance' -Recommendation 'No action required.'
            } elseif ($mode -eq 'AuditOnly') {
                Add-AuditResult -Category 'AppLocker - Policy & Enforcement Mode' -Control "AppLocker Enforcement - $($c.Label)" -Status 'WARN' -Severity 'Medium' `
                    -CurrentValue 'Audit Only' -RecommendedValue 'Enabled' -CIS_Control 'CIS 2.5' -NIST_Control 'CM-7' -MITRE_Technique 'T1218 (System Binary Proxy Execution)' `
                    -ISO27001_Control 'A.8.19' -NIS2_Article 'Art.21(2)(e)' -NSA_Guidance 'NSA/CISA Application Allowlisting Guidance' `
                    -Recommendation "Review AppLocker audit events (Event ID 8003/8006/8007) for the $($c.Label) collection to identify false positives, then promote enforcement from Audit Only to Enabled - Audit Only mode logs but does not block unauthorized execution."
            } elseif ($c.Type -eq 'Dll') {
                Add-AuditResult -Category 'AppLocker - Policy & Enforcement Mode' -Control "AppLocker Enforcement - $($c.Label)" -Status 'WARN' -Severity 'High' `
                    -CurrentValue 'Not Configured' -RecommendedValue 'Enabled (pilot for compatibility/performance impact first)' -CIS_Control 'CIS 2.5' -NIST_Control 'CM-7' `
                    -MITRE_Technique 'T1574 (Hijack Execution Flow)' -ISO27001_Control 'A.8.19' -NIS2_Article 'Art.21(2)(e)' -NSA_Guidance 'NSA/CISA Application Allowlisting Guidance' `
                    -Recommendation 'DLL rules are disabled - unmanaged DLL loading (e.g. via rundll32.exe or a hijacked search-order load) bypasses EXE-level AppLocker enforcement entirely, since only the initial process launch is checked. Pilot DLL rules on a representative device group before enterprise-wide rollout given their performance/compatibility overhead, but treat this as a meaningful residual gap in the interim.'
            } else {
                Add-AuditResult -Category 'AppLocker - Policy & Enforcement Mode' -Control "AppLocker Enforcement - $($c.Label)" -Status 'FAIL' -Severity 'High' `
                    -CurrentValue 'Not Configured' -RecommendedValue 'Enabled' -CIS_Control 'CIS 2.5' -NIST_Control 'CM-7' -MITRE_Technique 'T1218 (System Binary Proxy Execution)' `
                    -ISO27001_Control 'A.8.19' -NIS2_Article 'Art.21(2)(e)' -NSA_Guidance 'NSA/CISA Application Allowlisting Guidance' `
                    -Recommendation "Define and enable rules for the $($c.Label) collection via Local Security Policy > Application Control Policies > AppLocker, or centrally via GPO/Intune Endpoint Security policy."
            }
        }
    } catch {
        Add-AuditResult -Category 'AppLocker - Policy & Enforcement Mode' -Control 'AppLocker Enforcement Mode (Deep)' -Status 'WARN' -Severity 'Low' `
            -CurrentValue 'Query failed' -Recommendation "Unable to complete deep AppLocker enforcement audit: $($_.Exception.Message)"
    }
}

function Test-AppLockerRuleScopeCoverage {
    <#
        Reports the balance between rules scoped to Everyone/Authenticated Users (the
        built-in default rule set's normal, expected scope) versus rules scoped to a
        specific restricted group. Broad-only scoping is common and not itself a defect,
        but its complete absence of any group-restricted rule is a maturity signal worth
        surfacing rather than a hard failure.
    #>
    Write-SectionBanner 'AppLocker - Rule Scope Coverage'
    try {
        $xml = Get-AppLockerPolicyXmlCache
        if (-not $xml) {
            Add-AuditResult -Category 'AppLocker - Policy & Enforcement Mode' -Control 'AppLocker Rule Scope Coverage' -Status 'INFO' -Severity 'Informational' `
                -CurrentValue 'AppLocker unavailable' -Recommendation 'No effective AppLocker policy to evaluate.'
            return
        }
        $allRuleNodes = @($xml.SelectNodes('//FilePathRule')) + @($xml.SelectNodes('//FilePublisherRule')) + @($xml.SelectNodes('//FileHashRule'))
        if ($allRuleNodes.Count -eq 0) {
            Add-AuditResult -Category 'AppLocker - Policy & Enforcement Mode' -Control 'AppLocker Rule Scope Coverage' -Status 'INFO' -Severity 'Informational' `
                -CurrentValue 'No rules defined in the effective policy' -Recommendation 'Define AppLocker rules (at minimum the built-in default rule set) before this control is meaningful.'
            return
        }
        $broadScoped = @($allRuleNodes | Where-Object { $_.GetAttribute('UserOrGroupSid') -in @('S-1-1-0', 'S-1-5-11') })
        $restrictedScoped = @($allRuleNodes | Where-Object { $_.GetAttribute('UserOrGroupSid') -notin @('S-1-1-0', 'S-1-5-11') })

        if ($restrictedScoped.Count -gt 0) {
            Add-AuditResult -Category 'AppLocker - Policy & Enforcement Mode' -Control 'AppLocker Rule Scope Coverage' -Status 'PASS' -Severity 'Low' `
                -CurrentValue "$($allRuleNodes.Count) total rule(s): $($broadScoped.Count) scoped to Everyone/Authenticated Users, $($restrictedScoped.Count) scoped to a restricted group" `
                -RecommendedValue 'A mix of broad default-allow rules and restricted-group-scoped rules for sensitive applications' -CIS_Control 'CIS 2.5' -NIST_Control 'CM-7, AC-6' `
                -ISO27001_Control 'A.8.19' -NIS2_Article 'Art.21(2)(e)' -Recommendation 'No action required.'
        } else {
            Add-AuditResult -Category 'AppLocker - Policy & Enforcement Mode' -Control 'AppLocker Rule Scope Coverage' -Status 'WARN' -Severity 'Low' `
                -CurrentValue "All $($allRuleNodes.Count) rule(s) are scoped to Everyone/Authenticated Users; none target a restricted group" `
                -RecommendedValue 'A mix of broad default-allow rules and restricted-group-scoped rules for sensitive applications' -CIS_Control 'CIS 2.5' -NIST_Control 'CM-7, AC-6' `
                -ISO27001_Control 'A.8.19' -NIS2_Article 'Art.21(2)(e)' `
                -Recommendation 'Every rule in the effective policy is scoped to Everyone/Authenticated Users. This is normal for the built-in default rule set alone, but a mature deployment typically layers additional rules restricted to specific groups (e.g. a Developers group permitted to run compilers, denied to everyone else) rather than relying solely on broad default-allow breadth.'
        }
    } catch {
        Add-AuditResult -Category 'AppLocker - Policy & Enforcement Mode' -Control 'AppLocker Rule Scope Coverage' -Status 'WARN' -Severity 'Low' `
            -CurrentValue 'Query failed' -Recommendation "Unable to complete rule scope coverage audit: $($_.Exception.Message)"
    }
}

function Test-AppLockerWritableSystemDirectories {
    <#
        Deep ACL scan of historically-vulnerable, frequently-writable subdirectories inside
        the Windows tree that AppLocker's default %WINDIR%\* allow rule implicitly trusts.
        Severity is escalated to Critical only when a broad %WINDIR%\*-style allow rule is
        confirmed present in the effective policy (i.e. the writable directory is genuinely
        reachable through active AppLocker trust), and held at High otherwise.
    #>
    Write-SectionBanner 'AppLocker - Writable Directories Within Default-Allowed Windows Paths'
    try {
        $xml = Get-AppLockerPolicyXmlCache
        $flags = Get-AppLockerBroadDefaultRuleFlags -Xml $xml

        $windowsDirs = @(
            (Join-Path $env:WINDIR 'Tasks')
            (Join-Path $env:WINDIR 'Temp')
            (Join-Path $env:WINDIR 'tracing')
            (Join-Path $env:WINDIR 'Registration\CRMLog')
            (Join-Path $env:WINDIR 'System32\Tasks')
            (Join-Path $env:WINDIR 'System32\Microsoft\Crypto\RSA\MachineKeys')
        ) | Select-Object -Unique

        $anyChecked = $false
        foreach ($dir in $windowsDirs) {
            if (-not (Test-Path -LiteralPath $dir -PathType Container -ErrorAction SilentlyContinue)) { continue }
            $anyChecked = $true
            $check = Test-LowPrivilegeWriteAccess -Path $dir -ObjectType FileSystem
            if ($check.IsVulnerable) {
                $severity = if ($flags.HasBroadWindowsRule) { 'Critical' } else { 'High' }
                $coverageNote = if ($flags.HasBroadWindowsRule) { 'covered by an active AppLocker %WINDIR%\* allow rule' } else { 'AppLocker does not have a confirmed broad %WINDIR%\* allow rule, but this remains a general code-execution risk' }
                Add-AuditResult -Category 'AppLocker - ACL Writable Path Vulnerabilities' -Control "Writable Directory Within Default-Allowed Windows Path - $dir" -Status 'FAIL' -Severity $severity `
                    -CurrentValue "Grants: $($check.Principals -join '; '); $coverageNote" -RecommendedValue 'No low-privilege write grant' -CIS_Control 'CIS 4.8' -NIST_Control 'CM-7, AC-6' `
                    -MITRE_Technique 'T1574 (Hijack Execution Flow), T1218 (System Binary Proxy Execution)' -ISO27001_Control 'A.8.19' -NIS2_Article 'Art.21(2)(e)' `
                    -NSA_Guidance 'NSA/CISA Application Allowlisting Guidance' `
                    -Recommendation "Tighten the ACL on `"$dir`" (icacls `"$dir`" /remove:g `"Everyone`" `"Authenticated Users`" `"Users`") or add an explicit AppLocker Deny path rule scoped to this directory. A standard user can drop and execute an arbitrary binary here, which AppLocker's default %WINDIR%\* allow rule will not block."
            } else {
                Add-AuditResult -Category 'AppLocker - ACL Writable Path Vulnerabilities' -Control "Writable Directory Within Default-Allowed Windows Path - $dir" -Status 'PASS' -Severity 'High' `
                    -CurrentValue 'No low-privilege write grant' -RecommendedValue 'No low-privilege write grant' -CIS_Control 'CIS 4.8' -NIST_Control 'CM-7, AC-6' -ISO27001_Control 'A.8.19' `
                    -NIS2_Article 'Art.21(2)(e)' -Recommendation 'No action required.'
            }
        }
        if (-not $anyChecked) {
            Add-AuditResult -Category 'AppLocker - ACL Writable Path Vulnerabilities' -Control 'Writable Directories Within Default-Allowed Windows Paths' -Status 'INFO' -Severity 'Informational' `
                -CurrentValue 'None of the curated high-risk directories were found on this system' -Recommendation 'No action required.'
        }
    } catch {
        Add-AuditResult -Category 'AppLocker - ACL Writable Path Vulnerabilities' -Control 'Writable Directories Within Default-Allowed Windows Paths' -Status 'WARN' -Severity 'Low' `
            -CurrentValue 'Query failed' -Recommendation "Unable to complete writable-directory ACL audit: $($_.Exception.Message)"
    }
}

function Test-AppLockerDotNetFrameworkWritablePaths {
    <#
        Audits every installed .NET Framework version directory (Framework and Framework64)
        for low-privilege write access. These directories host csc.exe, msbuild.exe,
        installutil.exe, and regasm.exe - Microsoft-signed compilers/execution proxies that
        AppLocker's default path rules trust implicitly - so write access here is a direct
        path to planting a trojan alongside genuinely trusted tooling.
    #>
    Write-SectionBanner 'AppLocker - .NET Framework Directory Writable-Path Audit'
    try {
        $xml = Get-AppLockerPolicyXmlCache
        $flags = Get-AppLockerBroadDefaultRuleFlags -Xml $xml

        $frameworkRoots = @(
            (Join-Path $env:WINDIR 'Microsoft.NET\Framework')
            (Join-Path $env:WINDIR 'Microsoft.NET\Framework64')
        )
        $anyChecked = $false
        $anyVulnerable = $false
        foreach ($root in $frameworkRoots) {
            if (-not (Test-Path -LiteralPath $root -PathType Container -ErrorAction SilentlyContinue)) { continue }
            $versionDirs = Get-ChildItem -LiteralPath $root -Directory -Filter 'v*' -ErrorAction SilentlyContinue
            foreach ($vDir in $versionDirs) {
                $anyChecked = $true
                $check = Test-LowPrivilegeWriteAccess -Path $vDir.FullName -ObjectType FileSystem
                if ($check.IsVulnerable) {
                    $anyVulnerable = $true
                    $severity = if ($flags.HasBroadWindowsRule) { 'Critical' } else { 'High' }
                    Add-AuditResult -Category 'AppLocker - ACL Writable Path Vulnerabilities' -Control "Writable .NET Framework Directory - $($vDir.FullName)" -Status 'FAIL' -Severity $severity `
                        -CurrentValue "Grants: $($check.Principals -join '; ')" -RecommendedValue 'No low-privilege write grant' -CIS_Control 'CIS 4.8' -NIST_Control 'CM-7, AC-6' `
                        -MITRE_Technique 'T1127 (Trusted Developer Utilities Proxy Execution), T1218 (System Binary Proxy Execution)' -ISO27001_Control 'A.8.19' -NIS2_Article 'Art.21(2)(e)' `
                        -NSA_Guidance 'NSA/CISA Application Allowlisting Guidance' `
                        -Recommendation "Tighten the ACL on `"$($vDir.FullName)`". This directory hosts csc.exe/msbuild.exe/installutil.exe/regasm.exe - all Microsoft-signed and AppLocker-trusted-by-default. Write access here lets an attacker plant a trojan alongside them for a direct AppLocker bypass."
                }
            }
        }
        if ($anyChecked -and -not $anyVulnerable) {
            Add-AuditResult -Category 'AppLocker - ACL Writable Path Vulnerabilities' -Control '.NET Framework Directory Permissions' -Status 'PASS' -Severity 'High' `
                -CurrentValue 'No .NET Framework version directory is writable by a low-privilege principal' -RecommendedValue 'No low-privilege write grant' -CIS_Control 'CIS 4.8' `
                -NIST_Control 'CM-7, AC-6' -ISO27001_Control 'A.8.19' -NIS2_Article 'Art.21(2)(e)' -Recommendation 'No action required.'
        } elseif (-not $anyChecked) {
            Add-AuditResult -Category 'AppLocker - ACL Writable Path Vulnerabilities' -Control '.NET Framework Directory Permissions' -Status 'INFO' -Severity 'Informational' `
                -CurrentValue 'No .NET Framework installation found under Microsoft.NET' -Recommendation 'No action required.'
        }
    } catch {
        Add-AuditResult -Category 'AppLocker - ACL Writable Path Vulnerabilities' -Control '.NET Framework Directory Permissions' -Status 'WARN' -Severity 'Low' `
            -CurrentValue 'Query failed' -Recommendation "Unable to complete .NET Framework directory ACL audit: $($_.Exception.Message)"
    }
}

function Test-AppLockerPathRuleOverPermissiveness {
    <#
        Parses every FilePathCondition in the effective policy for two breadth signals: a
        rule permitting an entire drive root (e.g. C:\*, %OSDRIVE%\*), and custom
        (non-default-macro) path rules whose target directory is itself writable by a
        low-privileged principal - covering both the "overly permissive custom paths" and
        "secondary drive/root path" vectors from the same rule inventory pass.
    #>
    Write-SectionBanner 'AppLocker - Overly Permissive Path Rules'
    try {
        $xml = Get-AppLockerPolicyXmlCache
        if (-not $xml) {
            Add-AuditResult -Category 'AppLocker - ACL Writable Path Vulnerabilities' -Control 'Overly Permissive AppLocker Path Rules' -Status 'INFO' -Severity 'Informational' `
                -CurrentValue 'AppLocker unavailable' -Recommendation 'No effective AppLocker policy to evaluate.'
            return
        }
        $pathConditions = @($xml.SelectNodes('//FilePathCondition'))
        $dangerousPatterns = '^\*$|^[A-Za-z]:\\\*$|^%OSDRIVE%\\\*$|^%HOMEDRIVE%\\\*$'
        $flagged = [System.Collections.Generic.List[string]]::new()
        $customPathVulnerable = [System.Collections.Generic.List[string]]::new()

        foreach ($cond in $pathConditions) {
            $p = $cond.GetAttribute('Path')
            if ([string]::IsNullOrWhiteSpace($p)) { continue }
            if ($p -match $dangerousPatterns) {
                $flagged.Add($p)
                continue
            }
            if ($p -notmatch '(?i)^%(WINDIR|PROGRAMFILES|PROGRAMFILES\(X86\)|SYSTEM32|OSDRIVE)%') {
                $resolved = [Environment]::ExpandEnvironmentVariables(($p -replace '(?i)%OSDRIVE%', $env:SystemDrive) -replace '\\\*$', '')
                if ($resolved -and (Test-Path -LiteralPath $resolved -PathType Container -ErrorAction SilentlyContinue)) {
                    $check = Test-LowPrivilegeWriteAccess -Path $resolved -ObjectType FileSystem
                    if ($check.IsVulnerable) {
                        $customPathVulnerable.Add("$p -> $resolved [$($check.Principals -join '; ')]")
                    }
                }
            }
        }

        if ($flagged.Count -eq 0) {
            Add-AuditResult -Category 'AppLocker - ACL Writable Path Vulnerabilities' -Control 'Overly Permissive AppLocker Path Rules' -Status 'PASS' -Severity 'High' `
                -CurrentValue 'No rule permits an entire drive root (e.g. C:\*, %OSDRIVE%\*)' -RecommendedValue 'No drive-root-level wildcard path rules' -CIS_Control 'CIS 2.5' `
                -NIST_Control 'CM-7, AC-6' -MITRE_Technique 'T1574 (Hijack Execution Flow)' -ISO27001_Control 'A.8.19' -NIS2_Article 'Art.21(2)(e)' -Recommendation 'No action required.'
        } else {
            Add-AuditResult -Category 'AppLocker - ACL Writable Path Vulnerabilities' -Control 'Overly Permissive AppLocker Path Rules' -Status 'FAIL' -Severity 'Critical' `
                -CurrentValue "Drive-root-level wildcard rule(s) found: $($flagged -join ', ')" -RecommendedValue 'No drive-root-level wildcard path rules' -CIS_Control 'CIS 2.5' -NIST_Control 'CM-7, AC-6' `
                -MITRE_Technique 'T1574 (Hijack Execution Flow)' -ISO27001_Control 'A.8.19' -NIS2_Article 'Art.21(2)(e)' -NSA_Guidance 'NSA/CISA Application Allowlisting Guidance' `
                -Recommendation 'A path rule permitting an entire drive root (e.g. C:\* or %OSDRIVE%\*) allows execution from any user-writable location on that drive, including Downloads and Desktop - effectively nullifying AppLocker enforcement. Replace with narrower Publisher or Hash rules, or scope the path rule to a specific, non-writable subdirectory.'
        }

        if ($customPathVulnerable.Count -gt 0) {
            Add-AuditResult -Category 'AppLocker - ACL Writable Path Vulnerabilities' -Control 'Custom AppLocker Path Rule Targeting a Writable Directory' -Status 'FAIL' -Severity 'Critical' `
                -CurrentValue ($customPathVulnerable -join ' | ') -RecommendedValue 'Custom path rules should target directories not writable by standard users' -CIS_Control 'CIS 2.5' `
                -NIST_Control 'CM-7, AC-6' -MITRE_Technique 'T1574 (Hijack Execution Flow)' -ISO27001_Control 'A.8.19' -NIS2_Article 'Art.21(2)(e)' -NSA_Guidance 'NSA/CISA Application Allowlisting Guidance' `
                -Recommendation 'One or more custom AppLocker path rules (e.g. targeting a secondary drive or a custom tools folder such as C:\Tools\*) resolves to a directory writable by standard users. Tighten the directory ACL, or replace the path rule with a Publisher/Hash rule so trust is bound to the binary itself rather than an easily-poisoned location.'
        } else {
            Add-AuditResult -Category 'AppLocker - ACL Writable Path Vulnerabilities' -Control 'Custom AppLocker Path Rule Targeting a Writable Directory' -Status 'PASS' -Severity 'High' `
                -CurrentValue 'No custom path rule resolves to a low-privilege-writable directory' -RecommendedValue 'Custom path rules should target directories not writable by standard users' -CIS_Control 'CIS 2.5' `
                -NIST_Control 'CM-7, AC-6' -ISO27001_Control 'A.8.19' -NIS2_Article 'Art.21(2)(e)' -Recommendation 'No action required.'
        }
    } catch {
        Add-AuditResult -Category 'AppLocker - ACL Writable Path Vulnerabilities' -Control 'Overly Permissive AppLocker Path Rules' -Status 'WARN' -Severity 'Low' `
            -CurrentValue 'Query failed' -Recommendation "Unable to complete path rule over-permissiveness audit: $($_.Exception.Message)"
    }
}

function Test-AppLockerLOLBASExposure {
    <#
        Cross-references a curated list of well-documented AppLocker/WDAC bypass binaries
        (LOLBAS) against the effective policy's Deny rules. "Presence" of these binaries is
        expected and non-actionable (they ship with Windows/.NET and cannot be removed
        without breaking the OS) - the actionable signal is whether each one has been
        explicitly Denied, since AppLocker's default %WINDIR%\*-style allow rules implicitly
        permit all of them otherwise.
    #>
    Write-SectionBanner 'AppLocker - LOLBAS Execution Bypass Exposure'
    try {
        $xml = Get-AppLockerPolicyXmlCache
        $denyNames = Get-AppLockerDenyRuleBinaryNames -Xml $xml

        $exeCollection = if ($xml) { Get-AppLockerRuleCollectionNode -Xml $xml -CollectionType 'Exe' } else { $null }
        $exeMode = if ($exeCollection) { $exeCollection.EnforcementMode } else { $null }
        $appLockerActive = ($exeMode -eq 'Enabled') -or ($exeMode -eq 'AuditOnly')

        $directCandidates = [ordered]@{
            'wmic.exe'             = @('System32\wbem\WMIC.exe')
            'mshta.exe'            = @('System32\mshta.exe')
            'cscript.exe'          = @('System32\cscript.exe')
            'wscript.exe'          = @('System32\wscript.exe')
            'rundll32.exe'         = @('System32\rundll32.exe')
            'regsvr32.exe'         = @('System32\regsvr32.exe')
            'cmstp.exe'            = @('System32\cmstp.exe')
            'msiexec.exe'          = @('System32\msiexec.exe')
            'hh.exe'               = @('hh.exe', 'System32\hh.exe')
            'schtasks.exe'         = @('System32\schtasks.exe')
            'presentationhost.exe' = @('System32\PresentationHost.exe', 'SysWOW64\PresentationHost.exe')
        }
        $netFrameworkBinaries = @('csc.exe', 'vbc.exe', 'installutil.exe', 'regasm.exe', 'regsvcs.exe', 'msbuild.exe', 'dfsvc.exe', 'ieexec.exe')
        $netFrameworkDirs = @('Microsoft.NET\Framework64\v4.0.30319', 'Microsoft.NET\Framework\v4.0.30319', 'Microsoft.NET\Framework64\v2.0.50727', 'Microsoft.NET\Framework\v2.0.50727')

        $severityMap = @{
            'csc.exe' = 'High'; 'vbc.exe' = 'High'; 'installutil.exe' = 'High'; 'regasm.exe' = 'High'; 'regsvcs.exe' = 'High'; 'dfsvc.exe' = 'Medium'; 'msbuild.exe' = 'High'
            'wmic.exe' = 'High'; 'mshta.exe' = 'High'; 'cscript.exe' = 'High'; 'wscript.exe' = 'High'; 'rundll32.exe' = 'High'; 'regsvr32.exe' = 'High'; 'cmstp.exe' = 'High'; 'msiexec.exe' = 'Medium'
            'hh.exe' = 'Medium'; 'ieexec.exe' = 'Medium'; 'presentationhost.exe' = 'Medium'; 'schtasks.exe' = 'Medium'
        }
        $mitreMap = @{
            'csc.exe' = 'T1127.001 (MSBuild)'; 'vbc.exe' = 'T1127 (Trusted Developer Utilities Proxy Execution)'; 'installutil.exe' = 'T1218.004 (InstallUtil)'
            'regasm.exe' = 'T1218.009 (Regsvcs/Regasm)'; 'regsvcs.exe' = 'T1218.009 (Regsvcs/Regasm)'; 'dfsvc.exe' = 'T1127 (Trusted Developer Utilities Proxy Execution)'
            'msbuild.exe' = 'T1127.001 (MSBuild)'; 'wmic.exe' = 'T1047 (Windows Management Instrumentation)'; 'mshta.exe' = 'T1218.005 (Mshta)'; 'cscript.exe' = 'T1059.005 (Visual Basic)'
            'wscript.exe' = 'T1059.005 (Visual Basic)'; 'rundll32.exe' = 'T1218.011 (Rundll32)'; 'regsvr32.exe' = 'T1218.010 (Regsvr32)'; 'cmstp.exe' = 'T1218.003 (CMSTP)'
            'msiexec.exe' = 'T1218.007 (Msiexec)'; 'hh.exe' = 'T1218 (System Binary Proxy Execution)'; 'ieexec.exe' = 'T1218 (System Binary Proxy Execution)'
            'presentationhost.exe' = 'T1218 (System Binary Proxy Execution)'; 'schtasks.exe' = 'T1053.005 (Scheduled Task)'
        }

        $foundAny = $false
        $allBinaryEntries = [System.Collections.Generic.List[hashtable]]::new()
        foreach ($binName in $directCandidates.Keys) {
            foreach ($cand in $directCandidates[$binName]) {
                $full = Join-Path $env:WINDIR $cand
                if (Test-Path -LiteralPath $full -PathType Leaf -ErrorAction SilentlyContinue) {
                    $allBinaryEntries.Add(@{ Name = $binName; Path = $full }); break
                }
            }
        }
        foreach ($binName in $netFrameworkBinaries) {
            foreach ($dirRel in $netFrameworkDirs) {
                $full = Join-Path $env:WINDIR (Join-Path $dirRel $binName)
                if (Test-Path -LiteralPath $full -PathType Leaf -ErrorAction SilentlyContinue) {
                    $allBinaryEntries.Add(@{ Name = $binName; Path = $full }); break
                }
            }
        }

        foreach ($entry in $allBinaryEntries) {
            $binName = $entry.Name
            $foundPath = $entry.Path
            $foundAny = $true
            $isDenied = $denyNames.Contains($binName)
            $severity = $severityMap[$binName]
            $mitre = $mitreMap[$binName]

            if (-not $appLockerActive) {
                Add-AuditResult -Category 'AppLocker - LOLBAS & Execution Bypass Vectors' -Control "LOLBAS Exposure - $binName" -Status 'INFO' -Severity 'Informational' `
                    -CurrentValue "Present at $foundPath; AppLocker Exe collection is not currently enforcing/auditing" -RecommendedValue 'Explicit Deny rule once AppLocker enforcement is active' `
                    -CIS_Control 'CIS 2.5' -NIST_Control 'CM-7' -MITRE_Technique $mitre -ISO27001_Control 'A.8.19' -NIS2_Article 'Art.21(2)(e)' `
                    -Recommendation 'AppLocker Exe rules are not enforced/audited on this endpoint, so this LOLBIN''s AppLocker exposure is not yet applicable - see the enforcement-mode finding for the primary gap to close first.'
            } elseif ($isDenied) {
                Add-AuditResult -Category 'AppLocker - LOLBAS & Execution Bypass Vectors' -Control "LOLBAS Exposure - $binName" -Status 'PASS' -Severity $severity `
                    -CurrentValue "Present at $foundPath; explicit AppLocker Deny rule found" -RecommendedValue 'Explicit Deny rule (or restricted to a justified group)' -CIS_Control 'CIS 2.5' `
                    -NIST_Control 'CM-7' -MITRE_Technique $mitre -ISO27001_Control 'A.8.19' -NIS2_Article 'Art.21(2)(e)' -NSA_Guidance 'NSA/CISA Application Allowlisting Guidance' `
                    -Recommendation 'No action required.'
            } else {
                Add-AuditResult -Category 'AppLocker - LOLBAS & Execution Bypass Vectors' -Control "LOLBAS Exposure - $binName" -Status 'FAIL' -Severity $severity `
                    -CurrentValue "Present at $foundPath; no explicit AppLocker Deny rule found (implicitly allowed by the default path rule)" -RecommendedValue 'Explicit Deny rule (or restricted to a justified group)' `
                    -CIS_Control 'CIS 2.5' -NIST_Control 'CM-7' -MITRE_Technique $mitre -ISO27001_Control 'A.8.19' -NIS2_Article 'Art.21(2)(e)' -NSA_Guidance 'NSA/CISA Application Allowlisting Guidance' `
                    -Recommendation "Add an explicit AppLocker Deny rule for $binName (or restrict it to a justified group, e.g. Developers) - the default path allow rule implicitly permits this well-documented LOLBAS binary, letting attackers proxy-execute arbitrary code/scripts despite AppLocker being enforced."
            }
        }

        $psexecCmd = Get-Command 'psexec.exe' -ErrorAction SilentlyContinue
        if ($psexecCmd) {
            Add-AuditResult -Category 'AppLocker - LOLBAS & Execution Bypass Vectors' -Control 'LOLBAS Exposure - psexec.exe' -Status 'WARN' -Severity 'Medium' `
                -CurrentValue "Found on PATH at $($psexecCmd.Source)" -RecommendedValue 'Not present outside a justified administrative context, or explicitly Denied by AppLocker' -CIS_Control 'CIS 2.5' `
                -NIST_Control 'CM-7' -MITRE_Technique 'T1570 (Lateral Tool Transfer), T1569.002 (Service Execution)' -ISO27001_Control 'A.8.19' -NIS2_Article 'Art.21(2)(e)' `
                -Recommendation 'PsExec is not a built-in OS component - its presence here is either legitimate admin tooling (Sysinternals Suite) or staged for lateral movement/remote execution. Confirm legitimacy; if not required on this endpoint, remove it and add an AppLocker/WDAC Deny rule by hash.'
        } else {
            Add-AuditResult -Category 'AppLocker - LOLBAS & Execution Bypass Vectors' -Control 'LOLBAS Exposure - psexec.exe' -Status 'PASS' -Severity 'Medium' `
                -CurrentValue 'Not found on PATH' -RecommendedValue 'Not present outside a justified administrative context' -CIS_Control 'CIS 2.5' -NIST_Control 'CM-7' `
                -MITRE_Technique 'T1570 (Lateral Tool Transfer)' -ISO27001_Control 'A.8.19' -NIS2_Article 'Art.21(2)(e)' -Recommendation 'No action required.'
        }

        if (-not $foundAny) {
            Add-AuditResult -Category 'AppLocker - LOLBAS & Execution Bypass Vectors' -Control 'LOLBAS Binary Enumeration' -Status 'INFO' -Severity 'Informational' `
                -CurrentValue 'None of the curated LOLBAS binaries were located at their expected paths' -Recommendation 'Unusual for a standard Windows 11 install - verify System32/.NET Framework directory integrity.'
        }
    } catch {
        Add-AuditResult -Category 'AppLocker - LOLBAS & Execution Bypass Vectors' -Control 'LOLBAS Execution Bypass Exposure' -Status 'WARN' -Severity 'Low' `
            -CurrentValue 'Query failed' -Recommendation "Unable to complete LOLBAS exposure audit: $($_.Exception.Message)"
    }
}

function Test-AppLockerPublisherRuleOverTrust {
    <#
        Audits Publisher (certificate) Allow rules for total wildcarding - ProductName=*,
        BinaryName=*, and an unbounded BinaryVersionRange. A rule this broad trusts every
        binary a vendor has ever signed, which for "Microsoft" specifically means every
        Microsoft-signed LOLBAS binary is implicitly allowlisted too.
    #>
    Write-SectionBanner 'AppLocker - Publisher Rule Over-Trust'
    try {
        $xml = Get-AppLockerPolicyXmlCache
        if (-not $xml) {
            Add-AuditResult -Category 'AppLocker - LOLBAS & Execution Bypass Vectors' -Control 'AppLocker Publisher Rule Over-Trust' -Status 'INFO' -Severity 'Informational' `
                -CurrentValue 'AppLocker unavailable' -Recommendation 'No effective AppLocker policy to evaluate.'
            return
        }
        $allowPublisherConditions = @($xml.SelectNodes("//FilePublisherRule[@Action='Allow']/Conditions/FilePublisherCondition"))
        if ($allowPublisherConditions.Count -eq 0) {
            Add-AuditResult -Category 'AppLocker - LOLBAS & Execution Bypass Vectors' -Control 'AppLocker Publisher Rule Over-Trust' -Status 'PASS' -Severity 'Medium' `
                -CurrentValue 'No Publisher (certificate) Allow rules defined' -RecommendedValue 'Publisher rules scoped to specific ProductName/BinaryName/version where used' -CIS_Control 'CIS 2.5' `
                -NIST_Control 'CM-7, SI-7' -ISO27001_Control 'A.8.19' -NIS2_Article 'Art.21(2)(e)' -Recommendation 'No action required.'
            return
        }

        $overTrusted = [System.Collections.Generic.List[string]]::new()
        foreach ($cond in $allowPublisherConditions) {
            $publisher = $cond.GetAttribute('PublisherName')
            $product = $cond.GetAttribute('ProductName')
            $binary = $cond.GetAttribute('BinaryName')
            $versionRange = $cond.SelectSingleNode('BinaryVersionRange')
            $lowV = if ($versionRange) { $versionRange.GetAttribute('LowSection') } else { '*' }
            $highV = if ($versionRange) { $versionRange.GetAttribute('HighSection') } else { '*' }

            if (($product -eq '*') -and ($binary -eq '*') -and ($lowV -eq '*') -and ($highV -eq '*')) {
                $overTrusted.Add("Publisher='$publisher' (Product=*, Binary=*, Version=* to *)")
            }
        }

        if ($overTrusted.Count -eq 0) {
            Add-AuditResult -Category 'AppLocker - LOLBAS & Execution Bypass Vectors' -Control 'AppLocker Publisher Rule Over-Trust' -Status 'PASS' -Severity 'Medium' `
                -CurrentValue "$($allowPublisherConditions.Count) Publisher Allow rule(s) checked; none are fully wildcarded (Product=*, Binary=*, Version=* to *)" `
                -RecommendedValue 'Publisher rules scoped to specific ProductName/BinaryName/version' -CIS_Control 'CIS 2.5' -NIST_Control 'CM-7, SI-7' -ISO27001_Control 'A.8.19' `
                -NIS2_Article 'Art.21(2)(e)' -Recommendation 'No action required.'
        } else {
            Add-AuditResult -Category 'AppLocker - LOLBAS & Execution Bypass Vectors' -Control 'AppLocker Publisher Rule Over-Trust' -Status 'WARN' -Severity 'High' `
                -CurrentValue ($overTrusted -join ' | ') -RecommendedValue 'Publisher rules scoped to specific ProductName/BinaryName/version' -CIS_Control 'CIS 2.5' -NIST_Control 'CM-7, SI-7' `
                -MITRE_Technique 'T1218 (System Binary Proxy Execution)' -ISO27001_Control 'A.8.19' -NIS2_Article 'Art.21(2)(e)' -NSA_Guidance 'NSA/CISA Application Allowlisting Guidance' `
                -Recommendation 'A Publisher rule that trusts an entire vendor across all products, binaries, and versions implicitly allowlists every LOLBAS binary that vendor ever signed - including csc.exe, msbuild.exe, and rundll32.exe for a "trust all Microsoft" rule. Narrow each listed rule to a specific ProductName and BinaryName, and pin a minimum BinaryVersionRange, rather than trusting the publisher unconditionally.'
        }
    } catch {
        Add-AuditResult -Category 'AppLocker - LOLBAS & Execution Bypass Vectors' -Control 'AppLocker Publisher Rule Over-Trust' -Status 'WARN' -Severity 'Low' `
            -CurrentValue 'Query failed' -Recommendation "Unable to complete publisher rule audit: $($_.Exception.Message)"
    }
}

function Test-AppLockerServiceIntegrity {
    <#
        Audits the Application Identity service (AppIDSvc), which AppLocker enforcement
        depends on entirely: a disabled service or a tamperable service DACL both silently
        defeat every configured rule regardless of policy content.
    #>
    Write-SectionBanner 'AppLocker - Application Identity Service (AppIDSvc) Integrity'
    try {
        $svc = Get-Service -Name 'AppIDSvc' -ErrorAction SilentlyContinue
        if (-not $svc) {
            Add-AuditResult -Category 'AppLocker - Registry & Service Integrity' -Control 'AppIDSvc Service State' -Status 'INFO' -Severity 'Informational' `
                -CurrentValue 'Service not found' -Recommendation 'Not applicable on this SKU/build.'
        } elseif ($svc.StartType -eq 'Disabled') {
            Add-AuditResult -Category 'AppLocker - Registry & Service Integrity' -Control 'AppIDSvc Service State' -Status 'FAIL' -Severity 'Critical' `
                -CurrentValue 'Disabled' -RecommendedValue 'Not Disabled (Manual/trigger-start is the normal default - AppIDSvc does not run continuously)' -CIS_Control 'CIS 2.5' `
                -NIST_Control 'CM-7, SI-7' -MITRE_Technique 'T1562.001 (Disable or Modify Tools)' -ISO27001_Control 'A.8.19' -NIS2_Article 'Art.21(2)(e)' `
                -Recommendation 'Set-Service -Name AppIDSvc -StartupType Manual. AppLocker enforcement depends entirely on this service - disabling it silently defeats every configured rule regardless of policy.'
        } else {
            Add-AuditResult -Category 'AppLocker - Registry & Service Integrity' -Control 'AppIDSvc Service State' -Status 'PASS' -Severity 'Critical' `
                -CurrentValue "StartType=$($svc.StartType); Status=$($svc.Status)" -RecommendedValue 'Not Disabled' -CIS_Control 'CIS 2.5' -NIST_Control 'CM-7, SI-7' -ISO27001_Control 'A.8.19' `
                -NIS2_Article 'Art.21(2)(e)' -Recommendation 'No action required.'
        }

        $sdOutput = & sc.exe sdshow AppIDSvc 2>$null
        $sddl = if ($sdOutput) { (($sdOutput -join '')).Trim() } else { $null }
        if (-not [string]::IsNullOrWhiteSpace($sddl)) {
            $hasSuspiciousGrant = $sddl -match ';;;WD\)' -or $sddl -match ';;;AU\)' -or $sddl -match ';;;IU\)'
            if (-not $hasSuspiciousGrant) {
                Add-AuditResult -Category 'AppLocker - Registry & Service Integrity' -Control 'AppIDSvc Service DACL' -Status 'PASS' -Severity 'High' `
                    -CurrentValue 'No Everyone/Authenticated Users/Interactive User grant found' -RecommendedValue 'Default-restrictive service DACL' -CIS_Control 'CIS 2.5' -NIST_Control 'AC-6, CM-7' `
                    -MITRE_Technique 'T1562.001 (Disable or Modify Tools)' -ISO27001_Control 'A.8.19' -NIS2_Article 'Art.21(2)(e)' -Recommendation 'No action required.'
            } else {
                Add-AuditResult -Category 'AppLocker - Registry & Service Integrity' -Control 'AppIDSvc Service DACL' -Status 'WARN' -Severity 'High' `
                    -CurrentValue "SDDL: $sddl" -RecommendedValue 'Default-restrictive service DACL' -CIS_Control 'CIS 2.5' -NIST_Control 'AC-6, CM-7' `
                    -MITRE_Technique 'T1562.001 (Disable or Modify Tools)' -ISO27001_Control 'A.8.19' -NIS2_Article 'Art.21(2)(e)' `
                    -Recommendation 'The AppIDSvc service DACL includes an Everyone/Authenticated Users/Interactive-User token. Review the exact rights granted (raw SDDL shown above) - if a standard user can stop or reconfigure this service, they can disable AppLocker enforcement entirely. Restore the default DACL via sc.exe sdset if the grant is broader than intended.'
            }
        } else {
            Add-AuditResult -Category 'AppLocker - Registry & Service Integrity' -Control 'AppIDSvc Service DACL' -Status 'WARN' -Severity 'Low' `
                -CurrentValue 'Unable to retrieve service SDDL' -Recommendation 'sc.exe sdshow AppIDSvc returned no output - verify manually.'
        }
    } catch {
        Add-AuditResult -Category 'AppLocker - Registry & Service Integrity' -Control 'AppIDSvc Integrity' -Status 'WARN' -Severity 'Low' `
            -CurrentValue 'Query failed' -Recommendation "Unable to complete AppIDSvc integrity audit: $($_.Exception.Message)"
    }
}

function Test-AppLockerPolicyRegistryKeyACLs {
    <#
        Audits registry ACLs on every known local storage location for AppLocker/SRP policy
        data - the currently-documented SrpV2 key plus the SrpData/AppLocker paths - so that
        a low-privileged user cannot modify or wipe the cached policy applied to this
        endpoint without ever touching the source GPO.
    #>
    Write-SectionBanner 'AppLocker - Policy Registry Key Permissions'
    $keysToCheck = @(
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2'
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpData'
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppLocker'
    )
    $anyChecked = $false
    foreach ($key in $keysToCheck) {
        try {
            if (-not (Test-Path -LiteralPath $key -ErrorAction SilentlyContinue)) { continue }
            $anyChecked = $true
            $check = Test-LowPrivilegeWriteAccess -Path $key -ObjectType Registry
            if ($check.IsVulnerable) {
                Add-AuditResult -Category 'AppLocker - Registry & Service Integrity' -Control "AppLocker Policy Registry Key ACL - $key" -Status 'FAIL' -Severity 'Critical' `
                    -CurrentValue "Grants: $($check.Principals -join '; ')" -RecommendedValue 'No SetValue/CreateSubKey/FullControl grant to Everyone, Authenticated Users, or Users' -CIS_Control 'CIS 2.5' `
                    -NIST_Control 'AC-6, CM-7' -MITRE_Technique 'T1562.001 (Disable or Modify Tools)' -ISO27001_Control 'A.8.19' -NIS2_Article 'Art.21(2)(e)' -NSA_Guidance 'NSA/CISA Application Allowlisting Guidance' `
                    -Recommendation "Remove the low-privilege write grant on `"$key`". A standard user with write access here can modify or wipe the cached AppLocker policy definitions applied to this endpoint, defeating enforcement entirely without needing to touch the source GPO."
            } else {
                Add-AuditResult -Category 'AppLocker - Registry & Service Integrity' -Control "AppLocker Policy Registry Key ACL - $key" -Status 'PASS' -Severity 'Critical' `
                    -CurrentValue 'No low-privilege write grant' -RecommendedValue 'No SetValue/CreateSubKey/FullControl grant to Everyone, Authenticated Users, or Users' -CIS_Control 'CIS 2.5' `
                    -NIST_Control 'AC-6, CM-7' -ISO27001_Control 'A.8.19' -NIS2_Article 'Art.21(2)(e)' -Recommendation 'No action required.'
            }
        } catch {
            Add-AuditResult -Category 'AppLocker - Registry & Service Integrity' -Control "AppLocker Policy Registry Key ACL - $key" -Status 'WARN' -Severity 'Low' `
                -CurrentValue 'Query failed' -Recommendation "Unable to audit ACL for ${key}: $($_.Exception.Message)"
        }
    }
    if (-not $anyChecked) {
        Add-AuditResult -Category 'AppLocker - Registry & Service Integrity' -Control 'AppLocker Policy Registry Key Permissions' -Status 'INFO' -Severity 'Informational' `
            -CurrentValue 'None of the known AppLocker/SRP policy registry key locations are present' -Recommendation 'Expected if no AppLocker/SRP policy has ever been applied to this endpoint (e.g. local-only policy never configured, or the GPO is not yet linked).'
    }
}

function Test-AppLockerEventLogTelemetry {
    <#
        Audits the four AppLocker event log channels for operational (enabled) state and
        adequate maximum size, cross-referenced against which rule collections are actually
        enforced/audited so a disabled channel backing an active collection is flagged more
        severely than one backing an unconfigured collection.
    #>
    Write-SectionBanner 'AppLocker - Event Log Channel Telemetry'
    $channels = @(
        @{ Name = 'Microsoft-Windows-AppLocker/EXE and DLL';              RelevantTo = @('Exe', 'Dll') }
        @{ Name = 'Microsoft-Windows-AppLocker/MSI and Script';           RelevantTo = @('Msi', 'Script') }
        @{ Name = 'Microsoft-Windows-AppLocker/Packaged app-Execution';   RelevantTo = @('Appx') }
        @{ Name = 'Microsoft-Windows-AppLocker/Packaged app-Deployment';  RelevantTo = @('Appx') }
    )
    $xml = Get-AppLockerPolicyXmlCache
    foreach ($ch in $channels) {
        try {
            $log = Get-WinEvent -ListLog $ch.Name -ErrorAction Stop
            $relevantEnforced = $false
            if ($xml) {
                foreach ($ct in $ch.RelevantTo) {
                    $node = Get-AppLockerRuleCollectionNode -Xml $xml -CollectionType $ct
                    if ($node -and ($node.EnforcementMode -eq 'Enabled' -or $node.EnforcementMode -eq 'AuditOnly')) { $relevantEnforced = $true }
                }
            }

            if ($log.IsEnabled) {
                $maxKb = [math]::Round($log.MaximumSizeInBytes / 1KB, 0)
                Add-AuditResult -Category 'AppLocker - Registry & Service Integrity' -Control "AppLocker Event Log Channel - $($ch.Name)" -Status 'PASS' -Severity 'Medium' `
                    -CurrentValue "Enabled; MaxSize=$maxKb KB" -RecommendedValue 'Enabled, >= 4096 KB' -CIS_Control 'CIS 8.5' -NIST_Control 'AU-2, AU-12' `
                    -MITRE_Technique 'T1562.002 (Disable Windows Event Logging)' -ISO27001_Control 'A.8.15' -NIS2_Article 'Art.21(2)(b)' -NSA_Guidance 'NSA/CISA Audit Logging Best Practices' `
                    -Recommendation 'No action required.'

                if ($maxKb -lt 4096) {
                    Add-AuditResult -Category 'AppLocker - Registry & Service Integrity' -Control "AppLocker Event Log Size - $($ch.Name)" -Status 'WARN' -Severity 'Medium' `
                        -CurrentValue "$maxKb KB" -RecommendedValue '>= 4096 KB' -CIS_Control 'CIS 8.3' -NIST_Control 'AU-4, AU-11' -MITRE_Technique 'T1070.001 (Clear Windows Event Logs)' `
                        -ISO27001_Control 'A.8.15' -NIS2_Article 'Art.21(2)(b)' `
                        -Recommendation "Increase the log size: wevtutil sl `"$($ch.Name)`" /ms:4194304, so AppLocker allow/block telemetry (Event ID 8002/8004/8005/8007) is not lost to overflow during high-volume periods."
                }
            } elseif ($relevantEnforced) {
                Add-AuditResult -Category 'AppLocker - Registry & Service Integrity' -Control "AppLocker Event Log Channel - $($ch.Name)" -Status 'FAIL' -Severity 'High' `
                    -CurrentValue 'Disabled, despite a related rule collection being Enabled/AuditOnly' -RecommendedValue 'Enabled' -CIS_Control 'CIS 8.5' -NIST_Control 'AU-2, AU-12' `
                    -MITRE_Technique 'T1562.002 (Disable Windows Event Logging)' -ISO27001_Control 'A.8.15' -NIS2_Article 'Art.21(2)(b)' -NSA_Guidance 'NSA/CISA Audit Logging Best Practices' `
                    -Recommendation "Enable this channel: wevtutil sl `"$($ch.Name)`" /e:true. AppLocker is actively enforcing/auditing a related rule collection, but the corresponding event channel is disabled - blocked and allowed execution attempts are not being captured for SOC visibility."
            } else {
                Add-AuditResult -Category 'AppLocker - Registry & Service Integrity' -Control "AppLocker Event Log Channel - $($ch.Name)" -Status 'INFO' -Severity 'Informational' `
                    -CurrentValue 'Disabled; no related rule collection is currently enforced' -RecommendedValue 'Enabled once AppLocker enforcement is configured for this collection type' `
                    -Recommendation 'Enable this channel proactively before enabling the related AppLocker rule collection, so telemetry is captured from the very first enforcement action.'
            }
        } catch {
            Add-AuditResult -Category 'AppLocker - Registry & Service Integrity' -Control "AppLocker Event Log Channel - $($ch.Name)" -Status 'WARN' -Severity 'Low' `
                -CurrentValue 'Query failed' -Recommendation "Unable to query this event log channel: $($_.Exception.Message)"
        }
    }
}

#endregion

#region ============================== 25. MODERN IDENTITY, TOKENS & CLOUD SYNC (ENTRA / INTUNE) ==============================

function Get-DsregStatusCache {
    <# Central dsregcmd.exe /status accessor, shared across the identity/cloud checks. #>
    if ($null -eq $Script:DsregStatusCache) {
        try {
            $output = & dsregcmd.exe /status 2>$null
            $Script:DsregStatusCache = if ($output) { $output } else { $false }
        } catch { $Script:DsregStatusCache = $false }
    }
    return $Script:DsregStatusCache
}

function Get-DsregValue {
    param($Lines, [string]$Key)
    if (-not $Lines) { return 'Unknown' }
    $line = $Lines | Where-Object { $_ -match "^\s*$Key\s*:" } | Select-Object -First 1
    if ($line) { return (($line -split ':', 2)[1]).Trim() }
    return 'Unknown'
}

function Test-PRTTpmBinding {
    <#
        Audits Primary Refresh Token issuance and the device's cryptographic identity key
        provider via dsregcmd /status. dsregcmd does not expose a literal "PRT is TPM-bound"
        boolean, so this check uses the device key's KeyProvider field (Platform Crypto
        Provider = TPM-backed, Software Key Storage Provider = not) as the best available,
        honestly-labeled proxy for hardware-backed device identity underpinning PRT issuance.
    #>
    Write-SectionBanner 'Modern Identity - Primary Refresh Token (PRT) & TPM Binding'
    try {
        $dsreg = Get-DsregStatusCache
        if (-not $dsreg) { throw 'dsregcmd.exe returned no output' }

        $azureAdJoined = Get-DsregValue $dsreg 'AzureAdJoined'
        if ($azureAdJoined -ne 'YES') {
            Add-AuditResult -Category 'Modern Identity & Cloud Token Security' -Control 'Primary Refresh Token (PRT) & TPM Binding' -Status 'INFO' -Severity 'Informational' `
                -CurrentValue 'Device is not Entra ID (Azure AD) joined' -RecommendedValue 'N/A' `
                -Recommendation 'Not applicable - see the Zero Trust Device Identity Anchor finding for this device''s join state.'
            return
        }

        $azureAdPrt = Get-DsregValue $dsreg 'AzureAdPrt'
        $keyProvider = Get-DsregValue $dsreg 'KeyProvider'
        $isTpmBound = $keyProvider -match '(?i)Platform Crypto Provider'

        if ($azureAdPrt -eq 'YES' -and $isTpmBound) {
            Add-AuditResult -Category 'Modern Identity & Cloud Token Security' -Control 'Primary Refresh Token (PRT) & TPM Binding' -Status 'PASS' -Severity 'Critical' `
                -CurrentValue "AzureAdPrt=YES; KeyProvider=$keyProvider (TPM-backed)" -RecommendedValue 'AzureAdPrt=YES; device key backed by the Platform Crypto Provider (TPM)' `
                -CIS_Control 'CIS 5.1' -NIST_Control 'IA-3, IA-5' -MITRE_Technique 'T1528 (Steal Application Access Token), T1550.001 (Application Access Token)' -ISO27001_Control 'A.8.5' `
                -NIS2_Article 'Art.21(2)(i)' -NSA_Guidance 'NSA/CISA Advancing Zero Trust Maturity - Device Pillar' -Recommendation 'No action required.'
        } elseif ($azureAdPrt -eq 'YES' -and -not $isTpmBound) {
            Add-AuditResult -Category 'Modern Identity & Cloud Token Security' -Control 'Primary Refresh Token (PRT) & TPM Binding' -Status 'FAIL' -Severity 'High' `
                -CurrentValue "AzureAdPrt=YES; KeyProvider=$keyProvider (not confirmed TPM-backed)" -RecommendedValue 'Device key backed by the Platform Crypto Provider (TPM)' `
                -CIS_Control 'CIS 5.1' -NIST_Control 'IA-3, IA-5' -MITRE_Technique 'T1528 (Steal Application Access Token)' -ISO27001_Control 'A.8.5' -NIS2_Article 'Art.21(2)(i)' `
                -NSA_Guidance 'NSA/CISA Advancing Zero Trust Maturity - Device Pillar' `
                -Recommendation 'This device''s Entra ID identity key is not confirmed to be hardware-bound. Verify TPM presence/readiness (see the TPM finding earlier in this report) and that the device meets Windows Hello for Business / Entra ID hardware key requirements - a software-only key is more easily extracted if the endpoint is compromised.'
        } else {
            Add-AuditResult -Category 'Modern Identity & Cloud Token Security' -Control 'Primary Refresh Token (PRT) & TPM Binding' -Status 'WARN' -Severity 'Medium' `
                -CurrentValue "AzureAdPrt=$azureAdPrt; KeyProvider=$keyProvider" -RecommendedValue 'AzureAdPrt=YES' -CIS_Control 'CIS 5.1' -NIST_Control 'IA-3, IA-5' -ISO27001_Control 'A.8.5' `
                -NIS2_Article 'Art.21(2)(i)' `
                -Recommendation 'No active Primary Refresh Token was found. This is expected if no user has signed in with an Entra ID account since the last reboot; SSO to Entra ID-integrated resources will not function until a PRT is issued at next interactive sign-in.'
        }
    } catch {
        Add-AuditResult -Category 'Modern Identity & Cloud Token Security' -Control 'Primary Refresh Token (PRT) & TPM Binding' -Status 'WARN' -Severity 'Low' `
            -CurrentValue 'Query failed' -Recommendation "Unable to query dsregcmd.exe: $($_.Exception.Message)"
    }
}

function Test-SeamlessSSOAndKerberosCloudTGT {
    <#
        Audits the client-side Seamless SSO indicator (the autologon.microsoftazuread-sso.com
        Intranet-zone assignment pushed by the Seamless SSO GPO/CSP). Kerberos ticket-granting-
        ticket lifetime is a domain-controller-enforced Kerberos Policy (Default Domain
        Policy), not a locally-evaluable member-workstation setting, so this check reports
        that limitation explicitly rather than asserting a value it cannot see.
    #>
    Write-SectionBanner 'Modern Identity - Seamless SSO & Kerberos Cloud TGT'
    try {
        $ssoZonePath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\microsoftazuread-sso.com'
        $autologonValue = Get-RegistryValueSafe -Path (Join-Path $ssoZonePath 'autologon') -Name 'autologon' -DefaultValue $null
        if ($null -eq $autologonValue) {
            $autologonValue = Get-RegistryValueSafe -Path $ssoZonePath -Name 'autologon' -DefaultValue $null
        }

        if ($autologonValue -eq 1) {
            Add-AuditResult -Category 'Modern Identity & Cloud Token Security' -Control 'Seamless SSO Configuration' -Status 'PASS' -Severity 'Low' `
                -CurrentValue 'autologon.microsoftazuread-sso.com assigned to the Intranet zone (Seamless SSO configured)' -RecommendedValue 'Configured where Seamless SSO is the organization''s chosen hybrid identity flow' `
                -CIS_Control 'CIS 5.1' -NIST_Control 'IA-2' -ISO27001_Control 'A.8.5' -NIS2_Article 'Art.21(2)(i)' -Recommendation 'No action required.'
        } else {
            Add-AuditResult -Category 'Modern Identity & Cloud Token Security' -Control 'Seamless SSO Configuration' -Status 'INFO' -Severity 'Informational' `
                -CurrentValue 'Seamless SSO Intranet-zone assignment not found' -RecommendedValue 'Configured where Seamless SSO is the organization''s chosen hybrid identity flow' `
                -Recommendation 'This is only a gap if the organization has deployed Seamless SSO (Hybrid Entra ID join scenarios) and expects it here - Seamless SSO is not applicable to every environment (e.g. cloud-only, or PIN/WHfB-only sign-in flows).'
        }

        Add-AuditResult -Category 'Modern Identity & Cloud Token Security' -Control 'Kerberos TGT Lifetime (Domain Policy)' -Status 'INFO' -Severity 'Informational' `
            -CurrentValue 'Not evaluable from this endpoint' -RecommendedValue 'Maximum ticket age <= 10 hours, enforced via Default Domain Policy' -CIS_Control 'CIS 18.3' -NIST_Control 'IA-5' `
            -ISO27001_Control 'A.8.5' -NIS2_Article 'Art.21(2)(i)' `
            -Recommendation 'Kerberos ticket lifetime (MaxTicketAge/MaxRenewAge) is a Kerberos Policy setting enforced by domain controllers via the Default Domain Policy, not a per-workstation setting this audit can read locally. Verify TGT lifetime centrally on the domain (Group Policy Management > Default Domain Policy > Account Policies > Kerberos Policy) rather than on individual endpoints.'
    } catch {
        Add-AuditResult -Category 'Modern Identity & Cloud Token Security' -Control 'Seamless SSO & Kerberos Cloud TGT' -Status 'WARN' -Severity 'Low' `
            -CurrentValue 'Query failed' -Recommendation "Unable to complete Seamless SSO audit: $($_.Exception.Message)"
    }
}

function Test-WHfBTpmEnforcement {
    <#
        Audits the Windows Hello for Business "Require TPM" (RequireSecurityDevice) policy,
        which - when enforced - prohibits software-only ("soft key") WHfB enrollment and
        requires the sign-in key to be hardware-bound.
    #>
    Write-SectionBanner 'Modern Identity - Windows Hello for Business TPM Enforcement'
    try {
        $passportPath = 'HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork'
        $requireTpm = Get-RegistryValueSafe -Path $passportPath -Name 'RequireSecurityDevice' -DefaultValue $null

        if ($requireTpm -eq 1) {
            Add-AuditResult -Category 'Modern Identity & Cloud Token Security' -Control 'Windows Hello for Business - Require TPM (No Soft Keys)' -Status 'PASS' -Severity 'High' `
                -CurrentValue 'RequireSecurityDevice=1 (TPM required)' -RecommendedValue '1' -CIS_Control 'CIS 5.1' -NIST_Control 'IA-2, IA-5' `
                -MITRE_Technique 'T1556 (Modify Authentication Process), T1528 (Steal Application Access Token)' -ISO27001_Control 'A.8.5' -NIS2_Article 'Art.21(2)(i)' `
                -NSA_Guidance 'NSA/CISA Selecting Secure Multifactor Authentication' -Recommendation 'No action required.'
        } elseif ($null -eq $requireTpm) {
            Add-AuditResult -Category 'Modern Identity & Cloud Token Security' -Control 'Windows Hello for Business - Require TPM (No Soft Keys)' -Status 'INFO' -Severity 'Informational' `
                -CurrentValue 'Not Configured (WHfB policy not present on this endpoint)' -RecommendedValue '1' -CIS_Control 'CIS 5.1' -NIST_Control 'IA-2, IA-5' -ISO27001_Control 'A.8.5' `
                -NIS2_Article 'Art.21(2)(i)' -Recommendation 'Only actionable if the organization has deployed Windows Hello for Business. If it has, deploy the "Use a Trusted Platform Module (TPM)" WHfB policy (RequireSecurityDevice=1) via Intune/GPO to prohibit software-only key enrollment.'
        } else {
            Add-AuditResult -Category 'Modern Identity & Cloud Token Security' -Control 'Windows Hello for Business - Require TPM (No Soft Keys)' -Status 'FAIL' -Severity 'High' `
                -CurrentValue 'RequireSecurityDevice=0 (software-based keys permitted)' -RecommendedValue '1' -CIS_Control 'CIS 5.1' -NIST_Control 'IA-2, IA-5' `
                -MITRE_Technique 'T1556 (Modify Authentication Process)' -ISO27001_Control 'A.8.5' -NIS2_Article 'Art.21(2)(i)' -NSA_Guidance 'NSA/CISA Selecting Secure Multifactor Authentication' `
                -Recommendation 'Set the "Use a Trusted Platform Module (TPM)" WHfB policy to Required (RequireSecurityDevice=1). Software-based WHfB keys are stored without hardware isolation and are a materially weaker sign-in credential than a TPM-bound key.'
        }
    } catch {
        Add-AuditResult -Category 'Modern Identity & Cloud Token Security' -Control 'Windows Hello for Business TPM Enforcement' -Status 'WARN' -Severity 'Low' `
            -CurrentValue 'Query failed' -Recommendation "Unable to query WHfB policy: $($_.Exception.Message)"
    }
}

function Test-MDMPolicyRegistryACL {
    <#
        Audits the local ACL on the MDM/Intune policy cache under PolicyManager. A
        low-privilege write grant here would let a standard user silently override any
        Intune-deployed device configuration or compliance policy without ever touching the
        Intune service - the local cache is what Windows components actually read from.
    #>
    Write-SectionBanner 'Intune / MDM Policy Integrity - PolicyManager Registry ACL'
    $keysToCheck = @(
        'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device'
        'HKLM:\SOFTWARE\Microsoft\PolicyManager\providers'
    )
    $anyChecked = $false
    foreach ($key in $keysToCheck) {
        try {
            if (-not (Test-Path -LiteralPath $key -ErrorAction SilentlyContinue)) { continue }
            $anyChecked = $true
            $check = Test-LowPrivilegeWriteAccess -Path $key -ObjectType Registry
            if ($check.IsVulnerable) {
                Add-AuditResult -Category 'Intune / MDM Policy Integrity' -Control "MDM Policy Registry Key ACL - $key" -Status 'FAIL' -Severity 'Critical' `
                    -CurrentValue "Grants: $($check.Principals -join '; ')" -RecommendedValue 'No SetValue/CreateSubKey/FullControl grant to Everyone, Authenticated Users, or Users' -CIS_Control 'CIS 5.1' `
                    -NIST_Control 'AC-6, CM-7' -MITRE_Technique 'T1562.001 (Disable or Modify Tools)' -ISO27001_Control 'A.8.19' -NIS2_Article 'Art.21(2)(i)' `
                    -Recommendation "Remove the low-privilege write grant on `"$key`". A standard user with write access here can override or wipe deployed Intune device configuration/compliance policy locally, without needing access to the Intune tenant."
            } else {
                Add-AuditResult -Category 'Intune / MDM Policy Integrity' -Control "MDM Policy Registry Key ACL - $key" -Status 'PASS' -Severity 'Critical' `
                    -CurrentValue 'No low-privilege write grant' -RecommendedValue 'No SetValue/CreateSubKey/FullControl grant to Everyone, Authenticated Users, or Users' -CIS_Control 'CIS 5.1' `
                    -NIST_Control 'AC-6, CM-7' -ISO27001_Control 'A.8.19' -NIS2_Article 'Art.21(2)(i)' -Recommendation 'No action required.'
            }
        } catch {
            Add-AuditResult -Category 'Intune / MDM Policy Integrity' -Control "MDM Policy Registry Key ACL - $key" -Status 'WARN' -Severity 'Low' `
                -CurrentValue 'Query failed' -Recommendation "Unable to audit ACL for ${key}: $($_.Exception.Message)"
        }
    }
    if (-not $anyChecked) {
        Add-AuditResult -Category 'Intune / MDM Policy Integrity' -Control 'MDM Policy Registry Key Permissions' -Status 'INFO' -Severity 'Informational' `
            -CurrentValue 'PolicyManager registry path not present' -Recommendation 'Expected if this device is not MDM-enrolled.'
    }
}

function Test-MDMScheduledTaskIntegrity {
    <#
        Audits scheduled tasks under the Intune/MDM enrollment client's task path
        (\Microsoft\Windows\EnterpriseMgmt\) for missing target binaries or targets writable
        by a low-privileged principal - the same hijack pattern already audited for general
        SYSTEM-context tasks, scoped specifically to the enrollment/sync client so a tampered
        MDM task is called out distinctly from a general scheduled-task finding.
    #>
    Write-SectionBanner 'Intune / MDM Policy Integrity - Enrollment Scheduled Task Integrity'
    try {
        $tasks = @(Get-ScheduledTask -TaskPath '\Microsoft\Windows\EnterpriseMgmt\*' -ErrorAction SilentlyContinue)
        if ($tasks.Count -eq 0) {
            Add-AuditResult -Category 'Intune / MDM Policy Integrity' -Control 'MDM Enrollment Scheduled Task Integrity' -Status 'INFO' -Severity 'Informational' `
                -CurrentValue 'No tasks found under \Microsoft\Windows\EnterpriseMgmt\' -Recommendation 'Expected if this device is not MDM-enrolled.'
            return
        }

        $orphaned = [System.Collections.Generic.List[string]]::new()
        $writableTarget = [System.Collections.Generic.List[string]]::new()
        foreach ($task in $tasks) {
            foreach ($action in $task.Actions) {
                if (-not $action.Execute) { continue }
                $rawExecute = [Environment]::ExpandEnvironmentVariables($action.Execute)
                $taskLabel = "$($task.TaskPath)$($task.TaskName)"

                $resolved = $null
                if (Test-Path -LiteralPath $rawExecute -ErrorAction SilentlyContinue) {
                    $resolved = $rawExecute
                } elseif ($rawExecute -notmatch '[\\/]') {
                    $cmd = Get-Command $rawExecute -ErrorAction SilentlyContinue
                    if ($cmd) { $resolved = $cmd.Source }
                }

                if (-not $resolved) {
                    $orphaned.Add("$taskLabel -> $rawExecute [target not found]")
                } else {
                    $check = Test-LowPrivilegeWriteAccess -Path $resolved -ObjectType FileSystem
                    if ($check.IsVulnerable) {
                        $writableTarget.Add("$taskLabel -> $resolved [$($check.Principals -join '; ')]")
                    }
                }
            }
        }

        if ($orphaned.Count -eq 0 -and $writableTarget.Count -eq 0) {
            Add-AuditResult -Category 'Intune / MDM Policy Integrity' -Control 'MDM Enrollment Scheduled Task Integrity' -Status 'PASS' -Severity 'High' `
                -CurrentValue "$($tasks.Count) enrollment task(s) checked; all targets present and not low-privilege-writable" -RecommendedValue 'All targets present with restrictive ACLs' `
                -CIS_Control 'CIS 5.1' -NIST_Control 'CM-7, AC-6' -MITRE_Technique 'T1053.005 (Scheduled Task)' -ISO27001_Control 'A.8.19' -NIS2_Article 'Art.21(2)(i)' -Recommendation 'No action required.'
        } else {
            $issues = @($orphaned + $writableTarget)
            Add-AuditResult -Category 'Intune / MDM Policy Integrity' -Control 'MDM Enrollment Scheduled Task Integrity' -Status 'FAIL' -Severity 'Critical' `
                -CurrentValue ($issues -join ' | ') -RecommendedValue 'All targets present with restrictive ACLs' -CIS_Control 'CIS 5.1' -NIST_Control 'CM-7, AC-6' `
                -MITRE_Technique 'T1053.005 (Scheduled Task)' -ISO27001_Control 'A.8.19' -NIS2_Article 'Art.21(2)(i)' `
                -Recommendation 'One or more Intune/MDM enrollment client tasks reference a missing or low-privilege-writable target. These tasks typically run as SYSTEM on a recurring sync schedule - a hijacked target yields reliable, repeated SYSTEM code execution. Restore/protect the target immediately and consider re-enrolling the device if tampering is confirmed.'
        }
    } catch {
        Add-AuditResult -Category 'Intune / MDM Policy Integrity' -Control 'MDM Enrollment Scheduled Task Integrity' -Status 'WARN' -Severity 'Low' `
            -CurrentValue 'Query failed' -Recommendation "Unable to enumerate MDM enrollment scheduled tasks: $($_.Exception.Message)"
    }
}

#endregion

#region ============================== 26. RECOVERABILITY, SHADOW COPIES & RANSOMWARE PREPARATION ==============================

function Test-VSSServiceAndPermissions {
    <#
        Audits the Volume Shadow Copy Service state. VSS is the foundation of Windows'
        native ransomware-recovery path (File History, System Restore, "Previous Versions"),
        and is a favored ransomware pre-encryption target - "vssadmin delete shadows /all
        /quiet" is a MITRE T1490-documented step in most modern ransomware playbooks. A
        disabled VSS service removes this recovery option before an attacker even needs to
        delete anything.
    #>
    Write-SectionBanner 'Ransomware Preparation - Volume Shadow Copy Service (VSS)'
    try {
        $svc = Get-Service -Name 'VSS' -ErrorAction SilentlyContinue
        if (-not $svc) {
            Add-AuditResult -Category 'Ransomware Recovery & Resilience' -Control 'Volume Shadow Copy Service (VSS) State' -Status 'WARN' -Severity 'Medium' `
                -CurrentValue 'Service not found' -Recommendation 'Unexpected on a standard Windows 11 installation - verify service catalog integrity.'
            return
        }
        if ($svc.StartType -eq 'Disabled') {
            Add-AuditResult -Category 'Ransomware Recovery & Resilience' -Control 'Volume Shadow Copy Service (VSS) State' -Status 'FAIL' -Severity 'High' `
                -CurrentValue 'Disabled' -RecommendedValue 'Manual (default; VSS is normally trigger-started on demand, not continuously running)' -CIS_Control 'CIS 10.1' `
                -NIST_Control 'CP-9, CP-10' -MITRE_Technique 'T1490 (Inhibit System Recovery)' -ISO27001_Control 'A.8.13' -NIS2_Article 'Art.21(2)(c)' -NSA_Guidance 'NSA/CISA #StopRansomware Guidance' `
                -Recommendation 'Set-Service -Name VSS -StartupType Manual. A disabled VSS service prevents shadow copies from ever being created, removing a key local recovery path before ransomware even attempts to delete existing copies - and this exact state is a common ransomware pre-encryption artifact if found unexpectedly.'
        } else {
            Add-AuditResult -Category 'Ransomware Recovery & Resilience' -Control 'Volume Shadow Copy Service (VSS) State' -Status 'PASS' -Severity 'High' `
                -CurrentValue "StartType=$($svc.StartType); Status=$($svc.Status)" -RecommendedValue 'Not Disabled' -CIS_Control 'CIS 10.1' -NIST_Control 'CP-9, CP-10' -ISO27001_Control 'A.8.13' `
                -NIS2_Article 'Art.21(2)(c)' -Recommendation 'No action required.'
        }

        Add-AuditResult -Category 'Ransomware Recovery & Resilience' -Control 'VSS/wbadmin Administrative Restriction' -Status 'INFO' -Severity 'Informational' `
            -CurrentValue 'vssadmin.exe/wbadmin.exe require Administrator privileges by OS design; not delegable to standard users' -RecommendedValue 'Standard users hold no local Administrator rights (see local Administrators group membership finding)' `
            -CIS_Control 'CIS 5.4' -NIST_Control 'AC-6' -MITRE_Technique 'T1490 (Inhibit System Recovery)' -ISO27001_Control 'A.8.2' -NIS2_Article 'Art.21(2)(i)' `
            -Recommendation 'vssadmin/wbadmin cannot be independently delegated to standard users - the control that matters is whether the invoking account holds local Administrator rights, which is audited separately by the Local Administrators Group Membership and UAC findings in this report. Additionally, ensure Microsoft Defender Controlled Folder Access and Tamper Protection are enabled, since ransomware typically invokes these tools from an already-elevated context obtained through a separate compromise.'
    } catch {
        Add-AuditResult -Category 'Ransomware Recovery & Resilience' -Control 'Volume Shadow Copy Service (VSS)' -Status 'WARN' -Severity 'Low' `
            -CurrentValue 'Query failed' -Recommendation "Unable to complete VSS audit: $($_.Exception.Message)"
    }
}

function Test-ShadowStorageAllocation {
    <#
        Audits the maximum shadow-copy storage allocation for the system volume. A small
        explicit cap allows shadow copies to be exhausted quickly (through normal disk churn
        or a deliberate low-privilege fill-the-disk action), causing Windows to silently
        purge the oldest recovery points long before an incident occurs.
    #>
    Write-SectionBanner 'Ransomware Preparation - Shadow Storage Allocation'
    try {
        $sysDrive = $env:SystemDrive
        $shadowStorageOutput = & vssadmin.exe list shadowstorage /for=$sysDrive 2>$null
        if (-not $shadowStorageOutput) {
            Add-AuditResult -Category 'Ransomware Recovery & Resilience' -Control 'Shadow Storage Allocation' -Status 'INFO' -Severity 'Informational' `
                -CurrentValue 'No shadow storage association found (no shadow copies have ever been created on this volume)' -RecommendedValue 'Unbounded, or a generous explicit cap (>= 10% of volume size)' `
                -Recommendation 'Consider enabling System Protection (System Restore) or a backup product that leverages VSS, so a shadow storage association - and thus recovery points - actually exist.'
            return
        }

        $maxLine = $shadowStorageOutput | Where-Object { $_ -match '(?i)Maximum Shadow Copy Storage space' } | Select-Object -First 1
        $maxValueText = if ($maxLine) { ($maxLine -split ':', 2)[1].Trim() } else { 'Unknown' }

        if ($maxValueText -match '(?i)UNBOUNDED') {
            Add-AuditResult -Category 'Ransomware Recovery & Resilience' -Control 'Shadow Storage Allocation' -Status 'PASS' -Severity 'Medium' `
                -CurrentValue 'UNBOUNDED' -RecommendedValue 'Unbounded, or a generous explicit cap (>= 10% of volume size)' -CIS_Control 'CIS 10.1' -NIST_Control 'CP-9' -MITRE_Technique 'T1490 (Inhibit System Recovery)' `
                -ISO27001_Control 'A.8.13' -NIS2_Article 'Art.21(2)(c)' -Recommendation 'No action required.'
        } elseif ($maxValueText -match '(\d+(\.\d+)?)\s*(MB|GB)') {
            $sizeNum = [double]$Matches[1]
            $unit = $Matches[3]
            $sizeMb = if ($unit -eq 'GB') { $sizeNum * 1024 } else { $sizeNum }
            if ($sizeMb -lt 2048) {
                Add-AuditResult -Category 'Ransomware Recovery & Resilience' -Control 'Shadow Storage Allocation' -Status 'WARN' -Severity 'Medium' `
                    -CurrentValue "$maxValueText" -RecommendedValue 'Unbounded, or a generous explicit cap (>= 10% of volume size)' -CIS_Control 'CIS 10.1' -NIST_Control 'CP-9' `
                    -MITRE_Technique 'T1490 (Inhibit System Recovery)' -ISO27001_Control 'A.8.13' -NIS2_Article 'Art.21(2)(c)' `
                    -Recommendation "Shadow storage is capped at $maxValueText, which can be exhausted quickly under normal disk churn, silently purging the oldest recovery points. Increase via: vssadmin resize shadowstorage /for=$sysDrive /on=$sysDrive /maxsize=10%% (or a larger explicit size)."
            } else {
                Add-AuditResult -Category 'Ransomware Recovery & Resilience' -Control 'Shadow Storage Allocation' -Status 'PASS' -Severity 'Medium' `
                    -CurrentValue "$maxValueText" -RecommendedValue 'Unbounded, or a generous explicit cap (>= 10% of volume size)' -CIS_Control 'CIS 10.1' -NIST_Control 'CP-9' -ISO27001_Control 'A.8.13' `
                    -NIS2_Article 'Art.21(2)(c)' -Recommendation 'No action required.'
            }
        } else {
            Add-AuditResult -Category 'Ransomware Recovery & Resilience' -Control 'Shadow Storage Allocation' -Status 'INFO' -Severity 'Informational' `
                -CurrentValue "$maxValueText" -RecommendedValue 'Unbounded, or a generous explicit cap (>= 10% of volume size)' -Recommendation 'Unable to parse the shadow storage cap value precisely - review manually via vssadmin list shadowstorage.'
        }
    } catch {
        Add-AuditResult -Category 'Ransomware Recovery & Resilience' -Control 'Shadow Storage Allocation' -Status 'WARN' -Severity 'Low' `
            -CurrentValue 'Query failed' -Recommendation "Unable to query shadow storage allocation: $($_.Exception.Message)"
    }
}

function Test-WinREStatus {
    <#
        Audits Windows Recovery Environment status via reagentc /info. WinRE should remain
        enabled (it is the standard, supported recovery path); the physical-bypass risk the
        user is concerned with (booting into WinRE to reset passwords or replace utilman.exe)
        is mitigated by BitLocker with a pre-boot PIN on the OS volume - audited separately -
        which prevents WinRE-launched tools from accessing OS volume contents without it.
    #>
    Write-SectionBanner 'Ransomware Preparation - Windows Recovery Environment (WinRE)'
    try {
        $reagentOutput = & reagentc.exe /info 2>$null
        if (-not $reagentOutput) { throw 'reagentc.exe returned no output' }

        $statusLine = $reagentOutput | Where-Object { $_ -match '(?i)Windows RE status' } | Select-Object -First 1
        $status = if ($statusLine) { ($statusLine -split ':', 2)[1].Trim() } else { 'Unknown' }

        if ($status -match '(?i)Enabled') {
            Add-AuditResult -Category 'Ransomware Recovery & Resilience' -Control 'Windows Recovery Environment (WinRE) State' -Status 'PASS' -Severity 'High' `
                -CurrentValue 'Enabled' -RecommendedValue 'Enabled' -CIS_Control 'CIS 10.1' -NIST_Control 'CP-10, CP-9' -MITRE_Technique 'T1490 (Inhibit System Recovery)' `
                -ISO27001_Control 'A.8.13' -NIS2_Article 'Art.21(2)(c)' -Recommendation 'No action required. Ensure BitLocker with a pre-boot PIN is enforced on the OS volume (see the BitLocker Key Protector Architecture finding) so WinRE-based physical access cannot be used to bypass authentication or access OS volume contents.'
        } else {
            Add-AuditResult -Category 'Ransomware Recovery & Resilience' -Control 'Windows Recovery Environment (WinRE) State' -Status 'FAIL' -Severity 'High' `
                -CurrentValue "$status" -RecommendedValue 'Enabled' -CIS_Control 'CIS 10.1' -NIST_Control 'CP-10, CP-9' -MITRE_Technique 'T1490 (Inhibit System Recovery)' -ISO27001_Control 'A.8.13' `
                -NIS2_Article 'Art.21(2)(c)' -Recommendation 'Run "reagentc /enable" from an elevated prompt. A disabled WinRE removes the standard, supported OS recovery/repair path and typically also breaks BitLocker device-encryption prerequisites and Windows Update rollback capability.'
        }
    } catch {
        Add-AuditResult -Category 'Ransomware Recovery & Resilience' -Control 'Windows Recovery Environment (WinRE) State' -Status 'WARN' -Severity 'Low' `
            -CurrentValue 'Query failed' -Recommendation "Unable to query reagentc.exe: $($_.Exception.Message)"
    }
}

function Test-SystemRestoreConfiguration {
    <#
        Audits whether System Restore is enabled on the system volume and notes the event
        IDs to monitor for restore-point tampering (creation/deletion), which is a real but
        point-in-time-unauditable concern - live monitoring belongs in the SIEM/EDR layer,
        not a single-run posture check.
    #>
    Write-SectionBanner 'Ransomware Preparation - System Restore Configuration'
    try {
        $restorePoints = $null
        try { $restorePoints = @(Get-ComputerRestorePoint -ErrorAction Stop) } catch { $restorePoints = $null }

        if ($null -ne $restorePoints -and $restorePoints.Count -gt 0) {
            $latest = $restorePoints | Sort-Object -Property SequenceNumber -Descending | Select-Object -First 1
            Add-AuditResult -Category 'Ransomware Recovery & Resilience' -Control 'System Restore Configuration' -Status 'PASS' -Severity 'Medium' `
                -CurrentValue "$($restorePoints.Count) restore point(s) present; most recent: $($latest.Description) ($($latest.SequenceNumber))" -RecommendedValue 'System Restore enabled with recent restore points' `
                -CIS_Control 'CIS 10.1' -NIST_Control 'CP-9' -MITRE_Technique 'T1490 (Inhibit System Recovery)' -ISO27001_Control 'A.8.13' -NIS2_Article 'Art.21(2)(c)' `
                -Recommendation 'No action required. Monitor Application log Event ID 8194 (restore point created) and 8195/8196 (restore operation events) for unexpected mass-deletion patterns indicative of anti-forensic ransomware pre-staging.'
        } else {
            Add-AuditResult -Category 'Ransomware Recovery & Resilience' -Control 'System Restore Configuration' -Status 'WARN' -Severity 'Medium' `
                -CurrentValue 'No restore points found (System Restore may be disabled or none have been created yet)' -RecommendedValue 'System Restore enabled with recent restore points' -CIS_Control 'CIS 10.1' `
                -NIST_Control 'CP-9' -MITRE_Technique 'T1490 (Inhibit System Recovery)' -ISO27001_Control 'A.8.13' -NIS2_Article 'Art.21(2)(c)' `
                -Recommendation 'Enable System Protection for the system drive (sysdm.cpl > System Protection > Configure > Turn on system protection) as a supplementary local recovery layer alongside BitLocker and any centralized backup solution. Note: System Restore protects system/application state, not user documents - it is not a substitute for real backups.'
        }
    } catch {
        Add-AuditResult -Category 'Ransomware Recovery & Resilience' -Control 'System Restore Configuration' -Status 'WARN' -Severity 'Low' `
            -CurrentValue 'Query failed' -Recommendation "Unable to query System Restore configuration: $($_.Exception.Message)"
    }
}

#endregion

#region ============================== 27. ADVANCED NETWORK INTERFACE, CELLULAR & WI-FI SECURITY ==============================

function Test-WifiProfileSecurity {
    <#
        Audits every cached Wi-Fi profile via netsh wlan show profiles for weak
        authentication (Open, WEP, WPA-Personal/TKIP) and auto-connect behavior, plus the
        largely-deprecated Wi-Fi Sense auto-connect-to-suggested-hotspots policy where still
        present on managed builds.
    #>
    Write-SectionBanner 'Network Interface Security - Wi-Fi Profile Hardening'
    try {
        $profileListOutput = & netsh.exe wlan show profiles 2>$null
        if (-not $profileListOutput) {
            Add-AuditResult -Category 'Wireless & Network Interface Security' -Control 'Wi-Fi Profile Security' -Status 'INFO' -Severity 'Informational' `
                -CurrentValue 'No Wi-Fi adapter/profiles found, or WLAN AutoConfig service unavailable' -Recommendation 'Not applicable - no wireless capability detected.'
            return
        }
        $profileNames = @($profileListOutput | Select-String -Pattern '^\s*All User Profile\s*:\s*(.+)$' | ForEach-Object { $_.Matches[0].Groups[1].Value.Trim() })

        if ($profileNames.Count -eq 0) {
            Add-AuditResult -Category 'Wireless & Network Interface Security' -Control 'Wi-Fi Profile Security' -Status 'PASS' -Severity 'Medium' `
                -CurrentValue 'No cached Wi-Fi profiles found' -RecommendedValue 'No weak-authentication or unrestricted auto-connect profiles' -CIS_Control 'CIS 4.7' -NIST_Control 'SC-8, AC-18' `
                -MITRE_Technique 'T1557 (Adversary-in-the-Middle)' -ISO27001_Control 'A.8.20' -NIS2_Article 'Art.21(2)(d)' -Recommendation 'No action required.'
            return
        }

        $weakProfiles = [System.Collections.Generic.List[string]]::new()
        $autoConnectOpenProfiles = [System.Collections.Generic.List[string]]::new()
        foreach ($profileName in $profileNames) {
            try {
                $detail = & netsh.exe wlan show profile name="$profileName" 2>$null
                if (-not $detail) { continue }
                $authLine = $detail | Where-Object { $_ -match '(?i)^\s*Authentication\s*:' } | Select-Object -First 1
                $auth = if ($authLine) { ($authLine -split ':', 2)[1].Trim() } else { 'Unknown' }
                $connModeLine = $detail | Where-Object { $_ -match '(?i)^\s*Connection mode\s*:' } | Select-Object -First 1
                $connMode = if ($connModeLine) { ($connModeLine -split ':', 2)[1].Trim() } else { 'Unknown' }

                $isWeak = $auth -match '(?i)^Open$' -or $auth -match '(?i)WEP' -or $auth -match '(?i)^WPA-Personal$'
                if ($isWeak) { $weakProfiles.Add("$profileName [Auth=$auth]") }
                if (($auth -match '(?i)^Open$') -and ($connMode -match '(?i)Connect automatically')) {
                    $autoConnectOpenProfiles.Add("$profileName [Auto-connect to Open network]")
                }
            } catch { }
        }

        if ($weakProfiles.Count -eq 0) {
            Add-AuditResult -Category 'Wireless & Network Interface Security' -Control 'Wi-Fi Profile Security' -Status 'PASS' -Severity 'High' `
                -CurrentValue "$($profileNames.Count) cached profile(s) checked; none use Open/WEP/WPA-Personal(TKIP)" -RecommendedValue 'WPA2-Enterprise/WPA3 for corporate SSIDs; no Open/WEP/WPA1-Personal profiles' `
                -CIS_Control 'CIS 4.7' -NIST_Control 'SC-8, AC-18' -MITRE_Technique 'T1557 (Adversary-in-the-Middle)' -ISO27001_Control 'A.8.20' -NIS2_Article 'Art.21(2)(d)' -Recommendation 'No action required.'
        } else {
            Add-AuditResult -Category 'Wireless & Network Interface Security' -Control 'Wi-Fi Profile Security' -Status 'FAIL' -Severity 'High' `
                -CurrentValue ($weakProfiles -join ' | ') -RecommendedValue 'WPA2-Enterprise/WPA3 for corporate SSIDs; no Open/WEP/WPA1-Personal profiles' -CIS_Control 'CIS 4.7' -NIST_Control 'SC-8, AC-18' `
                -MITRE_Technique 'T1557 (Adversary-in-the-Middle)' -ISO27001_Control 'A.8.20' -NIS2_Article 'Art.21(2)(d)' -NSA_Guidance 'NSA/CISA Selecting Secure Remote Access Solutions' `
                -Recommendation "Remove cached profiles using Open/WEP/WPA-Personal authentication (netsh wlan delete profile name=`"<profile>`") unless there is a specific, low-risk business reason to retain them (e.g. a captive-portal guest network used only through a VPN). WEP is cryptographically broken; Open networks provide no confidentiality."
        }

        if ($autoConnectOpenProfiles.Count -gt 0) {
            Add-AuditResult -Category 'Wireless & Network Interface Security' -Control 'Auto-Connect to Open/Unvalidated Networks' -Status 'FAIL' -Severity 'High' `
                -CurrentValue ($autoConnectOpenProfiles -join ' | ') -RecommendedValue 'No profile auto-connects to an Open (unauthenticated) network' -CIS_Control 'CIS 4.7' -NIST_Control 'SC-8, AC-18' `
                -MITRE_Technique 'T1557 (Adversary-in-the-Middle)' -ISO27001_Control 'A.8.20' -NIS2_Article 'Art.21(2)(d)' -NSA_Guidance 'NSA/CISA Selecting Secure Remote Access Solutions' `
                -Recommendation "Change the listed profile(s) to connect manually only: netsh wlan set profileparameter name=`"<profile>`" connectionmode=manual. Auto-connecting to an open network is a classic evil-twin/rogue-AP attack vector - the endpoint will silently join any SSID matching the profile name, including an attacker-controlled one."
        }

        $wifiSenseValue = Get-RegistryValueSafe -Path 'HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots' -Name 'value' -DefaultValue $null
        if ($null -ne $wifiSenseValue) {
            if ($wifiSenseValue -eq 0) {
                Add-AuditResult -Category 'Wireless & Network Interface Security' -Control 'Wi-Fi Sense / Auto-Connect to Suggested Hotspots' -Status 'PASS' -Severity 'Medium' `
                    -CurrentValue 'Disabled' -RecommendedValue 'Disabled' -CIS_Control 'CIS 4.7' -NIST_Control 'SC-8' -ISO27001_Control 'A.8.20' -NIS2_Article 'Art.21(2)(d)' -Recommendation 'No action required.'
            } else {
                Add-AuditResult -Category 'Wireless & Network Interface Security' -Control 'Wi-Fi Sense / Auto-Connect to Suggested Hotspots' -Status 'FAIL' -Severity 'Medium' `
                    -CurrentValue 'Enabled' -RecommendedValue 'Disabled' -CIS_Control 'CIS 4.7' -NIST_Control 'SC-8' -ISO27001_Control 'A.8.20' -NIS2_Article 'Art.21(2)(d)' `
                    -Recommendation 'Disable "Allow Windows to automatically connect to suggested open hotspots" via GPO/Intune Wi-Fi CSP - auto-joining crowd-sourced/suggested hotspots exposes the endpoint to rogue access points.'
            }
        } else {
            Add-AuditResult -Category 'Wireless & Network Interface Security' -Control 'Wi-Fi Sense / Auto-Connect to Suggested Hotspots' -Status 'INFO' -Severity 'Informational' `
                -CurrentValue 'Policy not present (feature deprecated on current Windows releases)' -RecommendedValue 'Disabled where the underlying feature still exists' `
                -Recommendation 'Wi-Fi Sense-style auto-connect-to-suggested-hotspots was deprecated in modern Windows releases; absence of this policy is expected and not itself a finding.'
        }
    } catch {
        Add-AuditResult -Category 'Wireless & Network Interface Security' -Control 'Wi-Fi Profile Security' -Status 'WARN' -Severity 'Low' `
            -CurrentValue 'Query failed' -Recommendation "Unable to complete Wi-Fi profile audit: $($_.Exception.Message)"
    }
}

function Test-ConnectionManagerDualHoming {
    <#
        Audits the Windows Connection Manager "fBlockNonDomain" policy, which prevents a
        device simultaneously connected to a trusted domain/corporate network from also
        maintaining a connection to an untrusted Wi-Fi/cellular network - closing off a
        network-bridging path an attacker on the untrusted side could otherwise pivot
        through into the corporate segment.
    #>
    Write-SectionBanner 'Network Interface Security - Connection Manager Dual-Homing Prevention'
    try {
        $wcmPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy'
        $fBlockNonDomain = Get-RegistryValueSafe -Path $wcmPath -Name 'fBlockNonDomain' -DefaultValue $null

        if ($fBlockNonDomain -eq 1) {
            Add-AuditResult -Category 'Wireless & Network Interface Security' -Control 'Connection Manager - Block Non-Domain Networks (Dual-Homing Prevention)' -Status 'PASS' -Severity 'High' `
                -CurrentValue 'fBlockNonDomain=1 (Enabled)' -RecommendedValue '1' -CIS_Control 'CIS 4.7' -NIST_Control 'SC-7, AC-4' `
                -MITRE_Technique 'T1090 (Proxy), T1557 (Adversary-in-the-Middle)' -ISO27001_Control 'A.8.20' -NIS2_Article 'Art.21(2)(d)' -NSA_Guidance 'NSA/CISA Reduce Exposure - Network Protocol Poisoning' `
                -Recommendation 'No action required.'
        } else {
            Add-AuditResult -Category 'Wireless & Network Interface Security' -Control 'Connection Manager - Block Non-Domain Networks (Dual-Homing Prevention)' -Status 'FAIL' -Severity 'High' `
                -CurrentValue 'Not Configured / Disabled' -RecommendedValue '1' -CIS_Control 'CIS 4.7' -NIST_Control 'SC-7, AC-4' -MITRE_Technique 'T1090 (Proxy), T1557 (Adversary-in-the-Middle)' `
                -ISO27001_Control 'A.8.20' -NIS2_Article 'Art.21(2)(d)' -NSA_Guidance 'NSA/CISA Reduce Exposure - Network Protocol Poisoning' `
                -Recommendation 'Enable GPO "Prohibit connection to non-domain networks when connected to a domain authenticated network" (Computer Configuration > Administrative Templates > Network > Windows Connection Manager), which sets fBlockNonDomain=1. Without it, a laptop bridging corporate Ethernet/VPN and an untrusted Wi-Fi/cellular connection simultaneously can be used as an unwitting network pivot point.'
        }
    } catch {
        Add-AuditResult -Category 'Wireless & Network Interface Security' -Control 'Connection Manager Dual-Homing Prevention' -Status 'WARN' -Severity 'Low' `
            -CurrentValue 'Query failed' -Recommendation "Unable to query Connection Manager policy: $($_.Exception.Message)"
    }
}

function Test-Wired8021XEnforcement {
    <#
        Audits Wired AutoConfig (dot3svc) service state and per-adapter 802.1X profile
        configuration. Reported informationally rather than as a hard PASS/FAIL, since
        802.1X on wired ports is environment-dependent (not every network uses NAC) - the
        goal is visibility into whether the capability is present and configured where it
        matters.
    #>
    Write-SectionBanner 'Network Interface Security - Wired 802.1X Network Authentication'
    try {
        $svc = Get-Service -Name 'dot3svc' -ErrorAction SilentlyContinue
        if (-not $svc) {
            Add-AuditResult -Category 'Wireless & Network Interface Security' -Control 'Wired 802.1X Network Authentication' -Status 'INFO' -Severity 'Informational' `
                -CurrentValue 'Wired AutoConfig service not found' -Recommendation 'Not applicable on this SKU/build.'
            return
        }

        $lanProfiles = $null
        try { $lanProfiles = & netsh.exe lan show profiles 2>$null } catch { $lanProfiles = $null }
        $hasProfiles = $lanProfiles -and ($lanProfiles -match '(?i)Profile')

        if ($svc.Status -eq 'Running' -and $hasProfiles) {
            Add-AuditResult -Category 'Wireless & Network Interface Security' -Control 'Wired 802.1X Network Authentication' -Status 'PASS' -Severity 'Medium' `
                -CurrentValue 'Wired AutoConfig running; at least one wired 802.1X profile configured' -RecommendedValue 'Configured where Network Access Control (NAC) is required for wired ports' `
                -CIS_Control 'CIS 4.7' -NIST_Control 'AC-18, IA-3' -MITRE_Technique 'T1200 (Hardware Additions)' -ISO27001_Control 'A.8.20' -NIS2_Article 'Art.21(2)(d)' -Recommendation 'No action required.'
        } else {
            Add-AuditResult -Category 'Wireless & Network Interface Security' -Control 'Wired 802.1X Network Authentication' -Status 'INFO' -Severity 'Informational' `
                -CurrentValue "dot3svc Status=$($svc.Status); Wired 802.1X profile(s) configured=$hasProfiles" -RecommendedValue 'Configured where Network Access Control (NAC) is required for wired ports' `
                -Recommendation 'Not every environment requires 802.1X on wired ports. If this network uses NAC/port-based authentication for Ethernet, ensure dot3svc is running and a matching wired profile is deployed via GPO/Intune (Wired Network (IEEE 802.3) Policies); otherwise no action is required.'
        }
    } catch {
        Add-AuditResult -Category 'Wireless & Network Interface Security' -Control 'Wired 802.1X Network Authentication' -Status 'WARN' -Severity 'Low' `
            -CurrentValue 'Query failed' -Recommendation "Unable to complete wired 802.1X audit: $($_.Exception.Message)"
    }
}

function Test-IPv6TransitionProtocols {
    <#
        Audits legacy IPv6 transition/tunneling technologies (Teredo, 6to4, ISATAP) via
        their dedicated netsh interface state queries. These create IPv6 tunnels over IPv4
        that most network monitoring/firewall tooling does not inspect, functioning as an
        unmonitored covert channel if left enabled - a long-standing DISA STIG and hardening-
        guide finding.
    #>
    Write-SectionBanner 'Network Interface Security - IPv6 Transition Protocol Exposure'
    $transitionChecks = @(
        @{ Name = 'Teredo'; Command = 'teredo' }
        @{ Name = '6to4';   Command = '6to4' }
        @{ Name = 'ISATAP'; Command = 'isatap' }
    )
    foreach ($t in $transitionChecks) {
        try {
            $stateOutput = & netsh.exe interface $t.Command show state 2>$null
            if (-not $stateOutput) { throw "netsh interface $($t.Command) show state returned no output" }
            $stateLine = $stateOutput | Where-Object { $_ -match '(?i)^\s*State\s*:' } | Select-Object -First 1
            $state = if ($stateLine) { ($stateLine -split ':', 2)[1].Trim() } else { 'Unknown' }

            if ($state -match '(?i)disabled') {
                Add-AuditResult -Category 'Wireless & Network Interface Security' -Control "IPv6 Transition Protocol - $($t.Name)" -Status 'PASS' -Severity 'Medium' `
                    -CurrentValue $state -RecommendedValue 'Disabled' -CIS_Control 'CIS 4.7' -NIST_Control 'SC-7, CM-7' -MITRE_Technique 'T1572 (Protocol Tunneling)' -ISO27001_Control 'A.8.20' `
                    -NIS2_Article 'Art.21(2)(d)' -Recommendation 'No action required.'
            } else {
                Add-AuditResult -Category 'Wireless & Network Interface Security' -Control "IPv6 Transition Protocol - $($t.Name)" -Status 'FAIL' -Severity 'Medium' `
                    -CurrentValue $state -RecommendedValue 'Disabled' -CIS_Control 'CIS 4.7' -NIST_Control 'SC-7, CM-7' -MITRE_Technique 'T1572 (Protocol Tunneling)' -ISO27001_Control 'A.8.20' `
                    -NIS2_Article 'Art.21(2)(d)' -NSA_Guidance 'NSA/CISA Reduce Exposure - Network Protocol Poisoning' `
                    -Recommendation "Disable via: netsh interface $($t.Command) set state disabled. $($t.Name) tunnels IPv6 traffic over IPv4 in a way most perimeter and host-based monitoring does not inspect by default, functioning as an unmonitored covert channel if an attacker establishes one."
            }
        } catch {
            Add-AuditResult -Category 'Wireless & Network Interface Security' -Control "IPv6 Transition Protocol - $($t.Name)" -Status 'WARN' -Severity 'Low' `
                -CurrentValue 'Query failed' -Recommendation "Unable to query $($t.Name) state: $($_.Exception.Message)"
        }
    }
}

#endregion

#region ============================== 28. CONTAINERIZATION, WSL & HYPER-V ESCAPE VECTORS ==============================

function Test-WSLConfiguration {
    <#
        Audits whether Windows Subsystem for Linux is installed and, if so, enumerates
        installed distributions and their WSL version. WSL introduces a Linux userspace and
        a host/guest filesystem bridge (\\wsl$ and /mnt/c automount) that historically sat
        outside traditional Windows AV/EDR file-system hooks - this is reported as an
        attack-surface awareness item rather than an automatic hard failure, since WSL is
        legitimate developer tooling in many environments.
    #>
    Write-SectionBanner 'Virtualization - Windows Subsystem for Linux (WSL)'
    try {
        $wslFeature = $null
        try { $wslFeature = Get-WindowsOptionalFeature -Online -FeatureName 'Microsoft-Windows-Subsystem-Linux' -ErrorAction Stop } catch { $wslFeature = $null }
        $wslInstalled = $wslFeature -and $wslFeature.State -eq 'Enabled'

        if (-not $wslInstalled) {
            Add-AuditResult -Category 'Virtualization & Container Escape Surface' -Control 'Windows Subsystem for Linux (WSL) Presence' -Status 'PASS' -Severity 'Medium' `
                -CurrentValue 'Not installed' -RecommendedValue 'Not installed unless required for a documented development/business need' -CIS_Control 'CIS 4.1' -NIST_Control 'CM-7' `
                -MITRE_Technique 'T1609 (Container Administration Command)' -ISO27001_Control 'A.8.19' -NIS2_Article 'Art.21(2)(e)' -Recommendation 'No action required.'
            return
        }

        $distroOutput = $null
        try { $distroOutput = & wsl.exe --list --verbose 2>$null } catch { $distroOutput = $null }
        $distroLines = @()
        if ($distroOutput) {
            $distroLines = $distroOutput | Where-Object { $_ -and ($_ -notmatch '(?i)^\s*NAME\s+STATE\s+VERSION') } | ForEach-Object { ($_ -replace "`0", '').Trim() } | Where-Object { $_ -ne '' }
        }

        if ($distroLines.Count -eq 0) {
            Add-AuditResult -Category 'Virtualization & Container Escape Surface' -Control 'Windows Subsystem for Linux (WSL) Presence' -Status 'WARN' -Severity 'Medium' `
                -CurrentValue 'WSL feature installed; no distributions currently registered' -RecommendedValue 'Removed if not actively required' -CIS_Control 'CIS 4.1' -NIST_Control 'CM-7' `
                -MITRE_Technique 'T1609 (Container Administration Command)' -ISO27001_Control 'A.8.19' -NIS2_Article 'Art.21(2)(e)' `
                -Recommendation 'The WSL feature is enabled but no distribution is installed. If not actively needed, disable the feature: Disable-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux to reduce attack surface.'
        } else {
            $usesWsl1 = $distroLines -match '\s1\s*$'
            Add-AuditResult -Category 'Virtualization & Container Escape Surface' -Control 'Windows Subsystem for Linux (WSL) Presence' -Status 'WARN' -Severity 'Medium' `
                -CurrentValue "Installed distribution(s): $($distroLines -join ' | ')" -RecommendedValue 'Present only where required; MDE WSL sensor integration verified (see next finding)' -CIS_Control 'CIS 4.1' `
                -NIST_Control 'CM-7, SI-4' -MITRE_Technique 'T1609 (Container Administration Command)' -ISO27001_Control 'A.8.19' -NIS2_Article 'Art.21(2)(e)' -NSA_Guidance 'NSA/CISA Guidance on Endpoint Detection and Response' `
                -Recommendation 'WSL bridges the Windows host filesystem into the Linux guest (Linux binaries under /mnt/c can read/write host files with the invoking user''s Windows permissions) and exposes the guest filesystem back to Windows via \\wsl$. Confirm this is required for this user''s role, and verify Microsoft Defender for Endpoint has WSL sensor integration enabled (see next finding) so Linux-side activity is not a blind spot.'
            if ($usesWsl1) {
                Add-AuditResult -Category 'Virtualization & Container Escape Surface' -Control 'WSL Version (WSL1 vs WSL2)' -Status 'INFO' -Severity 'Informational' `
                    -CurrentValue 'One or more distributions are running under WSL1' -RecommendedValue 'WSL2 (stronger isolation via a lightweight VM boundary; also required for MDE WSL sensor support)' `
                    -Recommendation 'WSL1 translates Linux syscalls directly against the Windows kernel with no VM boundary. WSL2 runs inside a lightweight Hyper-V-backed VM, providing a real isolation boundary and is required for Microsoft Defender for Endpoint''s WSL sensor. Upgrade with: wsl --set-version <distro> 2.'
            }
        }
    } catch {
        Add-AuditResult -Category 'Virtualization & Container Escape Surface' -Control 'Windows Subsystem for Linux (WSL) Presence' -Status 'WARN' -Severity 'Low' `
            -CurrentValue 'Query failed' -Recommendation "Unable to complete WSL audit: $($_.Exception.Message)"
    }
}

function Test-WSLMDESensorIntegration {
    <#
        Notes whether MDE's WSL sensor integration should be verified for this endpoint.
        There is no reliably documented local registry/service surface to positively confirm
        this specific integration's enabled state offline, so this is reported as guidance
        toward the authoritative source (the Microsoft 365 Defender portal / device
        configuration) rather than a fabricated local PASS/FAIL.
    #>
    Write-SectionBanner 'Virtualization - MDE WSL Sensor Integration'
    try {
        $wslFeature = $null
        try { $wslFeature = Get-WindowsOptionalFeature -Online -FeatureName 'Microsoft-Windows-Subsystem-Linux' -ErrorAction Stop } catch { $wslFeature = $null }
        if (-not $wslFeature -or $wslFeature.State -ne 'Enabled') {
            Add-AuditResult -Category 'Virtualization & Container Escape Surface' -Control 'MDE WSL Sensor Integration' -Status 'INFO' -Severity 'Informational' `
                -CurrentValue 'WSL is not installed' -Recommendation 'Not applicable.'
            return
        }

        $senseService = Get-Service -Name 'Sense' -ErrorAction SilentlyContinue
        $mdeOnboarded = ($senseService -and $senseService.Status -eq 'Running')

        Add-AuditResult -Category 'Virtualization & Container Escape Surface' -Control 'MDE WSL Sensor Integration' -Status 'INFO' -Severity 'Informational' `
            -CurrentValue "WSL is installed; MDE Sense service running=$mdeOnboarded. WSL-sensor-specific enablement state is not reliably visible from local registry/service checks." `
            -RecommendedValue 'MDE onboarded (see MDE Onboarding finding) with WSL sensor integration confirmed enabled in the Microsoft 365 Defender portal' -CIS_Control 'CIS 4.1' -NIST_Control 'SI-4' `
            -MITRE_Technique 'T1609 (Container Administration Command)' -ISO27001_Control 'A.8.16' -NIS2_Article 'Art.21(2)(b)' -NSA_Guidance 'NSA/CISA Guidance on Endpoint Detection and Response' `
            -Recommendation 'Since WSL is present on this endpoint, verify in the Microsoft 365 Defender portal (Settings > Endpoints > Advanced features > Linux/WSL) that Defender for Endpoint''s WSL sensor is enabled for this device group, so process/file activity inside WSL distributions is captured rather than being an EDR blind spot.'
    } catch {
        Add-AuditResult -Category 'Virtualization & Container Escape Surface' -Control 'MDE WSL Sensor Integration' -Status 'WARN' -Severity 'Low' `
            -CurrentValue 'Query failed' -Recommendation "Unable to complete MDE WSL sensor check: $($_.Exception.Message)"
    }
}

function Test-WindowsSandboxConfiguration {
    <#
        Audits Windows Sandbox feature installation. Sandbox instances are ephemeral and
        isolated by default, but ship with networking enabled and (for any explicit .wsb
        configuration used) can be configured with host folder mappings - this check reports
        enablement and points toward hardened .wsb template distribution rather than
        asserting a specific runtime policy this audit cannot see (Sandbox has no persistent
        system-wide configuration; each launch is defined by its own .wsb file).
    #>
    Write-SectionBanner 'Virtualization - Windows Sandbox'
    try {
        $sandboxFeature = $null
        try { $sandboxFeature = Get-WindowsOptionalFeature -Online -FeatureName 'Containers-DisposableClientVM' -ErrorAction Stop } catch { $sandboxFeature = $null }

        if (-not $sandboxFeature -or $sandboxFeature.State -ne 'Enabled') {
            Add-AuditResult -Category 'Virtualization & Container Escape Surface' -Control 'Windows Sandbox' -Status 'PASS' -Severity 'Low' `
                -CurrentValue 'Not installed' -RecommendedValue 'Not installed unless required for a documented need' -CIS_Control 'CIS 4.1' -NIST_Control 'CM-7' -ISO27001_Control 'A.8.19' `
                -NIS2_Article 'Art.21(2)(e)' -Recommendation 'No action required.'
        } else {
            Add-AuditResult -Category 'Virtualization & Container Escape Surface' -Control 'Windows Sandbox' -Status 'INFO' -Severity 'Informational' `
                -CurrentValue 'Installed' -RecommendedValue 'Installed only where required; hardened .wsb templates used for high-risk tasks' -CIS_Control 'CIS 4.1' -NIST_Control 'CM-7' -ISO27001_Control 'A.8.19' `
                -NIS2_Article 'Art.21(2)(e)' `
                -Recommendation 'Windows Sandbox has no persistent system-wide policy - each session is defined by the .wsb configuration file used to launch it, and networking is enabled by default unless the launching .wsb explicitly sets <Networking>Disable</Networking>. If Sandbox is used to open untrusted content/links, distribute a hardened .wsb template (networking disabled, no host folder mappings, vGPU disabled) rather than relying on the ad hoc default.'
        }
    } catch {
        Add-AuditResult -Category 'Virtualization & Container Escape Surface' -Control 'Windows Sandbox' -Status 'WARN' -Severity 'Low' `
            -CurrentValue 'Query failed' -Recommendation "Unable to query Windows Sandbox feature state: $($_.Exception.Message)"
    }
}

function Test-WindowsDefenderApplicationGuard {
    <#
        Audits Windows Defender Application Guard (WDAG) feature installation and, where
        installed, its container hardening policy (session persistence, clipboard/print/
        camera-microphone redirection). WDAG isolates untrusted browser content in a
        hardware-virtualized, disposable container; enabling persistence retains container
        state (downloaded files, cookies) across sessions and materially weakens that
        isolation guarantee, similar in spirit to the Windows Sandbox check above.
    #>
    Write-SectionBanner 'Virtualization - Windows Defender Application Guard'
    try {
        $wdagFeature = $null
        try { $wdagFeature = Get-WindowsOptionalFeature -Online -FeatureName 'Windows-Defender-ApplicationGuard' -ErrorAction Stop } catch { $wdagFeature = $null }

        if (-not $wdagFeature -or $wdagFeature.State -ne 'Enabled') {
            Add-AuditResult -Category 'Virtualization & Container Escape Surface' -Control 'Windows Defender Application Guard' -Status 'INFO' -Severity 'Informational' `
                -CurrentValue 'Not installed' -RecommendedValue 'Installed and enforced where the organization relies on browser isolation for untrusted/high-risk web content' -CIS_Control 'CIS 9.6' `
                -NIST_Control 'SC-7, SC-39' -ISO27001_Control 'A.8.23' -NIS2_Article 'Art.21(2)(e)' `
                -Recommendation 'Not installed by default and not required on every endpoint. Consider enabling for users who routinely handle high-risk/untrusted links or attachments, since it isolates that activity in a hardware-virtualized, disposable container separate from the host OS.'
            return
        }

        $policyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI'
        $persistence = Get-RegistryValueSafe -Path $policyPath -Name 'AllowPersistence' -DefaultValue $null
        $clipboard = Get-RegistryValueSafe -Path $policyPath -Name 'ClipboardFileType' -DefaultValue $null
        $camMic = Get-RegistryValueSafe -Path $policyPath -Name 'AllowCameraMicrophoneRedirection' -DefaultValue $null
        $printing = Get-RegistryValueSafe -Path $policyPath -Name 'AllowPrinting' -DefaultValue $null

        $configSummary = "Persistence=$(if ($null -ne $persistence) { $persistence } else { 'Not Configured (default: disabled)' }); ClipboardFileType=$(if ($null -ne $clipboard) { $clipboard } else { 'Not Configured' }); CameraMicRedirection=$(if ($null -ne $camMic) { $camMic } else { 'Not Configured (default: disabled)' }); Printing=$(if ($null -ne $printing) { $printing } else { 'Not Configured (default: disabled)' })"

        if ($persistence -eq 1) {
            Add-AuditResult -Category 'Virtualization & Container Escape Surface' -Control 'Windows Defender Application Guard' -Status 'WARN' -Severity 'Medium' `
                -CurrentValue $configSummary -RecommendedValue 'AllowPersistence Disabled (0) - each WDAG session should reset to a clean state' -CIS_Control 'CIS 9.6' `
                -NIST_Control 'SC-7, SC-39' -MITRE_Technique 'T1611 (Escape to Host)' -ISO27001_Control 'A.8.23' -NIS2_Article 'Art.21(2)(e)' `
                -Recommendation 'WDAG is installed with session persistence enabled, which retains container state (downloaded files, cookies, browsing data) across sessions - this weakens the disposable, always-clean isolation guarantee that is WDAG''s main security value. Set AllowPersistence to 0 via policy unless a specific workflow requires it.'
        } else {
            Add-AuditResult -Category 'Virtualization & Container Escape Surface' -Control 'Windows Defender Application Guard' -Status 'INFO' -Severity 'Informational' `
                -CurrentValue $configSummary -RecommendedValue 'Persistence disabled; clipboard/camera-mic/print redirection limited to what the workflow actually requires' -CIS_Control 'CIS 9.6' `
                -NIST_Control 'SC-7, SC-39' -ISO27001_Control 'A.8.23' -NIS2_Article 'Art.21(2)(e)' `
                -Recommendation 'Installed and not configured for persistence. Review the clipboard/camera-microphone/print redirection settings above against actual business need - each enabled redirection channel is a narrow but real path between the isolated container and the host.'
        }
    } catch {
        Add-AuditResult -Category 'Virtualization & Container Escape Surface' -Control 'Windows Defender Application Guard' -Status 'WARN' -Severity 'Low' `
            -CurrentValue 'Query failed' -Recommendation "Unable to query Windows Defender Application Guard feature/policy state: $($_.Exception.Message)"
    }
}

function Test-HyperVVirtualSwitchSecurity {
    <#
        Audits Hyper-V virtual switches and, where any VM network adapters exist, whether
        MAC address spoofing is allowed on them - a setting that lets a guest VM impersonate
        another device's MAC address on the virtual network, facilitating ARP-spoofing-style
        attacks against sibling VMs or the host's bridged network segment.
    #>
    Write-SectionBanner 'Virtualization - Hyper-V Virtual Switch Security'
    try {
        $hyperVFeature = $null
        try { $hyperVFeature = Get-WindowsOptionalFeature -Online -FeatureName 'Microsoft-Hyper-V-All' -ErrorAction Stop } catch { $hyperVFeature = $null }
        $hyperVEnabled = $hyperVFeature -and $hyperVFeature.State -eq 'Enabled'

        if (-not $hyperVEnabled) {
            Add-AuditResult -Category 'Virtualization & Container Escape Surface' -Control 'Hyper-V Virtual Switch Security' -Status 'INFO' -Severity 'Informational' `
                -CurrentValue 'Hyper-V is not installed' -Recommendation 'Not applicable. Note: WSL2''s lightweight utility VM uses a minimal Hyper-V platform component independent of the full Hyper-V role and is not evaluated by this check.'
            return
        }

        $switches = $null
        try { $switches = @(Get-VMSwitch -ErrorAction Stop) } catch { $switches = @() }

        if ($switches.Count -eq 0) {
            Add-AuditResult -Category 'Virtualization & Container Escape Surface' -Control 'Hyper-V Virtual Switch Security' -Status 'PASS' -Severity 'Medium' `
                -CurrentValue 'Hyper-V installed; no virtual switches configured' -RecommendedValue 'No virtual switches unless actively required' -CIS_Control 'CIS 4.1' -NIST_Control 'SC-7, CM-7' `
                -ISO27001_Control 'A.8.20' -NIS2_Article 'Art.21(2)(d)' -Recommendation 'No action required.'
            return
        }

        $switchSummary = ($switches | ForEach-Object { "$($_.Name) [$($_.SwitchType)]" }) -join ', '
        Add-AuditResult -Category 'Virtualization & Container Escape Surface' -Control 'Hyper-V Virtual Switch Inventory' -Status 'INFO' -Severity 'Informational' `
            -CurrentValue "$($switches.Count) switch(es): $switchSummary" -RecommendedValue 'External switches limited to those with a documented business need' -CIS_Control 'CIS 4.1' -NIST_Control 'SC-7, CM-7' `
            -ISO27001_Control 'A.8.20' -NIS2_Article 'Art.21(2)(d)' -Recommendation 'Review each External-type switch for business justification - it bridges VM traffic onto the physical network segment.'

        $spoofingAdapters = $null
        try { $spoofingAdapters = @(Get-VMNetworkAdapter -VMName * -ErrorAction Stop | Where-Object { $_.MacAddressSpoofing -eq 'On' }) } catch { $spoofingAdapters = @() }

        if ($spoofingAdapters.Count -eq 0) {
            Add-AuditResult -Category 'Virtualization & Container Escape Surface' -Control 'Hyper-V MAC Address Spoofing' -Status 'PASS' -Severity 'Medium' `
                -CurrentValue 'No VM network adapter has MAC address spoofing enabled' -RecommendedValue 'Disabled unless a specific VM (e.g. a network appliance/NLB node) requires it' -CIS_Control 'CIS 4.1' `
                -NIST_Control 'SC-7, AC-4' -MITRE_Technique 'T1557 (Adversary-in-the-Middle)' -ISO27001_Control 'A.8.20' -NIS2_Article 'Art.21(2)(d)' -Recommendation 'No action required.'
        } else {
            $names = ($spoofingAdapters | ForEach-Object { "$($_.VMName)/$($_.Name)" }) -join ', '
            Add-AuditResult -Category 'Virtualization & Container Escape Surface' -Control 'Hyper-V MAC Address Spoofing' -Status 'WARN' -Severity 'Medium' `
                -CurrentValue "MAC spoofing enabled on: $names" -RecommendedValue 'Disabled unless a specific VM requires it' -CIS_Control 'CIS 4.1' -NIST_Control 'SC-7, AC-4' `
                -MITRE_Technique 'T1557 (Adversary-in-the-Middle)' -ISO27001_Control 'A.8.20' -NIS2_Article 'Art.21(2)(d)' `
                -Recommendation "Disable unless explicitly required (e.g. a network load-balancer/appliance VM): Set-VMNetworkAdapter -VMName <name> -MacAddressSpoofing Off. A VM permitted to spoof its MAC address can impersonate another device on the virtual/bridged network segment."
        }
    } catch {
        Add-AuditResult -Category 'Virtualization & Container Escape Surface' -Control 'Hyper-V Virtual Switch Security' -Status 'WARN' -Severity 'Low' `
            -CurrentValue 'Query failed' -Recommendation "Unable to complete Hyper-V virtual switch audit: $($_.Exception.Message)"
    }
}

#endregion

#region ============================== 29. INSECURE TEMPORARY FILES, UNATTENDED SCRIPTS & SECRET LEAKS ==============================

function Get-UserProfileDirectories {
    <# Enumerates real user profile directories under C:\Users, excluding shared/system profiles, cached for reuse. #>
    if ($null -eq $Script:UserProfileDirsCache) {
        try {
            $excluded = @('Public', 'Default', 'Default User', 'All Users', 'defaultuser0')
            $Script:UserProfileDirsCache = @(Get-ChildItem -LiteralPath 'C:\Users' -Directory -ErrorAction SilentlyContinue | Where-Object { $excluded -notcontains $_.Name } | Select-Object -ExpandProperty FullName)
        } catch { $Script:UserProfileDirsCache = @() }
    }
    return $Script:UserProfileDirsCache
}

function Test-ExportablePrivateKeyCertificates {
    <#
        Audits the Machine and User "My" (Personal) certificate stores for exportable
        private keys, and the Root trusted-authority stores for self-signed certificates.
        An exportable private key can be extracted by anyone with access to the profile/
        machine store, whereas a non-exportable (hardware- or CSP-protected) key cannot be
        exfiltrated even by a local administrator in some configurations.
    #>
    Write-SectionBanner 'Credential Exposure - Certificate Store Exportable Private Keys'
    try {
        $storesToCheck = @('Cert:\LocalMachine\My', 'Cert:\CurrentUser\My')
        $exportableFound = [System.Collections.Generic.List[string]]::new()
        $totalWithPrivateKey = 0

        foreach ($storePath in $storesToCheck) {
            try {
                $certs = @(Get-ChildItem -Path $storePath -ErrorAction SilentlyContinue | Where-Object { $_.HasPrivateKey })
                foreach ($cert in $certs) {
                    $totalWithPrivateKey++
                    $isExportable = $false
                    try {
                        if ($cert.PrivateKey -and $cert.PrivateKey.CspKeyContainerInfo) {
                            $isExportable = [bool]$cert.PrivateKey.CspKeyContainerInfo.Exportable
                        }
                    } catch { $isExportable = $false }
                    if ($isExportable) {
                        $exportableFound.Add("$storePath\$($cert.Thumbprint) [Subject=$($cert.Subject)]")
                    }
                }
            } catch { }
        }

        if ($exportableFound.Count -eq 0) {
            Add-AuditResult -Category 'Credential Exposure & Secret Leaks' -Control 'Certificate Store Exportable Private Keys' -Status 'PASS' -Severity 'Medium' `
                -CurrentValue "$totalWithPrivateKey certificate(s) with a private key checked; none flagged as exportable" -RecommendedValue 'Non-exportable private keys, especially for authentication/signing certificates' `
                -CIS_Control 'CIS 3.6' -NIST_Control 'SC-12, SC-28' -MITRE_Technique 'T1552.004 (Private Keys)' -ISO27001_Control 'A.8.24' -NIS2_Article 'Art.21(2)(h)' `
                -Recommendation 'No action required.'
        } else {
            Add-AuditResult -Category 'Credential Exposure & Secret Leaks' -Control 'Certificate Store Exportable Private Keys' -Status 'WARN' -Severity 'High' `
                -CurrentValue (($exportableFound | Select-Object -First 10) -join ' | ') -RecommendedValue 'Non-exportable private keys, especially for authentication/signing certificates' -CIS_Control 'CIS 3.6' `
                -NIST_Control 'SC-12, SC-28' -MITRE_Technique 'T1552.004 (Private Keys)' -ISO27001_Control 'A.8.24' -NIS2_Article 'Art.21(2)(h)' -NSA_Guidance 'NSA CSI: CNSA 2.0 Cryptographic Guidance' `
                -Recommendation 'Review each listed certificate. If it is used for authentication, code signing, or document signing, re-issue/re-import it with the private key marked non-exportable (or generated directly in a TPM/HSM-backed CSP), so the key cannot be trivially extracted by copying the certificate store.'
        }

        # Every entry in a Root store is self-signed by definition (Subject == Issuer) - that
        # alone doesn't distinguish a rogue CA from DigiCert/GlobalSign/etc. Match against a
        # broader allowlist of known public CAs and known corporate TLS-inspection vendors
        # (legitimate reasons for a non-major root to be present) instead, and treat a
        # recently-added unrecognized root as higher priority than a long-standing one.
        $knownCaPattern = '(?i)(microsoft|digicert|sectigo|comodo|globalsign|verisign|symantec|godaddy|go daddy|entrust|amazon|google trust|isrg|internet security research|baltimore|thawte|geotrust|usertrust|aaa certificate|quovadis|actalis|buypass|certum|ssl\.com|identrust|t-systems|d-trust|swisssign|apple|mozilla|starfield|network solutions|certplus|certigna|firmaprofesional|hongkong post|japan certification|taiwan-ca|e-tugra|dhimyotis|asseco|disig|adobe|visa|mastercard|deutsche telekom|telia|kpn|chunghwa|certsign|e-szigno)'
        $knownInterceptionPattern = '(?i)(zscaler|netskope|palo ?alto|cisco umbrella|opendns|bluecoat|blue coat|proxysg|forcepoint|websense|mcafee|trellix|fortinet|fortigate|sophos|kaspersky|avast|avg technologies|eset|bitdefender|malwarebytes|crowdstrike|check ?point|barracuda|sonicwall|watchguard|ironport|menlo security|iboss)'

        $unrecognizedRecent = [System.Collections.Generic.List[string]]::new()
        $unrecognizedOlder = [System.Collections.Generic.List[string]]::new()
        $rootCertsChecked = 0

        foreach ($rootStorePath in @('Cert:\LocalMachine\Root', 'Cert:\CurrentUser\Root')) {
            try {
                $rootCerts = @(Get-ChildItem -Path $rootStorePath -ErrorAction SilentlyContinue | Where-Object { $_.Subject -eq $_.Issuer })
                foreach ($rc in $rootCerts) {
                    $rootCertsChecked++
                    if ($rc.Subject -match $knownCaPattern -or $rc.Subject -match $knownInterceptionPattern) { continue }
                    $ageDays = ((Get-Date) - $rc.NotBefore).TotalDays
                    $entry = "$rootStorePath\$($rc.Thumbprint) [Subject=$($rc.Subject); NotBefore=$($rc.NotBefore.ToString('yyyy-MM-dd'))]"
                    if ($ageDays -ge 0 -and $ageDays -le 90) { $unrecognizedRecent.Add($entry) } else { $unrecognizedOlder.Add($entry) }
                }
            } catch { }
        }

        if ($unrecognizedRecent.Count -eq 0 -and $unrecognizedOlder.Count -eq 0) {
            Add-AuditResult -Category 'Credential Exposure & Secret Leaks' -Control 'Unrecognized Root Certificate Authorities' -Status 'PASS' -Severity 'Medium' `
                -CurrentValue "$rootCertsChecked root CA(s) checked; all matched a known public CA or corporate TLS-inspection vendor" -RecommendedValue 'Only recognized/approved root certificates present' `
                -CIS_Control 'CIS 3.6' -NIST_Control 'SC-17, SC-23' -MITRE_Technique 'T1553.004 (Install Root Certificate)' -ISO27001_Control 'A.8.24' -NIS2_Article 'Art.21(2)(h)' -Recommendation 'No action required.'
        } elseif ($unrecognizedRecent.Count -gt 0) {
            Add-AuditResult -Category 'Credential Exposure & Secret Leaks' -Control 'Unrecognized Root Certificate Authorities' -Status 'WARN' -Severity 'High' `
                -CurrentValue "$($unrecognizedRecent.Count) unrecognized root CA(s) added within the last 90 days: $($unrecognizedRecent -join ' | ')$(if ($unrecognizedOlder.Count -gt 0) { " | Plus $($unrecognizedOlder.Count) older unrecognized: $(($unrecognizedOlder | Select-Object -First 10) -join ' | ')" })" `
                -RecommendedValue 'Only recognized/approved root certificates present, especially none added recently' -CIS_Control 'CIS 3.6' -NIST_Control 'SC-17, SC-23' `
                -MITRE_Technique 'T1553.004 (Install Root Certificate), T1557 (Adversary-in-the-Middle)' -ISO27001_Control 'A.8.24' -NIS2_Article 'Art.21(2)(h)' -NSA_Guidance 'NSA CSI: Mitigating Credential Theft' `
                -Recommendation 'Investigate each unrecognized root CA, prioritizing the recently-added one(s) first. A root CA installed outside the OS-default set can be legitimate (internal enterprise PKI, an approved TLS-inspection proxy) - confirm it was deliberately and knowingly installed; if not, remove it via certlm.msc and investigate how it got there, as this can indicate active MITM interception of this endpoint''s TLS traffic.'
        } else {
            Add-AuditResult -Category 'Credential Exposure & Secret Leaks' -Control 'Unrecognized Root Certificate Authorities' -Status 'WARN' -Severity 'Medium' `
                -CurrentValue "$($unrecognizedOlder.Count) unrecognized root CA(s): $(($unrecognizedOlder | Select-Object -First 10) -join ' | ')" -RecommendedValue 'Only recognized/approved root certificates present' -CIS_Control 'CIS 3.6' `
                -NIST_Control 'SC-17, SC-23' -MITRE_Technique 'T1553.004 (Install Root Certificate)' -ISO27001_Control 'A.8.24' -NIS2_Article 'Art.21(2)(h)' `
                -Recommendation 'Review each unrecognized root CA and confirm it was deliberately and knowingly installed (internal PKI, a regional/less-common public CA, or approved TLS-inspection tooling not covered by this scan''s name-pattern list). This is a triage aid based on a name match, not a verdict - false positives are possible for legitimate but less common CAs.'
        }
    } catch {
        Add-AuditResult -Category 'Credential Exposure & Secret Leaks' -Control 'Certificate Store Private Key Security' -Status 'WARN' -Severity 'Low' `
            -CurrentValue 'Query failed' -Recommendation "Unable to complete certificate store audit: $($_.Exception.Message)"
    }
}

function Test-DeveloperSecretFileExposure {
    <#
        Sweeps every local user profile for the standard developer/cloud-CLI secret file
        locations: SSH private keys, AWS CLI credentials, PowerShell PSReadLine command
        history (a well-known plaintext-password leak vector when users type credentials
        interactively), and Azure CLI token caches.
    #>
    Write-SectionBanner 'Credential Exposure - Developer & Cloud CLI Secret Files'
    try {
        $profiles = Get-UserProfileDirectories
        if ($profiles.Count -eq 0) {
            Add-AuditResult -Category 'Credential Exposure & Secret Leaks' -Control 'Developer & Cloud CLI Secret Files' -Status 'WARN' -Severity 'Low' `
                -CurrentValue 'No user profile directories enumerated' -Recommendation 'Verify C:\Users is accessible.'
            return
        }

        $sshKeysFound = [System.Collections.Generic.List[string]]::new()
        $awsCredsFound = [System.Collections.Generic.List[string]]::new()
        $psReadLineLeaks = [System.Collections.Generic.List[string]]::new()
        $azureCliCacheFound = [System.Collections.Generic.List[string]]::new()

        foreach ($profileDir in $profiles) {
            try {
                foreach ($keyName in @('id_rsa', 'id_dsa', 'id_ecdsa', 'id_ed25519')) {
                    $keyPath = Join-Path $profileDir ".ssh\$keyName"
                    if (Test-Path -LiteralPath $keyPath -PathType Leaf -ErrorAction SilentlyContinue) {
                        $header = (Get-Content -LiteralPath $keyPath -TotalCount 3 -ErrorAction SilentlyContinue) -join ' '
                        $looksEncrypted = $header -match '(?i)ENCRYPTED'
                        $note = if ($looksEncrypted) { 'passphrase-protected' } else { 'passphrase protection not confirmed' }
                        $sshKeysFound.Add("$keyPath [$note]")
                    }
                }

                $awsCredsPath = Join-Path $profileDir '.aws\credentials'
                if (Test-Path -LiteralPath $awsCredsPath -PathType Leaf -ErrorAction SilentlyContinue) {
                    $awsCredsFound.Add($awsCredsPath)
                }

                $psReadLineHistPath = Join-Path $profileDir 'AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'
                if (Test-Path -LiteralPath $psReadLineHistPath -PathType Leaf -ErrorAction SilentlyContinue) {
                    $suspiciousLines = @(Select-String -LiteralPath $psReadLineHistPath -Pattern 'password|-AsPlainText|ConvertTo-SecureString|net use.*:.*\S' -ErrorAction SilentlyContinue)
                    if ($suspiciousLines.Count -gt 0) {
                        $psReadLineLeaks.Add("$psReadLineHistPath [$($suspiciousLines.Count) suspicious line(s)]")
                    }
                }

                foreach ($azCache in @('.azure\accessTokens.json', '.azure\msal_token_cache.bin')) {
                    $azPath = Join-Path $profileDir $azCache
                    if (Test-Path -LiteralPath $azPath -PathType Leaf -ErrorAction SilentlyContinue) {
                        $azureCliCacheFound.Add($azPath)
                    }
                }
            } catch { }
        }

        if ($sshKeysFound.Count -eq 0) {
            Add-AuditResult -Category 'Credential Exposure & Secret Leaks' -Control 'SSH Private Key Files' -Status 'PASS' -Severity 'High' `
                -CurrentValue 'No SSH private key files found across local user profiles' -RecommendedValue 'None present, or passphrase-protected if present' -CIS_Control 'CIS 3.3' -NIST_Control 'IA-5, SC-28' `
                -MITRE_Technique 'T1552.004 (Private Keys)' -ISO27001_Control 'A.8.5' -NIS2_Article 'Art.21(2)(h)' -Recommendation 'No action required.'
        } else {
            Add-AuditResult -Category 'Credential Exposure & Secret Leaks' -Control 'SSH Private Key Files' -Status 'WARN' -Severity 'High' `
                -CurrentValue ($sshKeysFound -join ' | ') -RecommendedValue 'Passphrase-protected, or migrated to a hardware security key/TPM-backed agent' -CIS_Control 'CIS 3.3' -NIST_Control 'IA-5, SC-28' `
                -MITRE_Technique 'T1552.004 (Private Keys)' -ISO27001_Control 'A.8.5' -NIS2_Article 'Art.21(2)(h)' -NSA_Guidance 'NSA CSI: Mitigating Credential Theft' `
                -Recommendation 'Confirm each listed key is passphrase-protected (this scan checks only for an "ENCRYPTED" header marker - verify manually if uncertain). Consider migrating to a hardware security key (FIDO2/YubiKey) or Windows Hello-backed SSH agent instead of a bare on-disk private key file.'
        }

        if ($awsCredsFound.Count -gt 0) {
            Add-AuditResult -Category 'Credential Exposure & Secret Leaks' -Control 'AWS CLI Credentials File' -Status 'WARN' -Severity 'Medium' `
                -CurrentValue ($awsCredsFound -join ' | ') -RecommendedValue 'Use short-lived credentials (AWS SSO/STS) instead of long-lived access keys in ~/.aws/credentials where feasible' `
                -CIS_Control 'CIS 3.3' -NIST_Control 'IA-5, SC-28' -MITRE_Technique 'T1552.001 (Credentials In Files)' -ISO27001_Control 'A.8.5' -NIS2_Article 'Art.21(2)(h)' `
                -Recommendation 'AWS CLI credential files are always stored in plaintext by design when present - this is inherent to the tool, not a misconfiguration on its own. Where feasible, migrate to AWS IAM Identity Center (SSO) short-lived credentials rather than long-lived access keys, and ensure the profile owner''s Windows account is protected accordingly.'
        }

        if ($psReadLineLeaks.Count -eq 0) {
            Add-AuditResult -Category 'Credential Exposure & Secret Leaks' -Control 'PSReadLine Command History Credential Leakage' -Status 'PASS' -Severity 'Medium' `
                -CurrentValue 'No password-pattern matches found in PSReadLine command history files' -RecommendedValue 'No plaintext credential-bearing commands in history' -CIS_Control 'CIS 3.3' -NIST_Control 'IA-5' `
                -MITRE_Technique 'T1552.003 (Bash History), T1555 (Credentials from Password Stores)' -ISO27001_Control 'A.8.5' -NIS2_Article 'Art.21(2)(h)' -Recommendation 'No action required.'
        } else {
            Add-AuditResult -Category 'Credential Exposure & Secret Leaks' -Control 'PSReadLine Command History Credential Leakage' -Status 'FAIL' -Severity 'High' `
                -CurrentValue ($psReadLineLeaks -join ' | ') -RecommendedValue 'No plaintext credential-bearing commands in history' -CIS_Control 'CIS 3.3' -NIST_Control 'IA-5' `
                -MITRE_Technique 'T1552.003 (Bash History), T1555 (Credentials from Password Stores)' -ISO27001_Control 'A.8.5' -NIS2_Article 'Art.21(2)(h)' -NSA_Guidance 'NSA CSI: Mitigating Credential Theft' `
                -Recommendation 'Review each listed history file for plaintext credentials typed interactively (e.g. -Password, ConvertTo-SecureString -AsPlainText, net use with inline credentials). Purge affected lines or clear the file, rotate any exposed credentials, and train users to use Get-Credential/secret-vault patterns instead of inline plaintext secrets in PowerShell commands.'
        }

        if ($azureCliCacheFound.Count -gt 0) {
            Add-AuditResult -Category 'Credential Exposure & Secret Leaks' -Control 'Azure CLI Token Cache' -Status 'WARN' -Severity 'Low' `
                -CurrentValue ($azureCliCacheFound -join ' | ') -RecommendedValue 'Expected for active Azure CLI users; ensure the OS profile itself is protected (disk encryption, screen lock)' `
                -CIS_Control 'CIS 3.3' -NIST_Control 'IA-5' -MITRE_Technique 'T1528 (Steal Application Access Token)' -ISO27001_Control 'A.8.5' -NIS2_Article 'Art.21(2)(h)' `
                -Recommendation 'Cached Azure CLI OAuth tokens are expected for active CLI users and are not inherently a misconfiguration. Ensure the underlying protections are in place (BitLocker, screen lock, no shared local accounts) since anyone who can read this profile can potentially replay the cached token until it expires.'
        }
    } catch {
        Add-AuditResult -Category 'Credential Exposure & Secret Leaks' -Control 'Developer & Cloud CLI Secret Files' -Status 'WARN' -Severity 'Low' `
            -CurrentValue 'Query failed' -Recommendation "Unable to complete developer secret file sweep: $($_.Exception.Message)"
    }
}

function Test-ThirdPartyAgentSecretExposure {
    <#
        Scans a bounded set of recently-modified files in known enterprise deployment/
        management tool directories (SCCM, Altiris, Tanium, and common custom IT script
        staging folders) for password-like patterns. SCCM task sequence logs in particular
        have a well-documented history of leaking task sequence variables - including
        domain-join account passwords - in plaintext.
    #>
    Write-SectionBanner 'Credential Exposure - Third-Party Deployment Agent Secret Files'
    $searchTargets = @(
        @{ Path = 'C:\Windows\CCM\Logs'; Filter = '*.log' }
        @{ Path = 'C:\_SMSTaskSequence';  Filter = '*.*' }
        @{ Path = 'C:\Program Files\Altiris'; Filter = '*.xml' }
        @{ Path = 'C:\Program Files (x86)\Altiris'; Filter = '*.xml' }
        @{ Path = 'C:\Program Files (x86)\Tanium\Tanium Client'; Filter = '*.config' }
        @{ Path = 'C:\Scripts'; Filter = '*.*' }
        @{ Path = 'C:\IT'; Filter = '*.*' }
        @{ Path = 'C:\Deploy'; Filter = '*.*' }
    )
    $passwordPattern = '(?i)(password|passwd|pwd)\s*[:=]\s*["'']?[^\s"''<>]{4,}'
    $found = [System.Collections.Generic.List[string]]::new()
    $anyDirChecked = $false

    foreach ($target in $searchTargets) {
        try {
            if (-not (Test-Path -LiteralPath $target.Path -PathType Container -ErrorAction SilentlyContinue)) { continue }
            $anyDirChecked = $true
            $files = @(Get-ChildItem -LiteralPath $target.Path -Filter $target.Filter -File -ErrorAction SilentlyContinue |
                Sort-Object -Property LastWriteTime -Descending | Select-Object -First 50)
            foreach ($f in $files) {
                try {
                    $matchLines = @(Select-String -LiteralPath $f.FullName -Pattern $passwordPattern -ErrorAction SilentlyContinue | Select-Object -First 3)
                    if ($matchLines.Count -gt 0) {
                        $found.Add("$($f.FullName) [$($matchLines.Count) match(es)]")
                    }
                } catch { }
            }
        } catch { }
    }

    if (-not $anyDirChecked) {
        Add-AuditResult -Category 'Credential Exposure & Secret Leaks' -Control 'Third-Party Deployment Agent Secret Files' -Status 'INFO' -Severity 'Informational' `
            -CurrentValue 'None of the known deployment/management tool directories are present on this endpoint' -Recommendation 'No action required.'
        return
    }

    if ($found.Count -eq 0) {
        Add-AuditResult -Category 'Credential Exposure & Secret Leaks' -Control 'Third-Party Deployment Agent Secret Files' -Status 'PASS' -Severity 'High' `
            -CurrentValue 'No password-pattern matches found in the most recently modified files under known deployment tool directories' -RecommendedValue 'No hardcoded credentials in deployment logs/scripts/config files' `
            -CIS_Control 'CIS 3.3' -NIST_Control 'IA-5, SC-28' -MITRE_Technique 'T1552.001 (Credentials In Files)' -ISO27001_Control 'A.8.5' -NIS2_Article 'Art.21(2)(h)' `
            -Recommendation 'No action required. Note: this scan is bounded to the 50 most recently modified files per known directory for performance - it is a sampling sweep, not an exhaustive audit.'
    } else {
        Add-AuditResult -Category 'Credential Exposure & Secret Leaks' -Control 'Third-Party Deployment Agent Secret Files' -Status 'FAIL' -Severity 'Critical' `
            -CurrentValue (($found | Select-Object -First 10) -join ' | ') -RecommendedValue 'No hardcoded credentials in deployment logs/scripts/config files' -CIS_Control 'CIS 3.3' -NIST_Control 'IA-5, SC-28' `
            -MITRE_Technique 'T1552.001 (Credentials In Files)' -ISO27001_Control 'A.8.5' -NIS2_Article 'Art.21(2)(h)' -NSA_Guidance 'NSA CSI: Mitigating Credential Theft' `
            -Recommendation 'Review each listed file for an actual embedded credential (this pattern match can include false positives such as "password" appearing in a comment or UI string). Confirmed exposures - especially SCCM task sequence logs, which have a documented history of leaking domain-join account passwords in plaintext - require immediate credential rotation and log/file remediation.'
    }
}

function Test-CredentialManagerStoredCredentials {
    <#
        Enumerates Windows Credential Manager entries for the current (elevated) session via
        cmdkey /list. Credential Manager never exposes the stored secret itself - only the
        target name, type, and persistence are shown - but every saved credential is a
        standing lateral-movement asset: Windows decrypts and hands over the underlying
        secret transparently to any process authenticating as the owning user, so a large
        number of entries (especially saved TERMSRV/* RDP credentials) widens the blast
        radius if this profile or endpoint is ever compromised.
    #>
    Write-SectionBanner 'Credential Exposure - Windows Credential Manager Stored Credentials'
    try {
        $cmdkeyOutput = @(& cmdkey.exe /list 2>$null)
        if (-not $cmdkeyOutput -or $cmdkeyOutput.Count -eq 0) {
            Add-AuditResult -Category 'Credential Exposure & Secret Leaks' -Control 'Windows Credential Manager Stored Credentials' -Status 'WARN' -Severity 'Low' `
                -CurrentValue 'cmdkey /list returned no output' -Recommendation 'Unable to enumerate Credential Manager entries for the current session.'
            return
        }

        $targets = [System.Collections.Generic.List[string]]::new()
        $currentTarget = $null
        $currentType = 'Unknown'
        foreach ($line in $cmdkeyOutput) {
            if ($line -match '^\s*Target:\s*(.+)$') {
                if ($currentTarget) { $targets.Add("$currentTarget [$currentType]") }
                $currentTarget = $Matches[1].Trim()
                $currentType = 'Unknown'
            } elseif ($line -match '^\s*Type:\s*(.+)$') {
                $currentType = $Matches[1].Trim()
            }
        }
        if ($currentTarget) { $targets.Add("$currentTarget [$currentType]") }

        if ($targets.Count -eq 0) {
            Add-AuditResult -Category 'Credential Exposure & Secret Leaks' -Control 'Windows Credential Manager Stored Credentials' -Status 'PASS' -Severity 'Medium' `
                -CurrentValue 'No stored credentials found for the current session' -RecommendedValue 'No unnecessary saved credentials' -CIS_Control 'CIS 3.3' `
                -NIST_Control 'IA-5' -ISO27001_Control 'A.8.5' -NIS2_Article 'Art.21(2)(h)' -Recommendation 'No action required.'
            return
        }

        $rdpTargets = @($targets | Where-Object { $_ -match '(?i)TERMSRV/' })
        $severity = if ($rdpTargets.Count -gt 0) { 'Medium' } else { 'Low' }

        Add-AuditResult -Category 'Credential Exposure & Secret Leaks' -Control 'Windows Credential Manager Stored Credentials' -Status 'WARN' -Severity $severity `
            -CurrentValue "$($targets.Count) stored credential(s): $($targets -join ' | ')" -RecommendedValue 'Only credentials explicitly required, reviewed periodically; no saved RDP passwords on shared/high-risk endpoints' `
            -CIS_Control 'CIS 3.3' -NIST_Control 'IA-5' -MITRE_Technique 'T1555 (Credentials from Password Stores), T1552 (Unsecured Credentials)' -ISO27001_Control 'A.8.5' -NIS2_Article 'Art.21(2)(h)' -NSA_Guidance 'NSA CSI: Mitigating Credential Theft' `
            -Recommendation 'Review each listed target and remove any credential no longer required (cmdkey /delete:<target>, or via Control Panel > Credential Manager). Saved RDP (TERMSRV/*) credentials in particular are high-value to an attacker who gains local access, since Windows will silently hand over the decrypted secret without re-prompting.'
    } catch {
        Add-AuditResult -Category 'Credential Exposure & Secret Leaks' -Control 'Windows Credential Manager Stored Credentials' -Status 'WARN' -Severity 'Low' -CurrentValue 'Query failed' `
            -Recommendation "Unable to enumerate Credential Manager entries: $($_.Exception.Message)"
    }
}

#endregion

#region ============================== 30. PERIPHERAL, THUNDERBOLT & MEDIA CONTROLS ==============================

function Test-ThunderboltDMALockScreenPolicy {
    <#
        Audits the BitLocker "Disable new DMA devices when this computer is locked" policy
        (DisableExternalDMAUnderLock), which is distinct from the general Kernel DMA
        Protection policy audited earlier in this report: this setting specifically blocks
        newly-attached Thunderbolt/PCIe devices from obtaining DMA access while the
        workstation is at the lock screen, closing the "plug in a malicious device while I
        step away" physical-access window.
    #>
    Write-SectionBanner 'Peripheral Security - Thunderbolt/PCIe DMA Lock-Screen Policy'
    try {
        $fvePath = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE'
        $disableDmaUnderLock = Get-RegistryValueSafe -Path $fvePath -Name 'DisableExternalDMAUnderLock' -DefaultValue $null

        if ($disableDmaUnderLock -eq 1) {
            Add-AuditResult -Category 'Peripheral & Physical Attack Surface' -Control 'DMA Lock-Screen Policy (Disable New DMA Devices When Locked)' -Status 'PASS' -Severity 'High' `
                -CurrentValue 'DisableExternalDMAUnderLock=1 (Enabled)' -RecommendedValue '1' -CIS_Control 'CIS 10.5' -NIST_Control 'SC-28, PE-3' `
                -MITRE_Technique 'T1200 (Hardware Additions)' -ISO27001_Control 'A.8.24' -NIS2_Article 'Art.21(2)(d)' -NSA_Guidance 'NSA/CISA Stop Malicious Cyber Activity - Physical Access Vectors' `
                -Recommendation 'No action required.'
        } else {
            Add-AuditResult -Category 'Peripheral & Physical Attack Surface' -Control 'DMA Lock-Screen Policy (Disable New DMA Devices When Locked)' -Status 'FAIL' -Severity 'High' `
                -CurrentValue 'Not Configured / Disabled' -RecommendedValue '1' -CIS_Control 'CIS 10.5' -NIST_Control 'SC-28, PE-3' -MITRE_Technique 'T1200 (Hardware Additions)' -ISO27001_Control 'A.8.24' `
                -NIS2_Article 'Art.21(2)(d)' -NSA_Guidance 'NSA/CISA Stop Malicious Cyber Activity - Physical Access Vectors' `
                -Recommendation 'Enable the BitLocker GPO "Disable new DMA devices when this computer is locked" (Computer Configuration > Administrative Templates > Windows Components > BitLocker Drive Encryption), which sets DisableExternalDMAUnderLock=1. Without it, a newly-attached Thunderbolt/PCIe device can be granted DMA access even while the workstation is at the lock screen, enabling physical memory-read/credential-extraction attacks against an unattended locked device.'
        }
    } catch {
        Add-AuditResult -Category 'Peripheral & Physical Attack Surface' -Control 'DMA Lock-Screen Policy' -Status 'WARN' -Severity 'Low' `
            -CurrentValue 'Query failed' -Recommendation "Unable to query the DMA lock-screen policy: $($_.Exception.Message)"
    }
}

function Test-BluetoothSecurity {
    <#
        Audits Bluetooth radio/service presence and, where visible, the MDM-CSP-backed
        discoverability policy. Enterprise-managed discoverability control is only reliably
        visible when the device is actively MDM-managed with that specific CSP applied - this
        is reported honestly as informational baseline visibility rather than a fabricated
        universal PASS/FAIL, since an un-configured value is common and not itself a defect.
    #>
    Write-SectionBanner 'Peripheral Security - Bluetooth'
    try {
        $btService = Get-Service -Name 'bthserv' -ErrorAction SilentlyContinue
        if (-not $btService) {
            Add-AuditResult -Category 'Peripheral & Physical Attack Surface' -Control 'Bluetooth Radio/Service State' -Status 'INFO' -Severity 'Informational' `
                -CurrentValue 'Bluetooth Support Service not found - no Bluetooth hardware/driver present' -Recommendation 'Not applicable.'
            return
        }

        Add-AuditResult -Category 'Peripheral & Physical Attack Surface' -Control 'Bluetooth Radio/Service State' -Status 'INFO' -Severity 'Informational' `
            -CurrentValue "StartType=$($btService.StartType); Status=$($btService.Status)" -RecommendedValue 'Disabled entirely if not required; otherwise kept updated and non-discoverable when idle' `
            -CIS_Control 'CIS 4.1' -NIST_Control 'SC-8, AC-18' -MITRE_Technique 'T1091 (Replication Through Removable Media), T1200 (Hardware Additions)' -ISO27001_Control 'A.8.20' -NIS2_Article 'Art.21(2)(d)' `
            -Recommendation 'If Bluetooth is not required for this device''s role (peripherals, headsets, etc.), disable it entirely: Set-Service -Name bthserv -StartupType Disabled, removing the radio-level attack surface (BlueBorne-class RCE vulnerabilities, unauthorized HID keyboard/mouse injection pairing) altogether.'

        $discoverablePolicy = Get-RegistryValueSafe -Path 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Bluetooth' -Name 'AllowDiscoverableMode' -DefaultValue $null
        if ($null -ne $discoverablePolicy) {
            if ($discoverablePolicy -eq 0) {
                Add-AuditResult -Category 'Peripheral & Physical Attack Surface' -Control 'Bluetooth Discoverable Mode Policy' -Status 'PASS' -Severity 'Medium' `
                    -CurrentValue 'AllowDiscoverableMode=0 (Not discoverable)' -RecommendedValue '0' -CIS_Control 'CIS 4.1' -NIST_Control 'AC-18' -ISO27001_Control 'A.8.20' -NIS2_Article 'Art.21(2)(d)' `
                    -Recommendation 'No action required.'
            } else {
                Add-AuditResult -Category 'Peripheral & Physical Attack Surface' -Control 'Bluetooth Discoverable Mode Policy' -Status 'WARN' -Severity 'Medium' `
                    -CurrentValue 'AllowDiscoverableMode=1 (Discoverable permitted)' -RecommendedValue '0' -CIS_Control 'CIS 4.1' -NIST_Control 'AC-18' -ISO27001_Control 'A.8.20' -NIS2_Article 'Art.21(2)(d)' `
                    -Recommendation 'Set the Bluetooth CSP "AllowDiscoverableMode" policy to 0 via Intune, so the device is not broadcasting itself as pairable outside of an explicit, deliberate pairing action.'
            }
        } else {
            Add-AuditResult -Category 'Peripheral & Physical Attack Surface' -Control 'Bluetooth Discoverable Mode Policy' -Status 'INFO' -Severity 'Informational' `
                -CurrentValue 'MDM-managed discoverability policy not present (not centrally managed, or a different management channel is in use)' -RecommendedValue 'Managed centrally where MDM is in use' `
                -Recommendation 'Enterprise-managed Bluetooth discoverability control requires the Bluetooth CSP via Intune. Its absence here is expected for unmanaged or non-Intune-managed devices and is not independently actionable from this endpoint.'
        }
    } catch {
        Add-AuditResult -Category 'Peripheral & Physical Attack Surface' -Control 'Bluetooth Security' -Status 'WARN' -Severity 'Low' `
            -CurrentValue 'Query failed' -Recommendation "Unable to complete Bluetooth security audit: $($_.Exception.Message)"
    }
}

#endregion

#region ============================== 31. ARTIFICIAL INTELLIGENCE & TELEMETRY HARDENING (WINDOWS 11) ==============================

function Test-WindowsCopilotPolicy {
    <#
        Audits the "Turn off Windows Copilot" GPO/CSP. Whether Copilot should be enabled is
        an organizational data-handling decision rather than a universal hardening
        requirement (much like UAC installer detection and Windows Copilot's cousin,
        Recall), so this is reported without an unconditional PASS/FAIL judgement -
        explicitly-disabled is PASS, unconfigured is INFO with context, not FAIL.
    #>
    Write-SectionBanner 'AI & Telemetry Hardening - Windows Copilot'
    try {
        $copilotPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot'
        $turnOffCopilot = Get-RegistryValueSafe -Path $copilotPath -Name 'TurnOffWindowsCopilot' -DefaultValue $null

        if ($turnOffCopilot -eq 1) {
            Add-AuditResult -Category 'AI & Telemetry Hardening' -Control 'Windows Copilot Policy' -Status 'PASS' -Severity 'Medium' `
                -CurrentValue 'Turned off via policy' -RecommendedValue 'Turned off, unless explicitly approved for this data-sensitivity tier' -CIS_Control 'CIS 18.9' -NIST_Control 'SC-7, PT-2' `
                -MITRE_Technique 'T1213 (Data from Information Repositories)' -ISO27001_Control 'A.8.11' -NIS2_Article 'Art.21(2)(h)' -Recommendation 'No action required.'
        } else {
            Add-AuditResult -Category 'AI & Telemetry Hardening' -Control 'Windows Copilot Policy' -Status 'INFO' -Severity 'Informational' `
                -CurrentValue 'Not explicitly turned off (default OS behavior applies)' -RecommendedValue 'Turned off via GPO/Intune if the organization has not completed a data-handling/DLP review for AI-assistant features' `
                -CIS_Control 'CIS 18.9' -NIST_Control 'SC-7, PT-2' -ISO27001_Control 'A.8.11' -NIS2_Article 'Art.21(2)(h)' `
                -Recommendation 'This is a policy/business decision, not a universal defect. If the organization has not completed a data-handling review for AI-assistant features that can process on-screen/clipboard/file content, set "Turn off Windows Copilot" (Computer Configuration > Administrative Templates > Windows Components > Windows Copilot) to Enabled.'
        }
    } catch {
        Add-AuditResult -Category 'AI & Telemetry Hardening' -Control 'Windows Copilot Policy' -Status 'WARN' -Severity 'Low' `
            -CurrentValue 'Query failed' -Recommendation "Unable to query the Windows Copilot policy: $($_.Exception.Message)"
    }
}

function Test-WindowsRecallSecurityControls {
    <#
        Complements the base Windows Recall enablement check (Removable Media & Device
        Control section) with the deeper controls this module asked for: whether the local
        snapshot storage location - if it can be located - has a restrictive ACL. Recall's
        exact snapshot-store path and behavior are still evolving across Windows 11 24H2+
        servicing updates, so this is reported with appropriate uncertainty rather than
        false precision, and is skipped entirely (not re-run) on builds that predate the
        feature.
    #>
    Write-SectionBanner 'AI & Telemetry Hardening - Windows Recall Security Controls'
    try {
        $buildNumber = 0
        try { $buildNumber = [int](Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop).BuildNumber } catch { $buildNumber = 0 }
        if ($buildNumber -lt 26100) {
            Add-AuditResult -Category 'AI & Telemetry Hardening' -Control 'Windows Recall Security Controls' -Status 'INFO' -Severity 'Informational' `
                -CurrentValue "OS Build $buildNumber (pre-24H2)" -RecommendedValue 'Not applicable on this build' -Recommendation 'Not applicable - Windows Recall requires Windows 11 24H2 (build 26100+) on supported Copilot+ hardware.'
            return
        }

        $aiPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI'
        $disableAiAnalysis = Get-RegistryValueSafe -Path $aiPath -Name 'DisableAIDataAnalysis' -DefaultValue $null
        if ($disableAiAnalysis -eq 1) {
            Add-AuditResult -Category 'AI & Telemetry Hardening' -Control 'Windows Recall Security Controls' -Status 'INFO' -Severity 'Informational' `
                -CurrentValue 'Recall is disabled via policy (see the base Recall finding); deeper snapshot-store controls are not applicable' -Recommendation 'No action required.'
            return
        }

        $possibleSnapshotDirs = @(
            (Join-Path $env:LOCALAPPDATA 'CoreAIPlatform.00')
            (Join-Path $env:LOCALAPPDATA 'Microsoft\Windows\Recall')
        )
        $foundDir = $possibleSnapshotDirs | Where-Object { Test-Path -LiteralPath $_ -PathType Container -ErrorAction SilentlyContinue } | Select-Object -First 1

        if (-not $foundDir) {
            Add-AuditResult -Category 'AI & Telemetry Hardening' -Control 'Windows Recall Snapshot Storage Location' -Status 'INFO' -Severity 'Informational' `
                -CurrentValue 'Recall is not confirmed disabled, but no snapshot storage directory was located at the currently-known candidate paths' -RecommendedValue 'Snapshot store (if active) restricted to the owning user, with Windows Hello required to view history' `
                -Recommendation 'Recall''s on-disk layout has changed across Windows 11 24H2 servicing updates and this scan''s candidate paths may be out of date for this specific build. If Recall is active on this device (verify via Settings > Privacy & security > Recall & snapshots), manually confirm: (1) Windows Hello is required to open Recall/view snapshot history, and (2) the snapshot database/image folder is not readable by other standard users.'
        } else {
            $check = Test-LowPrivilegeWriteAccess -Path $foundDir -ObjectType FileSystem
            if ($check.IsVulnerable) {
                Add-AuditResult -Category 'AI & Telemetry Hardening' -Control 'Windows Recall Snapshot Storage Location' -Status 'FAIL' -Severity 'High' `
                    -CurrentValue "$foundDir - Grants: $($check.Principals -join '; ')" -RecommendedValue 'Restricted to the owning user only' -CIS_Control 'CIS 10.3' -NIST_Control 'SC-28, PT-2' `
                    -MITRE_Technique 'T1113 (Screen Capture), T1005 (Data from Local System)' -ISO27001_Control 'A.8.11' -NIS2_Article 'Art.21(2)(h)' `
                    -Recommendation "Tighten the ACL on `"$foundDir`" so it is not accessible to Everyone/Authenticated Users/Users beyond the owning account. Recall snapshots can contain sensitive on-screen content (credentials, regulated data) captured automatically."
            } else {
                Add-AuditResult -Category 'AI & Telemetry Hardening' -Control 'Windows Recall Snapshot Storage Location' -Status 'PASS' -Severity 'High' `
                    -CurrentValue "$foundDir - no low-privilege write grant found" -RecommendedValue 'Restricted to the owning user only' -CIS_Control 'CIS 10.3' -NIST_Control 'SC-28, PT-2' -ISO27001_Control 'A.8.11' `
                    -NIS2_Article 'Art.21(2)(h)' -Recommendation 'No action required. Confirm separately that Windows Hello re-authentication is required to view snapshot history (Settings > Privacy & security > Recall & snapshots).'
            }
        }
    } catch {
        Add-AuditResult -Category 'AI & Telemetry Hardening' -Control 'Windows Recall Security Controls' -Status 'WARN' -Severity 'Low' `
            -CurrentValue 'Query failed' -Recommendation "Unable to complete Windows Recall security controls audit: $($_.Exception.Message)"
    }
}

function Test-TelemetryLevel {
    <#
        Audits the Windows diagnostic data collection level (AllowTelemetry) and the
        commercial data pipeline opt-in, which governs whether diagnostic data is made
        available to the organization's own Desktop Analytics/Endpoint Analytics workspace
        versus Microsoft-only processing.
    #>
    Write-SectionBanner 'AI & Telemetry Hardening - Diagnostic Data Collection Level'
    try {
        $dataCollectionPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
        $allowTelemetry = Get-RegistryValueSafe -Path $dataCollectionPath -Name 'AllowTelemetry' -DefaultValue $null

        if ($null -eq $allowTelemetry) {
            Add-AuditResult -Category 'AI & Telemetry Hardening' -Control 'Diagnostic Data Collection Level (AllowTelemetry)' -Status 'INFO' -Severity 'Informational' `
                -CurrentValue 'Not Configured (OS default applies)' -RecommendedValue '0 (Security, Enterprise/Education only) or 1 (Required/Basic)' -CIS_Control 'CIS 18.9' -NIST_Control 'PT-2, SC-7' `
                -ISO27001_Control 'A.8.11' -NIS2_Article 'Art.21(2)(h)' `
                -Recommendation 'Set "Allow Diagnostic Data" (Computer Configuration > Administrative Templates > Windows Components > Data Collection and Preview Builds) to Diagnostic data off (Security, Enterprise/Education edition only) or Required diagnostic data, to minimize the diagnostic data footprint leaving the endpoint.'
        } elseif ([int]$allowTelemetry -le 1) {
            Add-AuditResult -Category 'AI & Telemetry Hardening' -Control 'Diagnostic Data Collection Level (AllowTelemetry)' -Status 'PASS' -Severity 'Medium' `
                -CurrentValue "AllowTelemetry=$allowTelemetry" -RecommendedValue '0 (Security) or 1 (Required/Basic)' -CIS_Control 'CIS 18.9' -NIST_Control 'PT-2, SC-7' -ISO27001_Control 'A.8.11' `
                -NIS2_Article 'Art.21(2)(h)' -Recommendation 'No action required.'
        } else {
            Add-AuditResult -Category 'AI & Telemetry Hardening' -Control 'Diagnostic Data Collection Level (AllowTelemetry)' -Status 'FAIL' -Severity 'Medium' `
                -CurrentValue "AllowTelemetry=$allowTelemetry (Optional/Full diagnostic data)" -RecommendedValue '0 (Security) or 1 (Required/Basic)' -CIS_Control 'CIS 18.9' -NIST_Control 'PT-2, SC-7' `
                -ISO27001_Control 'A.8.11' -NIS2_Article 'Art.21(2)(h)' `
                -Recommendation 'Reduce "Allow Diagnostic Data" to Required diagnostic data (1) or, on Enterprise/Education editions, Diagnostic data off (0). The Optional/Full tier collects substantially more diagnostic content, which can be a compliance concern for regulated data environments.'
        }
    } catch {
        Add-AuditResult -Category 'AI & Telemetry Hardening' -Control 'Diagnostic Data Collection Level' -Status 'WARN' -Severity 'Low' `
            -CurrentValue 'Query failed' -Recommendation "Unable to query the diagnostic data collection policy: $($_.Exception.Message)"
    }
}

#endregion

#region ============================== 32. TARGETED GAP CHECKS - DEFENDER, NETWORK, ACCOUNTS & AWARENESS ==============================

function Test-ControlledFolderAccess {
    <#
        Audits Microsoft Defender Controlled Folder Access, which blocks unauthorized/
        unrecognized applications from modifying files in protected folders - a direct,
        preventive complement to the VSS/backup-based recovery controls audited in the
        Ransomware Recovery & Resilience section, and one of the most effective built-in
        ransomware-specific mitigations available on Windows 11.
    #>
    Write-SectionBanner 'Defender Protection Gaps - Controlled Folder Access'
    try {
        $pref = Get-DefenderPreferenceCache
        if (-not $pref) { throw 'Defender preferences unavailable' }

        $cfaMap = @{ 0 = 'Disabled'; 1 = 'Enabled (Block)'; 2 = 'Audit Mode'; 3 = 'Block Disk Modification Only'; 4 = 'Audit Disk Modification Only' }
        $state = $pref.EnableControlledFolderAccess
        $desc = $cfaMap[[int]$state]
        if (-not $desc) { $desc = "Value $state" }

        if ([int]$state -eq 1) {
            Add-AuditResult -Category 'Next-Gen Antivirus & EDR' -Control 'Controlled Folder Access (Ransomware Protection)' -Status 'PASS' -Severity 'High' `
                -CurrentValue 'Enabled (Block)' -RecommendedValue 'Enabled (Block)' -CIS_Control 'CIS 10.1' -NIST_Control 'SI-3, CP-9' `
                -MITRE_Technique 'T1486 (Data Encrypted for Impact), T1490 (Inhibit System Recovery)' -ISO27001_Control 'A.8.7' -NIS2_Article 'Art.21(2)(b)' `
                -NSA_Guidance 'NSA/CISA #StopRansomware Guidance' -Recommendation 'No action required.'
        } elseif ([int]$state -eq 2 -or [int]$state -eq 4) {
            Add-AuditResult -Category 'Next-Gen Antivirus & EDR' -Control 'Controlled Folder Access (Ransomware Protection)' -Status 'WARN' -Severity 'High' `
                -CurrentValue $desc -RecommendedValue 'Enabled (Block)' -CIS_Control 'CIS 10.1' -NIST_Control 'SI-3, CP-9' -MITRE_Technique 'T1486 (Data Encrypted for Impact)' -ISO27001_Control 'A.8.7' `
                -NIS2_Article 'Art.21(2)(b)' `
                -Recommendation 'Review Controlled Folder Access audit events (Event ID 1123) for false positives against legitimate applications, then promote from Audit to Block mode: Set-MpPreference -EnableControlledFolderAccess Enabled.'
        } else {
            Add-AuditResult -Category 'Next-Gen Antivirus & EDR' -Control 'Controlled Folder Access (Ransomware Protection)' -Status 'FAIL' -Severity 'High' `
                -CurrentValue $desc -RecommendedValue 'Enabled (Block)' -CIS_Control 'CIS 10.1' -NIST_Control 'SI-3, CP-9' `
                -MITRE_Technique 'T1486 (Data Encrypted for Impact), T1490 (Inhibit System Recovery)' -ISO27001_Control 'A.8.7' -NIS2_Article 'Art.21(2)(b)' -NSA_Guidance 'NSA/CISA #StopRansomware Guidance' `
                -Recommendation 'Enable Controlled Folder Access: Set-MpPreference -EnableControlledFolderAccess Enabled. This blocks unauthorized applications (including most ransomware encryptors) from modifying files in protected folders (Documents, Desktop, Pictures by default).'
        }

        $protectedFolders = @($pref.ControlledFolderAccessProtectedFolders)
        $allowedApps = @($pref.ControlledFolderAccessAllowedApplications)
        Add-AuditResult -Category 'Next-Gen Antivirus & EDR' -Control 'Controlled Folder Access - Protected Folder & Allowed Application Scope' -Status 'INFO' -Severity 'Informational' `
            -CurrentValue "$($protectedFolders.Count) additional protected folder(s); $($allowedApps.Count) explicitly allowed application(s)" -RecommendedValue 'Reviewed periodically for unnecessary allowed-application entries' `
            -Recommendation 'Each entry in the allowed-applications list is exempted from Controlled Folder Access enforcement. Periodically review (Get-MpPreference).ControlledFolderAccessAllowedApplications for entries no longer needed or overly broad.'
    } catch {
        Add-AuditResult -Category 'Next-Gen Antivirus & EDR' -Control 'Controlled Folder Access' -Status 'WARN' -Severity 'Low' `
            -CurrentValue 'Unavailable' -Recommendation "Unable to query Controlled Folder Access state: $($_.Exception.Message)"
    }
}

function Test-DefenderNetworkProtection {
    <#
        Audits Microsoft Defender Network Protection, which blocks outbound connections to
        known-malicious domains/IPs (phishing, exploit-kit, and C2 infrastructure) at the OS
        network stack level, independent of and complementary to browser-specific SmartScreen
        protections audited elsewhere.
    #>
    Write-SectionBanner 'Defender Protection Gaps - Network Protection'
    try {
        $pref = Get-DefenderPreferenceCache
        if (-not $pref) { throw 'Defender preferences unavailable' }

        $npState = $pref.EnableNetworkProtection
        if ([int]$npState -eq 1) {
            Add-AuditResult -Category 'Next-Gen Antivirus & EDR' -Control 'Network Protection' -Status 'PASS' -Severity 'High' -CurrentValue 'Enabled (Block)' -RecommendedValue 'Enabled (Block)' `
                -CIS_Control 'CIS 9.2' -NIST_Control 'SC-7, SI-4' -MITRE_Technique 'T1071 (Application Layer Protocol), T1189 (Drive-by Compromise)' -ISO27001_Control 'A.8.20' -NIS2_Article 'Art.21(2)(b)' `
                -NSA_Guidance 'NSA/CISA Guidance on Endpoint Detection and Response' -Recommendation 'No action required.'
        } elseif ([int]$npState -eq 2) {
            Add-AuditResult -Category 'Next-Gen Antivirus & EDR' -Control 'Network Protection' -Status 'WARN' -Severity 'Medium' -CurrentValue 'Audit Mode' -RecommendedValue 'Enabled (Block)' `
                -CIS_Control 'CIS 9.2' -NIST_Control 'SC-7, SI-4' -ISO27001_Control 'A.8.20' -NIS2_Article 'Art.21(2)(b)' `
                -Recommendation 'Review Network Protection audit events, then promote to Block mode: Set-MpPreference -EnableNetworkProtection Enabled.'
        } else {
            Add-AuditResult -Category 'Next-Gen Antivirus & EDR' -Control 'Network Protection' -Status 'FAIL' -Severity 'High' -CurrentValue 'Disabled' -RecommendedValue 'Enabled (Block)' `
                -CIS_Control 'CIS 9.2' -NIST_Control 'SC-7, SI-4' -MITRE_Technique 'T1071 (Application Layer Protocol), T1189 (Drive-by Compromise), T1566 (Phishing)' -ISO27001_Control 'A.8.20' `
                -NIS2_Article 'Art.21(2)(b)' -NSA_Guidance 'NSA/CISA Guidance on Endpoint Detection and Response' `
                -Recommendation 'Enable Network Protection: Set-MpPreference -EnableNetworkProtection Enabled. This blocks outbound connections to known-malicious domains/IPs at the OS network stack level.'
        }
    } catch {
        Add-AuditResult -Category 'Next-Gen Antivirus & EDR' -Control 'Network Protection' -Status 'WARN' -Severity 'Low' -CurrentValue 'Unavailable' `
            -Recommendation "Unable to query Network Protection state: $($_.Exception.Message)"
    }
}

function Test-DefenderExclusions {
    <#
        Audits configured Defender path/process/extension exclusions for overly broad
        entries (an entire drive root or top-level system directory), and reports the full
        exclusion inventory for periodic review. Exclusions are a legitimate, necessary
        feature for performance/compatibility, but each one is a standing, silent gap in AV
        coverage - stale or overly broad exclusions are a very common real-world finding.
    #>
    Write-SectionBanner 'Defender Protection Gaps - AV/ASR Exclusions Audit'
    try {
        $pref = Get-DefenderPreferenceCache
        if (-not $pref) { throw 'Defender preferences unavailable' }

        $exclusionPaths = @($pref.ExclusionPath)
        $exclusionProcesses = @($pref.ExclusionProcess)
        $exclusionExtensions = @($pref.ExclusionExtension)

        $dangerousPaths = [System.Collections.Generic.List[string]]::new()
        $dangerousPatterns = @('^[A-Za-z]:\\$', '^[A-Za-z]:\\Windows\\?$', '^[A-Za-z]:\\Users\\?$', '^[A-Za-z]:\\Program Files\\?$', '^[A-Za-z]:\\Program Files \(x86\)\\?$', '^[A-Za-z]:\\Windows\\System32\\?$', '^[A-Za-z]:\\ProgramData\\?$')
        foreach ($p in $exclusionPaths) {
            if (-not $p) { continue }
            $normalized = $p.TrimEnd('\')
            foreach ($pattern in $dangerousPatterns) {
                if ($normalized -match $pattern -or "$normalized\" -match $pattern) { $dangerousPaths.Add($p); break }
            }
        }

        if ($dangerousPaths.Count -gt 0) {
            Add-AuditResult -Category 'Next-Gen Antivirus & EDR' -Control 'Defender Exclusions - Overly Broad Path Exclusions' -Status 'FAIL' -Severity 'Critical' `
                -CurrentValue ($dangerousPaths -join ', ') -RecommendedValue 'No exclusions at a drive root or top-level system directory' -CIS_Control 'CIS 10.1' -NIST_Control 'SI-3, CM-7' `
                -MITRE_Technique 'T1562.001 (Disable or Modify Tools)' -ISO27001_Control 'A.8.7' -NIS2_Article 'Art.21(2)(b)' -NSA_Guidance 'NSA/CISA Guidance on Endpoint Detection and Response' `
                -Recommendation "Remove the listed exclusion(s): Remove-MpPreference -ExclusionPath `"<path>`". Excluding an entire drive root or top-level system directory effectively disables real-time scanning across the whole machine - this is a common `"performance fix`" that silently guts AV coverage."
        } else {
            Add-AuditResult -Category 'Next-Gen Antivirus & EDR' -Control 'Defender Exclusions - Overly Broad Path Exclusions' -Status 'PASS' -Severity 'Critical' `
                -CurrentValue "$($exclusionPaths.Count) path exclusion(s) checked; none at a drive root or top-level system directory" -RecommendedValue 'No exclusions at a drive root or top-level system directory' `
                -CIS_Control 'CIS 10.1' -NIST_Control 'SI-3, CM-7' -ISO27001_Control 'A.8.7' -NIS2_Article 'Art.21(2)(b)' -Recommendation 'No action required.'
        }

        $totalExclusions = $exclusionPaths.Count + $exclusionProcesses.Count + $exclusionExtensions.Count
        if ($totalExclusions -gt 0) {
            Add-AuditResult -Category 'Next-Gen Antivirus & EDR' -Control 'Defender Exclusions - Full Inventory' -Status 'INFO' -Severity 'Informational' `
                -CurrentValue "Paths=$($exclusionPaths.Count) [$($exclusionPaths -join ', ')]; Processes=$($exclusionProcesses.Count) [$($exclusionProcesses -join ', ')]; Extensions=$($exclusionExtensions.Count) [$($exclusionExtensions -join ', ')]" `
                -RecommendedValue 'Every exclusion documented with a specific, current business justification' -CIS_Control 'CIS 10.1' -NIST_Control 'SI-3, CM-7' -ISO27001_Control 'A.8.7' -NIS2_Article 'Art.21(2)(b)' `
                -Recommendation 'Review this exclusion inventory against current business need - stale exclusions are common, and each is a standing gap in coverage. Process exclusions are especially high-value to attackers if the excluded process name can be reused/impersonated.'
        } else {
            Add-AuditResult -Category 'Next-Gen Antivirus & EDR' -Control 'Defender Exclusions - Full Inventory' -Status 'PASS' -Severity 'Low' -CurrentValue 'No exclusions configured' `
                -RecommendedValue 'No exclusions, or every exclusion documented with a specific business justification' -Recommendation 'No action required.'
        }
    } catch {
        Add-AuditResult -Category 'Next-Gen Antivirus & EDR' -Control 'Defender Exclusions Audit' -Status 'WARN' -Severity 'Low' -CurrentValue 'Unavailable' `
            -Recommendation "Unable to query Defender exclusions: $($_.Exception.Message)"
    }
}

function Test-SMBShareSecurity {
    <#
        Audits share-level permissions on every non-default SMB share for grants of Full
        Control or Change to Everyone, Authenticated Users, or the local Users group -
        distinct from the earlier default-administrative-share check, which only covers
        C$/ADMIN$ and not custom shares an administrator or application may have created.
    #>
    Write-SectionBanner 'Network & Share Hardening - SMB Share Permissions'
    try {
        $shares = @(Get-SmbShare -ErrorAction Stop | Where-Object { $_.Name -notmatch '^[A-Za-z]\$$' -and $_.Name -notin @('ADMIN$', 'IPC$', 'print$') })

        if ($shares.Count -eq 0) {
            Add-AuditResult -Category 'Network Architecture & Protocol Hardening' -Control 'Custom SMB Share Permissions' -Status 'PASS' -Severity 'Medium' `
                -CurrentValue 'No custom (non-default) SMB shares found' -RecommendedValue 'No Everyone/Authenticated Users/Users Full Control or Change grant on any custom share' `
                -CIS_Control 'CIS 4.8' -NIST_Control 'AC-3, AC-6' -MITRE_Technique 'T1021.002 (SMB/Windows Admin Shares)' -ISO27001_Control 'A.8.3' -NIS2_Article 'Art.21(2)(d)' -Recommendation 'No action required.'
            return
        }

        $insecureShares = [System.Collections.Generic.List[string]]::new()
        foreach ($share in $shares) {
            try {
                $access = @(Get-SmbShareAccess -Name $share.Name -ErrorAction Stop)
                $badGrants = @($access | Where-Object { ($_.AccountName -match '(?i)Everyone|Authenticated Users|BUILTIN\\Users') -and ($_.AccessRight -match '(?i)Full|Change') -and ($_.AccessControlType -eq 'Allow') })
                if ($badGrants.Count -gt 0) {
                    $grantDesc = (($badGrants | ForEach-Object { "$($_.AccountName)=$($_.AccessRight)" }) -join ', ')
                    $insecureShares.Add("$($share.Name) [$($share.Path)] -> $grantDesc")
                }
            } catch { }
        }

        if ($insecureShares.Count -eq 0) {
            Add-AuditResult -Category 'Network Architecture & Protocol Hardening' -Control 'Custom SMB Share Permissions' -Status 'PASS' -Severity 'High' `
                -CurrentValue "$($shares.Count) custom share(s) checked; none grant Everyone/Authenticated Users/Users Full Control or Change" -RecommendedValue 'No broad Full Control/Change grant to Everyone/Authenticated Users/Users' `
                -CIS_Control 'CIS 4.8' -NIST_Control 'AC-3, AC-6' -MITRE_Technique 'T1021.002 (SMB/Windows Admin Shares)' -ISO27001_Control 'A.8.3' -NIS2_Article 'Art.21(2)(d)' -Recommendation 'No action required.'
        } else {
            Add-AuditResult -Category 'Network Architecture & Protocol Hardening' -Control 'Custom SMB Share Permissions' -Status 'FAIL' -Severity 'High' `
                -CurrentValue ($insecureShares -join ' | ') -RecommendedValue 'No broad Full Control/Change grant to Everyone/Authenticated Users/Users' -CIS_Control 'CIS 4.8' -NIST_Control 'AC-3, AC-6' `
                -MITRE_Technique 'T1021.002 (SMB/Windows Admin Shares), T1135 (Network Share Discovery)' -ISO27001_Control 'A.8.3' -NIS2_Article 'Art.21(2)(d)' -NSA_Guidance 'NSA/CISA Identity and Access Management Best Practices' `
                -Recommendation 'Tighten share-level permissions on the listed share(s): Revoke-SmbShareAccess -Name "<share>" -AccountName "Everyone" -Force, then grant access only to the groups that need it via Grant-SmbShareAccess. NTFS ACLs on the underlying folder are enforced in addition to share permissions - review both.'
        }
    } catch {
        Add-AuditResult -Category 'Network Architecture & Protocol Hardening' -Control 'SMB Share Permissions' -Status 'WARN' -Severity 'Low' -CurrentValue 'Query failed' `
            -Recommendation "Unable to enumerate SMB shares: $($_.Exception.Message)"
    }
}

function Test-FirewallRuleBroadAllowRules {
    <#
        Audits enabled inbound Allow firewall rules for high-risk ports (RDP, SMB, WinRM,
        SSH, FTP, Telnet, SQL Server) scoped to any remote address, rather than a specific
        management subnet - the profile-level state audited earlier does not catch an
        individually over-permissive rule sitting within an otherwise-correct profile.
    #>
    Write-SectionBanner 'Network & Share Hardening - Firewall Rules Allowing High-Risk Ports from Any Address'
    try {
        $highRiskPorts = [ordered]@{ '3389' = 'RDP'; '445' = 'SMB'; '5985' = 'WinRM HTTP'; '5986' = 'WinRM HTTPS'; '22' = 'SSH'; '21' = 'FTP'; '23' = 'Telnet'; '1433' = 'SQL Server' }
        $inboundAllowRules = @(Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True -ErrorAction Stop)

        $riskyRules = [System.Collections.Generic.List[string]]::new()
        foreach ($rule in $inboundAllowRules) {
            try {
                $portFilter = $rule | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue
                $addrFilter = $rule | Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue
                if (-not $portFilter -or -not $addrFilter) { continue }
                $remoteAny = ($addrFilter.RemoteAddress -contains 'Any')
                if (-not $remoteAny) { continue }

                foreach ($portEntry in $highRiskPorts.GetEnumerator()) {
                    if ($portFilter.LocalPort -contains $portEntry.Key) {
                        $riskyRules.Add("$($rule.DisplayName) [$($portEntry.Value)/$($portEntry.Key), RemoteAddress=Any]")
                    }
                }
            } catch { }
        }

        $uniqueRisky = @($riskyRules | Select-Object -Unique)
        if ($uniqueRisky.Count -eq 0) {
            Add-AuditResult -Category 'Network Architecture & Protocol Hardening' -Control 'Firewall Rules - High-Risk Ports Open to Any Remote Address' -Status 'PASS' -Severity 'High' `
                -CurrentValue "$($inboundAllowRules.Count) enabled inbound Allow rule(s) checked; none open a high-risk port to RemoteAddress=Any" `
                -RecommendedValue 'High-risk ports scoped to specific remote address ranges, or not exposed at all' -CIS_Control 'CIS 4.4' -NIST_Control 'SC-7' `
                -MITRE_Technique 'T1021 (Remote Services), T1210 (Exploitation of Remote Services)' -ISO27001_Control 'A.8.20' -NIS2_Article 'Art.21(2)(d)' -Recommendation 'No action required.'
        } else {
            Add-AuditResult -Category 'Network Architecture & Protocol Hardening' -Control 'Firewall Rules - High-Risk Ports Open to Any Remote Address' -Status 'FAIL' -Severity 'High' `
                -CurrentValue ($uniqueRisky -join ' | ') -RecommendedValue 'High-risk ports scoped to specific remote address ranges, or not exposed at all' -CIS_Control 'CIS 4.4' -NIST_Control 'SC-7' `
                -MITRE_Technique 'T1021 (Remote Services), T1210 (Exploitation of Remote Services)' -ISO27001_Control 'A.8.20' -NIS2_Article 'Art.21(2)(d)' -NSA_Guidance 'NSA/CISA Selecting Secure Remote Access Solutions' `
                -Recommendation 'Scope each listed rule''s remote address to a specific management subnet/VPN range (Set-NetFirewallRule -DisplayName "<name>" -RemoteAddress <CIDR>) rather than Any, or disable the rule entirely if the service is not intentionally exposed to the network.'
        }
    } catch {
        Add-AuditResult -Category 'Network Architecture & Protocol Hardening' -Control 'Firewall Rule High-Risk Port Audit' -Status 'WARN' -Severity 'Low' -CurrentValue 'Query failed' `
            -Recommendation "Unable to enumerate firewall rules: $($_.Exception.Message)"
    }
}

function Test-RDPSecurityLayerAndTLS {
    <#
        Audits RDP's own Security Layer and Minimum Encryption Level settings - distinct
        from the general Schannel protocol audit earlier, since RDP negotiates its transport
        security independently and can be left on the legacy native RDP encryption scheme
        even when system-wide Schannel/TLS policy is fully hardened.
    #>
    Write-SectionBanner 'Network & Share Hardening - RDP Security Layer & Encryption Level'
    try {
        $fDenyTs = Get-RegistryValueSafe -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -DefaultValue 1
        if ([int]$fDenyTs -eq 1) {
            Add-AuditResult -Category 'Network Architecture & Protocol Hardening' -Control 'RDP Security Layer (SSL/TLS Enforcement)' -Status 'INFO' -Severity 'Informational' `
                -CurrentValue 'RDP is disabled' -Recommendation 'Not applicable - see the Remote Desktop Protocol (RDP) State finding.'
            return
        }

        $rdpTcpPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
        $securityLayer = Get-RegistryValueSafe -Path $rdpTcpPath -Name 'SecurityLayer' -DefaultValue 0
        $minEncryption = Get-RegistryValueSafe -Path $rdpTcpPath -Name 'MinEncryptionLevel' -DefaultValue 2

        if ([int]$securityLayer -eq 2) {
            Add-AuditResult -Category 'Network Architecture & Protocol Hardening' -Control 'RDP Security Layer (SSL/TLS Enforcement)' -Status 'PASS' -Severity 'High' `
                -CurrentValue 'SecurityLayer=2 (SSL/TLS only)' -RecommendedValue '2 (SSL/TLS only)' -CIS_Control 'CIS 4.9' -NIST_Control 'SC-8, SC-13' -MITRE_Technique 'T1557 (Adversary-in-the-Middle)' `
                -ISO27001_Control 'A.8.24' -NIS2_Article 'Art.21(2)(j)' -NSA_Guidance 'NSA/CISA Selecting Secure Remote Access Solutions' -Recommendation 'No action required.'
        } else {
            $layerMap = @{ 0 = 'RDP Security Layer (legacy)'; 1 = 'Negotiate' }
            $layerDesc = $layerMap[[int]$securityLayer]
            if (-not $layerDesc) { $layerDesc = "Value $securityLayer" }
            Add-AuditResult -Category 'Network Architecture & Protocol Hardening' -Control 'RDP Security Layer (SSL/TLS Enforcement)' -Status 'FAIL' -Severity 'High' `
                -CurrentValue "SecurityLayer=$securityLayer ($layerDesc)" -RecommendedValue '2 (SSL/TLS only)' -CIS_Control 'CIS 4.9' -NIST_Control 'SC-8, SC-13' -MITRE_Technique 'T1557 (Adversary-in-the-Middle)' `
                -ISO27001_Control 'A.8.24' -NIS2_Article 'Art.21(2)(j)' -NSA_Guidance 'NSA/CISA Selecting Secure Remote Access Solutions' `
                -Recommendation 'Set "Require use of specific security layer for remote (RDP) connections" to SSL (SecurityLayer=2). The legacy RDP Security Layer and Negotiate modes can be downgraded to weaker native RDP encryption, which lacks server identity verification.'
        }

        if ([int]$minEncryption -ge 3) {
            Add-AuditResult -Category 'Network Architecture & Protocol Hardening' -Control 'RDP Minimum Encryption Level' -Status 'PASS' -Severity 'Medium' `
                -CurrentValue "MinEncryptionLevel=$minEncryption (High)" -RecommendedValue '3 (High)' -CIS_Control 'CIS 4.9' -NIST_Control 'SC-8, SC-13' -ISO27001_Control 'A.8.24' -NIS2_Article 'Art.21(2)(j)' `
                -Recommendation 'No action required.'
        } else {
            Add-AuditResult -Category 'Network Architecture & Protocol Hardening' -Control 'RDP Minimum Encryption Level' -Status 'FAIL' -Severity 'Medium' `
                -CurrentValue "MinEncryptionLevel=$minEncryption" -RecommendedValue '3 (High)' -CIS_Control 'CIS 4.9' -NIST_Control 'SC-8, SC-13' -ISO27001_Control 'A.8.24' -NIS2_Article 'Art.21(2)(j)' `
                -Recommendation 'Set "Set client connection encryption level" to High (MinEncryptionLevel=3) so RDP traffic uses 128-bit encryption at minimum in both directions.'
        }
    } catch {
        Add-AuditResult -Category 'Network Architecture & Protocol Hardening' -Control 'RDP Security Layer & Encryption Level' -Status 'WARN' -Severity 'Low' -CurrentValue 'Query failed' `
            -Recommendation "Unable to query RDP security layer configuration: $($_.Exception.Message)"
    }
}

function Test-PasswordNeverExpiresAccounts {
    <#
        Audits enabled local accounts for a non-expiring password, excluding the handful of
        built-in accounts Windows itself configures this way by default (Guest,
        DefaultAccount, WDAGUtilityAccount). A forgotten test/service account with a
        never-expiring password is one of the most common real-world local account findings.
    #>
    Write-SectionBanner 'Account & Exploit Mitigation Gaps - Password Never Expires (Local Accounts)'
    try {
        $expectedExemptAccounts = @('Guest', 'DefaultAccount', 'WDAGUtilityAccount')
        $accounts = @(Get-LocalUser -ErrorAction Stop | Where-Object { $_.Enabled -eq $true -and $null -eq $_.PasswordExpires -and ($expectedExemptAccounts -notcontains $_.Name) })

        if ($accounts.Count -eq 0) {
            Add-AuditResult -Category 'Identity, Privilege Management & Access Control' -Control 'Local Accounts with Non-Expiring Passwords' -Status 'PASS' -Severity 'Medium' `
                -CurrentValue 'No enabled, non-exempt local accounts have a non-expiring password' -RecommendedValue 'Password expiration enforced, or a documented exception' -CIS_Control 'CIS 5.2' `
                -NIST_Control 'IA-5' -MITRE_Technique 'T1078.003 (Local Accounts)' -ISO27001_Control 'A.8.5' -NIS2_Article 'Art.21(2)(i)' -Recommendation 'No action required.'
        } else {
            $names = ($accounts | ForEach-Object { $_.Name }) -join ', '
            Add-AuditResult -Category 'Identity, Privilege Management & Access Control' -Control 'Local Accounts with Non-Expiring Passwords' -Status 'WARN' -Severity 'Medium' `
                -CurrentValue "$($accounts.Count) account(s): $names" -RecommendedValue 'Password expiration enforced, or a documented exception' -CIS_Control 'CIS 5.2' -NIST_Control 'IA-5' `
                -MITRE_Technique 'T1078.003 (Local Accounts)' -ISO27001_Control 'A.8.5' -NIS2_Article 'Art.21(2)(i)' -NSA_Guidance 'NSA/CISA Identity and Access Management Best Practices' `
                -Recommendation "Review each listed account. Set-LocalUser -Name `"<account>`" -PasswordNeverExpires `$false to re-enable expiration, unless the account is a documented, managed service account (ideally LAPS-managed rather than a manually-created never-expiring local account)."
        }
    } catch {
        Add-AuditResult -Category 'Identity, Privilege Management & Access Control' -Control 'Local Accounts with Non-Expiring Passwords' -Status 'WARN' -Severity 'Low' -CurrentValue 'Query failed' `
            -Recommendation "Unable to enumerate local accounts: $($_.Exception.Message)"
    }
}

function Test-RemoteDesktopUsersGroupMembership {
    <#
        Audits local Remote Desktop Users group membership - the population of accounts (in
        addition to Administrators) able to establish an interactive RDP session, paralleling
        the existing Administrators-group membership check.
    #>
    Write-SectionBanner 'Account & Exploit Mitigation Gaps - Remote Desktop Users Group Membership'
    try {
        $members = @(Get-LocalGroupMember -Group 'Remote Desktop Users' -ErrorAction Stop)
        $memberList = ($members | ForEach-Object { $_.Name }) -join ', '
        if ($members.Count -eq 0) {
            Add-AuditResult -Category 'Identity, Privilege Management & Access Control' -Control 'Remote Desktop Users Group Membership' -Status 'PASS' -Severity 'Medium' `
                -CurrentValue 'No members (RDP access restricted to Administrators only, if RDP is enabled at all)' -RecommendedValue 'Minimal, justified membership' -CIS_Control 'CIS 5.4' `
                -NIST_Control 'AC-6, AC-17' -MITRE_Technique 'T1078 (Valid Accounts), T1021.001 (Remote Desktop Protocol)' -ISO27001_Control 'A.5.18' -NIS2_Article 'Art.21(2)(i)' -Recommendation 'No action required.'
        } else {
            Add-AuditResult -Category 'Identity, Privilege Management & Access Control' -Control 'Remote Desktop Users Group Membership' -Status 'WARN' -Severity 'Medium' `
                -CurrentValue "$($members.Count) member(s): $memberList" -RecommendedValue 'Minimal, justified membership' -CIS_Control 'CIS 5.4' -NIST_Control 'AC-6, AC-17' `
                -MITRE_Technique 'T1078 (Valid Accounts), T1021.001 (Remote Desktop Protocol)' -ISO27001_Control 'A.5.18' -NIS2_Article 'Art.21(2)(i)' `
                -Recommendation 'Review the membership list above against least-privilege expectations - every listed account can establish an interactive RDP session. Combine with NLA enforcement and firewall scoping (audited elsewhere) rather than relying on group membership alone.'
        }
    } catch {
        Add-AuditResult -Category 'Identity, Privilege Management & Access Control' -Control 'Remote Desktop Users Group Membership' -Status 'WARN' -Severity 'Low' -CurrentValue 'Query failed' `
            -Recommendation "Unable to enumerate Remote Desktop Users group membership: $($_.Exception.Message)"
    }
}

function Test-SEHOPMitigation {
    <#
        Audits Structured Exception Handling Overwrite Protection (SEHOP), a kernel-level
        exploit mitigation named explicitly in the original hardening scope but not
        previously implemented as its own check - it is controlled independently of the
        DEP/ASLR/CFG mitigations already audited via Get-ProcessMitigation.
    #>
    Write-SectionBanner 'Account & Exploit Mitigation Gaps - SEHOP'
    try {
        $kernelPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel'
        $disableSehop = Get-RegistryValueSafe -Path $kernelPath -Name 'DisableExceptionChainValidation' -DefaultValue 0

        if ([int]$disableSehop -eq 0) {
            Add-AuditResult -Category 'Attack Surface Reduction & Exploit Prevention' -Control 'Structured Exception Handling Overwrite Protection (SEHOP)' -Status 'PASS' -Severity 'Medium' `
                -CurrentValue 'DisableExceptionChainValidation=0 (SEHOP enabled)' -RecommendedValue '0' -CIS_Control 'CIS 10.1' -NIST_Control 'SI-16, SC-39' -MITRE_Technique 'T1055 (Process Injection)' `
                -ISO27001_Control 'A.8.7' -NIS2_Article 'Art.21(2)(b)' -NSA_Guidance 'NSA Hardening Guidance for Windows 11' -Recommendation 'No action required.'
        } else {
            Add-AuditResult -Category 'Attack Surface Reduction & Exploit Prevention' -Control 'Structured Exception Handling Overwrite Protection (SEHOP)' -Status 'FAIL' -Severity 'Medium' `
                -CurrentValue 'DisableExceptionChainValidation=1 (SEHOP disabled)' -RecommendedValue '0' -CIS_Control 'CIS 10.1' -NIST_Control 'SI-16, SC-39' -MITRE_Technique 'T1055 (Process Injection)' `
                -ISO27001_Control 'A.8.7' -NIS2_Article 'Art.21(2)(b)' -NSA_Guidance 'NSA Hardening Guidance for Windows 11' `
                -Recommendation 'Set HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel\DisableExceptionChainValidation (DWORD) = 0, then reboot. SEHOP validates a thread''s exception handler chain before dispatch, blocking SEH-overwrite stack exploitation.'
        }
    } catch {
        Add-AuditResult -Category 'Attack Surface Reduction & Exploit Prevention' -Control 'SEHOP' -Status 'WARN' -Severity 'Low' -CurrentValue 'Query failed' `
            -Recommendation "Unable to query SEHOP configuration: $($_.Exception.Message)"
    }
}

function Test-PrintSpoolerRPCHardening {
    <#
        Audits the RPC authentication-level hardening for the print system (RpcAuthnLevel
        PrivacyEnabled), which closes the CVE-2021-1678 RPC coercion/relay variant related to
        the PrintNightmare vulnerability class, distinct from the driver-installation
        restriction and Spooler-service checks already covered.
    #>
    Write-SectionBanner 'Account & Exploit Mitigation Gaps - Print Spooler RPC Hardening'
    try {
        $printPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Print'
        $rpcPrivacy = Get-RegistryValueSafe -Path $printPath -Name 'RpcAuthnLevelPrivacyEnabled' -DefaultValue $null

        if ($rpcPrivacy -eq 1) {
            Add-AuditResult -Category 'Attack Surface Reduction & Exploit Prevention' -Control 'Print Spooler RPC Authentication Level (Privacy)' -Status 'PASS' -Severity 'High' `
                -CurrentValue 'RpcAuthnLevelPrivacyEnabled=1 (Enabled)' -RecommendedValue '1' -CIS_Control 'CIS 4.1' -NIST_Control 'SC-8, CM-7' -MITRE_Technique 'T1547.012 (Print Processors)' `
                -ISO27001_Control 'A.8.9' -NIS2_Article 'Art.21(2)(e)' -NSA_Guidance 'CISA Advisory: PrintNightmare Mitigations' -Recommendation 'No action required.'
        } else {
            Add-AuditResult -Category 'Attack Surface Reduction & Exploit Prevention' -Control 'Print Spooler RPC Authentication Level (Privacy)' -Status 'FAIL' -Severity 'High' `
                -CurrentValue 'Not Configured / Disabled' -RecommendedValue '1' -CIS_Control 'CIS 4.1' -NIST_Control 'SC-8, CM-7' -MITRE_Technique 'T1547.012 (Print Processors)' -ISO27001_Control 'A.8.9' `
                -NIS2_Article 'Art.21(2)(e)' -NSA_Guidance 'CISA Advisory: PrintNightmare Mitigations' `
                -Recommendation 'Set the print system RPC hardening GPO, which writes RpcAuthnLevelPrivacyEnabled=1 under HKLM:\SYSTEM\CurrentControlSet\Control\Print, requiring RPC_C_AUTHN_LEVEL_PKT_PRIVACY for print system RPC calls.'
        }
    } catch {
        Add-AuditResult -Category 'Attack Surface Reduction & Exploit Prevention' -Control 'Print Spooler RPC Hardening' -Status 'WARN' -Severity 'Low' -CurrentValue 'Query failed' `
            -Recommendation "Unable to query Print Spooler RPC hardening state: $($_.Exception.Message)"
    }
}

function Test-BitLockerEncryptionType {
    <#
        Audits whether each fully-encrypted BitLocker volume used Full or Used-Space-Only
        encryption via the WipingStatus field of Win32_EncryptableVolume::GetConversionStatus.
        Used Space Only leaves previously-deleted, pre-encryption file remnants recoverable
        from unallocated space until overwritten by new writes.
    #>
    Write-SectionBanner 'Volume Encryption - BitLocker Encryption Type (Used Space Only vs Full)'
    try {
        $volumes = @(Get-BitLockerVolume -ErrorAction Stop | Where-Object { $_.VolumeStatus -eq 'FullyEncrypted' })
        if ($volumes.Count -eq 0) {
            Add-AuditResult -Category 'Volume Encryption & Data-at-Rest' -Control 'BitLocker Encryption Type (Used Space Only vs Full)' -Status 'INFO' -Severity 'Informational' `
                -CurrentValue 'No fully-encrypted volumes to evaluate' -Recommendation 'See the BitLocker Encryption Status finding.'
            return
        }
        foreach ($vol in $volumes) {
            try {
                $ev = Get-CimInstance -Namespace 'root\cimv2\security\microsoftvolumeencryption' -ClassName Win32_EncryptableVolume -Filter "DriveLetter='$($vol.MountPoint)'" -ErrorAction Stop
                if (-not $ev) { continue }
                $conv = Invoke-CimMethod -InputObject $ev -MethodName GetConversionStatus -ErrorAction Stop

                if ($conv.WipingStatus -eq 0) {
                    Add-AuditResult -Category 'Volume Encryption & Data-at-Rest' -Control "BitLocker Encryption Type - $($vol.MountPoint)" -Status 'WARN' -Severity 'Medium' `
                        -CurrentValue 'Used Space Only (free space not wiped)' -RecommendedValue 'Full encryption for devices that held unencrypted data before BitLocker was enabled' -CIS_Control 'CIS 3.11' `
                        -NIST_Control 'SC-28, MP-6' -MITRE_Technique 'T1005 (Data from Local System)' -ISO27001_Control 'A.8.24' -NIS2_Article 'Art.21(2)(h)' `
                        -Recommendation "If this volume held sensitive data before BitLocker was first enabled, consider a full re-encryption pass: manage-bde -w $($vol.MountPoint) (wipes free space), or decrypt and re-enable without the -UsedSpaceOnly switch for ground-up full encryption."
                } else {
                    Add-AuditResult -Category 'Volume Encryption & Data-at-Rest' -Control "BitLocker Encryption Type - $($vol.MountPoint)" -Status 'PASS' -Severity 'Medium' `
                        -CurrentValue 'Full encryption (free space wiped)' -RecommendedValue 'Full encryption' -CIS_Control 'CIS 3.11' -NIST_Control 'SC-28, MP-6' -ISO27001_Control 'A.8.24' -NIS2_Article 'Art.21(2)(h)' `
                        -Recommendation 'No action required.'
                }
            } catch {
                Add-AuditResult -Category 'Volume Encryption & Data-at-Rest' -Control "BitLocker Encryption Type - $($vol.MountPoint)" -Status 'INFO' -Severity 'Informational' `
                    -CurrentValue 'Unable to determine Used Space Only vs Full via WMI on this build' -Recommendation 'Verify manually via manage-bde -status if this distinction matters for this device''s data sensitivity tier.'
            }
        }
    } catch {
        Add-AuditResult -Category 'Volume Encryption & Data-at-Rest' -Control 'BitLocker Encryption Type' -Status 'WARN' -Severity 'Low' -CurrentValue 'Query failed' `
            -Recommendation "Unable to complete BitLocker encryption type audit: $($_.Exception.Message)"
    }
}

function Test-BitLockerAutoUnlockExposure {
    <#
        Audits BitLocker auto-unlock on non-OS (data) volumes. Auto-unlock stores the data
        volume's unlock key protected only by the OS volume's own encryption - if the OS
        volume is ever unlocked by an attacker, the auto-unlocked data volume's protection
        is effectively bypassed too.
    #>
    Write-SectionBanner 'Volume Encryption - BitLocker Auto-Unlock Exposure (Data Volumes)'
    try {
        $dataVolumes = @(Get-BitLockerVolume -ErrorAction Stop | Where-Object { $_.VolumeType -ne 'OperatingSystem' -and $_.VolumeStatus -eq 'FullyEncrypted' })
        if ($dataVolumes.Count -eq 0) {
            Add-AuditResult -Category 'Volume Encryption & Data-at-Rest' -Control 'BitLocker Auto-Unlock Exposure' -Status 'INFO' -Severity 'Informational' `
                -CurrentValue 'No encrypted non-OS (data) volumes found' -Recommendation 'Not applicable.'
            return
        }
        $autoUnlockVolumes = @($dataVolumes | Where-Object { $_.AutoUnlockEnabled -eq $true })
        if ($autoUnlockVolumes.Count -eq 0) {
            Add-AuditResult -Category 'Volume Encryption & Data-at-Rest' -Control 'BitLocker Auto-Unlock Exposure' -Status 'PASS' -Severity 'Medium' `
                -CurrentValue 'No data volume has auto-unlock enabled' -RecommendedValue 'Auto-unlock avoided, or accepted only where the OS volume is well-protected (TPM+PIN)' -CIS_Control 'CIS 3.11' `
                -NIST_Control 'SC-28' -ISO27001_Control 'A.8.24' -NIS2_Article 'Art.21(2)(h)' -Recommendation 'No action required.'
        } else {
            $mountPoints = ($autoUnlockVolumes | ForEach-Object { $_.MountPoint }) -join ', '
            Add-AuditResult -Category 'Volume Encryption & Data-at-Rest' -Control 'BitLocker Auto-Unlock Exposure' -Status 'WARN' -Severity 'Medium' `
                -CurrentValue "Auto-unlock enabled on: $mountPoints" -RecommendedValue 'Auto-unlock avoided, or accepted only where the OS volume is well-protected (TPM+PIN)' -CIS_Control 'CIS 3.11' `
                -NIST_Control 'SC-28' -MITRE_Technique 'T1552.004 (Private Keys)' -ISO27001_Control 'A.8.24' -NIS2_Article 'Art.21(2)(h)' `
                -Recommendation 'This is a reasonable convenience trade-off only where the OS volume itself has strong protection (TPM+PIN, audited under BitLocker Key Protector Architecture). If that protection is not in place, disable with Disable-BitLockerAutoUnlock -MountPoint "<drive>".'
        }
    } catch {
        Add-AuditResult -Category 'Volume Encryption & Data-at-Rest' -Control 'BitLocker Auto-Unlock Exposure' -Status 'WARN' -Severity 'Low' -CurrentValue 'Query failed' `
            -Recommendation "Unable to query BitLocker auto-unlock configuration: $($_.Exception.Message)"
    }
}

function Test-SecureBootCertificateStatus {
    <#
        A currency-awareness item for the industry-wide expiration of the original 2011
        Microsoft UEFI CA certificates (beginning mid-2026). There is no reliable local API
        to query exact DB/DBX/KEK certificate expiration dates, so this is reported honestly
        as an awareness/verification pointer rather than a fabricated PASS/FAIL.
    #>
    Write-SectionBanner 'Hardware & Firmware - Secure Boot Certificate Currency (Awareness)'
    try {
        $secureBootEnabled = $false
        try { $secureBootEnabled = [bool](Confirm-SecureBootUEFI -ErrorAction Stop) } catch { $secureBootEnabled = $false }

        if (-not $secureBootEnabled) {
            Add-AuditResult -Category 'Hardware, Firmware & Platform Integrity' -Control 'Secure Boot Certificate Currency' -Status 'INFO' -Severity 'Informational' `
                -CurrentValue 'Secure Boot is not enabled' -Recommendation 'Not applicable - see the Secure Boot & UEFI Firmware Mode finding.'
            return
        }

        Add-AuditResult -Category 'Hardware, Firmware & Platform Integrity' -Control 'Secure Boot Certificate Currency' -Status 'INFO' -Severity 'Informational' `
            -CurrentValue 'Secure Boot enabled; exact DB/DBX/KEK certificate expiration is not reliably queryable from a simple local check' `
            -RecommendedValue 'Firmware DB/KEK/PK certificates updated ahead of the industry-wide 2026 expiration of the original 2011 Microsoft UEFI CA certificates' `
            -CIS_Control 'CIS 10.5' -NIST_Control 'SC-28, SI-7' -ISO27001_Control 'A.8.24' -NIS2_Article 'Art.21(2)(d)' `
            -Recommendation 'The original Microsoft UEFI CA 2011 certificates embedded in most PC firmware begin expiring in June 2026; OEM/Microsoft-issued updates to the Secure Boot DB/DBX/KEK are required to avoid a future boot failure or loss of Secure Boot validation. Verify this device has received the relevant Windows Update-delivered certificate updates (Microsoft KB5025885) and keep firmware/BIOS current via the OEM.'
    } catch {
        Add-AuditResult -Category 'Hardware, Firmware & Platform Integrity' -Control 'Secure Boot Certificate Currency' -Status 'WARN' -Severity 'Low' -CurrentValue 'Query failed' `
            -Recommendation "Unable to complete Secure Boot certificate awareness check: $($_.Exception.Message)"
    }
}

function Test-USBDeviceConnectionHistory {
    <#
        Enumerates historical USB storage device connections recorded under the USBSTOR
        registry branch, as a DFIR-style inventory/awareness item rather than a pass/fail
        control - device presence alone does not indicate misuse.
    #>
    Write-SectionBanner 'Removable Media - Historical USB Device Connection Inventory'
    try {
        $usbStorPath = 'HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR'
        if (-not (Test-Path -LiteralPath $usbStorPath)) {
            Add-AuditResult -Category 'Removable Media & Device Control' -Control 'Historical USB Storage Device Inventory' -Status 'INFO' -Severity 'Informational' `
                -CurrentValue 'No USBSTOR history found' -Recommendation 'No action required.'
            return
        }
        $deviceClasses = @(Get-ChildItem -LiteralPath $usbStorPath -ErrorAction SilentlyContinue)
        $deviceInstances = [System.Collections.Generic.List[string]]::new()
        foreach ($dc in $deviceClasses) {
            Get-ChildItem -LiteralPath $dc.PSPath -ErrorAction SilentlyContinue | ForEach-Object {
                $friendlyName = (Get-ItemProperty -LiteralPath $_.PSPath -Name 'FriendlyName' -ErrorAction SilentlyContinue).FriendlyName
                if (-not $friendlyName) { $friendlyName = $dc.PSChildName }
                $deviceInstances.Add($friendlyName)
            }
        }
        $uniqueDevices = @($deviceInstances | Select-Object -Unique)

        $severity = if ($uniqueDevices.Count -gt 20) { 'Low' } else { 'Informational' }
        $status = if ($uniqueDevices.Count -gt 20) { 'WARN' } else { 'INFO' }
        Add-AuditResult -Category 'Removable Media & Device Control' -Control 'Historical USB Storage Device Inventory' -Status $status -Severity $severity `
            -CurrentValue "$($uniqueDevices.Count) distinct USB storage device(s) ever connected: $(($uniqueDevices | Select-Object -First 15) -join ', ')" `
            -RecommendedValue 'A reviewable, low count consistent with expected device usage' -CIS_Control 'CIS 10.3' -NIST_Control 'MP-7' `
            -MITRE_Technique 'T1052.001 (Exfiltration over USB), T1091 (Replication Through Removable Media)' -ISO27001_Control 'A.7.10' -NIS2_Article 'Art.21(2)(g)' `
            -Recommendation 'This is a DFIR-style inventory item, not a pass/fail control. A high or unexpected device count may warrant review against expected usage; consider USB device allowlisting (Device Installation Restriction policies) if this endpoint should only connect specific known peripherals.'
    } catch {
        Add-AuditResult -Category 'Removable Media & Device Control' -Control 'Historical USB Storage Device Inventory' -Status 'WARN' -Severity 'Low' -CurrentValue 'Query failed' `
            -Recommendation "Unable to enumerate USBSTOR history: $($_.Exception.Message)"
    }
}

function Test-FirewallLoggingConfiguration {
    <#
        Audits Windows Firewall logging configuration per profile - blocked-connection
        logging (off by default, and the single most useful signal for detecting network
        reconnaissance/scanning) and log file size (the default is small and rolls over
        quickly on an active endpoint).
    #>
    Write-SectionBanner 'Network & Share Hardening - Windows Firewall Logging Configuration'
    try {
        $profiles = @(Get-NetFirewallProfile -ErrorAction Stop)
        foreach ($p in $profiles) {
            if ($p.LogBlocked -eq $true) {
                Add-AuditResult -Category 'Network Architecture & Protocol Hardening' -Control "Firewall Logging - $($p.Name) Profile (Blocked Connections)" -Status 'PASS' -Severity 'Medium' `
                    -CurrentValue 'LogBlocked=True' -RecommendedValue 'True' -CIS_Control 'CIS 4.4' -NIST_Control 'AU-2, AU-12' -MITRE_Technique 'T1562.004 (Disable or Modify System Firewall)' `
                    -ISO27001_Control 'A.8.15' -NIS2_Article 'Art.21(2)(b)' -NSA_Guidance 'NSA/CISA Audit Logging Best Practices' -Recommendation 'No action required.'
            } else {
                Add-AuditResult -Category 'Network Architecture & Protocol Hardening' -Control "Firewall Logging - $($p.Name) Profile (Blocked Connections)" -Status 'FAIL' -Severity 'Medium' `
                    -CurrentValue 'LogBlocked=False' -RecommendedValue 'True' -CIS_Control 'CIS 4.4' -NIST_Control 'AU-2, AU-12' -MITRE_Technique 'T1562.004 (Disable or Modify System Firewall)' `
                    -ISO27001_Control 'A.8.15' -NIS2_Article 'Art.21(2)(b)' -NSA_Guidance 'NSA/CISA Audit Logging Best Practices' `
                    -Recommendation "Set-NetFirewallProfile -Profile $($p.Name) -LogBlocked True. Blocked-connection logging provides network reconnaissance/scan visibility that is otherwise invisible - it is off by default and frequently overlooked."
            }

            $logSizeKb = $p.LogMaxSizeKilobytes
            if ($logSizeKb -ge 16384) {
                Add-AuditResult -Category 'Network Architecture & Protocol Hardening' -Control "Firewall Log Size - $($p.Name) Profile" -Status 'PASS' -Severity 'Low' `
                    -CurrentValue "$logSizeKb KB" -RecommendedValue '>= 16384 KB' -CIS_Control 'CIS 8.3' -NIST_Control 'AU-4, AU-11' -ISO27001_Control 'A.8.15' -NIS2_Article 'Art.21(2)(b)' -Recommendation 'No action required.'
            } else {
                Add-AuditResult -Category 'Network Architecture & Protocol Hardening' -Control "Firewall Log Size - $($p.Name) Profile" -Status 'WARN' -Severity 'Low' `
                    -CurrentValue "$logSizeKb KB (default is frequently 4096 KB)" -RecommendedValue '>= 16384 KB' -CIS_Control 'CIS 8.3' -NIST_Control 'AU-4, AU-11' -ISO27001_Control 'A.8.15' -NIS2_Article 'Art.21(2)(b)' `
                    -Recommendation "Increase via Set-NetFirewallProfile -Profile $($p.Name) -LogMaxSizeKilobytes 16384. The default log size rolls over quickly on an active endpoint, losing historical connection evidence."
            }
        }
    } catch {
        Add-AuditResult -Category 'Network Architecture & Protocol Hardening' -Control 'Windows Firewall Logging Configuration' -Status 'WARN' -Severity 'Low' -CurrentValue 'Query failed' `
            -Recommendation "Unable to query firewall logging configuration: $($_.Exception.Message)"
    }
}

function Test-FirewallInboundActiveRulesInventory {
    <#
        Inventories every currently-enabled inbound firewall rule with its port/protocol
        and, where the rule is scoped to a specific program, the bound binary - flagging a
        binary that is missing on disk, unsigned, or sitting in a user-writable location so
        a reviewer can spot a suspicious listener without manually walking every rule in the
        Windows Firewall console. Complements (not replaces) Test-FirewallRuleBroadAllowRules,
        which only targets a fixed list of high-risk ports opened to any remote address.
    #>
    Write-SectionBanner 'Network Architecture - Active Inbound Firewall Rules Inventory'
    try {
        $rules = @(Get-NetFirewallRule -Direction Inbound -Enabled True -ErrorAction Stop)
        if ($rules.Count -eq 0) {
            Add-AuditResult -Category 'Network Architecture & Protocol Hardening' -Control 'Active Inbound Firewall Rules Inventory' -Status 'INFO' -Severity 'Informational' `
                -CurrentValue 'No enabled inbound firewall rules found' -Recommendation 'No action required.'
            return
        }

        $sigCache = @{}
        $ruleLines = [System.Collections.Generic.List[string]]::new()
        $notableLines = [System.Collections.Generic.List[string]]::new()

        foreach ($rule in $rules) {
            try {
                $portFilter = $rule | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue
                $appFilter  = $rule | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue

                $proto = if ($portFilter -and $portFilter.Protocol -and $portFilter.Protocol -ne 'Any') { $portFilter.Protocol } else { 'Any' }
                $port  = if ($portFilter -and $portFilter.LocalPort) { ($portFilter.LocalPort -join ',') } else { 'Any' }

                $program = if ($appFilter -and $appFilter.Program -and $appFilter.Program -notin @('Any', 'System')) { $appFilter.Program } else { $null }

                $binaryNote = 'not bound to a specific binary'
                if ($program) {
                    $expandedPath = [System.Environment]::ExpandEnvironmentVariables($program)
                    if (Test-Path -LiteralPath $expandedPath -PathType Leaf -ErrorAction SilentlyContinue) {
                        if (-not $sigCache.ContainsKey($expandedPath)) {
                            try { $sigCache[$expandedPath] = (Get-AuthenticodeSignature -LiteralPath $expandedPath -ErrorAction Stop).Status } catch { $sigCache[$expandedPath] = 'Unknown' }
                        }
                        $sigStatus = $sigCache[$expandedPath]

                        $writable = ($expandedPath -match '(?i)\\Users\\[^\\]+\\(AppData|Downloads|Desktop)\\' -or $expandedPath -match '(?i)\\Temp\\')

                        $binaryNote = "bound to $expandedPath [Signature=$sigStatus]"
                        if ($writable) { $binaryNote += ' [user-writable path]' }

                        if ($sigStatus -ne 'Valid') {
                            $notableLines.Add("$($rule.DisplayName): bound binary '$expandedPath' signature status is '$sigStatus'")
                        }
                        if ($writable) {
                            $notableLines.Add("$($rule.DisplayName): bound binary '$expandedPath' resides in a user-writable location")
                        }
                    } else {
                        $binaryNote = "bound to $expandedPath [file not found on disk]"
                        $notableLines.Add("$($rule.DisplayName): bound binary '$expandedPath' does not exist on disk")
                    }
                }

                $ruleLines.Add("$($rule.DisplayName) [Action=$($rule.Action); Protocol=$proto; Port=$port; Profile=$($rule.Profile)] - $binaryNote")
            } catch { }
        }

        $allowCount = @($rules | Where-Object { $_.Action -eq 'Allow' }).Count
        $shown = @($ruleLines | Select-Object -First 80)
        $truncatedNote = if ($ruleLines.Count -gt 80) { " (showing first 80 of $($ruleLines.Count))" } else { '' }
        $summary = "$($rules.Count) enabled inbound rule(s), $allowCount Allow$($truncatedNote): $($shown -join ' | ')"

        if ($notableLines.Count -gt 0) {
            $uniqueNotable = @($notableLines | Select-Object -Unique)
            Add-AuditResult -Category 'Network Architecture & Protocol Hardening' -Control 'Active Inbound Firewall Rules Inventory' -Status 'WARN' -Severity 'Medium' `
                -CurrentValue $summary -RecommendedValue 'All program-bound rules reference a present, Authenticode-signed binary outside user-writable locations' `
                -CIS_Control 'CIS 4.4' -NIST_Control 'SC-7, CM-7' -MITRE_Technique 'T1071 (Application Layer Protocol), T1218 (Signed Binary Proxy Execution)' `
                -ISO27001_Control 'A.8.20' -NIS2_Article 'Art.21(2)(d)' -NSA_Guidance 'NSA/CISA Host-Based Firewall Guidance' `
                -Recommendation "Review the following notable rule(s): $($uniqueNotable -join ' | '). A rule bound to a missing, unsigned, or user-writable-path binary can indicate stale/leftover software or a persistence mechanism disguising itself as a legitimate listener."
        } else {
            Add-AuditResult -Category 'Network Architecture & Protocol Hardening' -Control 'Active Inbound Firewall Rules Inventory' -Status 'INFO' -Severity 'Informational' `
                -CurrentValue $summary -RecommendedValue 'Reviewed periodically against expected listening services' `
                -CIS_Control 'CIS 4.4' -NIST_Control 'SC-7, CM-7' -ISO27001_Control 'A.8.20' -NIS2_Article 'Art.21(2)(d)' `
                -Recommendation 'No action required. Full inventory of active inbound rules (name, port/protocol, profile, bound binary) for review against expected listening services.'
        }
    } catch {
        Add-AuditResult -Category 'Network Architecture & Protocol Hardening' -Control 'Active Inbound Firewall Rules Inventory' -Status 'WARN' -Severity 'Low' -CurrentValue 'Query failed' `
            -Recommendation "Unable to enumerate inbound firewall rules: $($_.Exception.Message)"
    }
}

function Test-HostsFileIntegrity {
    <#
        Audits C:\Windows\System32\drivers\etc\hosts for tampering: active (uncommented)
        entries - especially ones redirecting Windows Update, Microsoft, or well-known
        security-vendor domains, a classic technique for blocking updates/AV telemetry or
        performing local DNS-level MITM - and whether standard users can write to the file
        at all (the default ACL restricts writes to SYSTEM/Administrators).
    #>
    Write-SectionBanner 'Network Architecture - Hosts File Integrity'
    try {
        $hostsPath = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
        if (-not (Test-Path -LiteralPath $hostsPath -PathType Leaf -ErrorAction SilentlyContinue)) {
            Add-AuditResult -Category 'Network Architecture & Protocol Hardening' -Control 'Hosts File Integrity' -Status 'WARN' -Severity 'Low' `
                -CurrentValue 'hosts file not found' -Recommendation "Expected file not present at $hostsPath - unusual for a Windows installation; verify system integrity."
            return
        }

        $rawLines = @(Get-Content -LiteralPath $hostsPath -ErrorAction Stop)
        $activeEntries = [System.Collections.Generic.List[string]]::new()
        foreach ($line in $rawLines) {
            $trimmed = $line.Trim()
            if ([string]::IsNullOrWhiteSpace($trimmed) -or $trimmed.StartsWith('#')) { continue }
            $codePart = ($trimmed -split '#')[0].Trim()
            if ([string]::IsNullOrWhiteSpace($codePart)) { continue }
            if ($codePart -match '^(?<ip>\S+)\s+(?<hostname>\S+)') {
                $activeEntries.Add("$($Matches.ip) -> $($Matches.hostname)")
            }
        }

        $sensitiveDomainPattern = '(?i)(windowsupdate\.com|microsoft\.com|msftconnecttest\.com|sfx\.ms|digicert\.com|sectigo\.com|globalsign\.com|verisign\.com|symantec\.com|mcafee\.com|crowdstrike\.com|sentinelone\.com|avast\.com|kaspersky\.com|malwarebytes\.com|virustotal\.com|wdcp\.microsoft\.com|wd\.microsoft\.com)'
        $suspiciousEntries = @($activeEntries | Where-Object { $_ -match $sensitiveDomainPattern })

        $writableByStandardUser = $false
        try {
            $acl = Get-Acl -LiteralPath $hostsPath -ErrorAction Stop
            foreach ($ace in $acl.Access) {
                if ($ace.AccessControlType -eq 'Allow' -and ($ace.FileSystemRights -match 'Write|FullControl|Modify') -and
                    ($ace.IdentityReference.Value -match '(?i)Everyone|BUILTIN\\Users|Authenticated Users')) {
                    $writableByStandardUser = $true
                }
            }
        } catch { }

        if ($suspiciousEntries.Count -gt 0) {
            Add-AuditResult -Category 'Network Architecture & Protocol Hardening' -Control 'Hosts File Integrity' -Status 'FAIL' -Severity 'Critical' `
                -CurrentValue "$($activeEntries.Count) active entry/entries, including sensitive-domain redirect(s): $($suspiciousEntries -join ' | ')" `
                -RecommendedValue 'No active hosts file entries redirecting Windows Update, Microsoft, or security-vendor domains' -CIS_Control 'CIS 9.2' -NIST_Control 'SC-20, SI-4' `
                -MITRE_Technique 'T1565.001 (Stored Data Manipulation), T1584.004 (Compromise Infrastructure: Server)' -ISO27001_Control 'A.8.20' -NIS2_Article 'Art.21(2)(d)' -NSA_Guidance 'NSA/CISA Reduce Exposure - Network Protocol Poisoning' `
                -Recommendation "Review $hostsPath immediately - it is redirecting a Windows Update, Microsoft, or security-vendor domain, a common technique for blocking updates/telemetry or intercepting traffic. Remove the offending line(s) unless explicitly and knowingly configured by IT, and investigate how the entry was added."
        } elseif ($activeEntries.Count -gt 0) {
            Add-AuditResult -Category 'Network Architecture & Protocol Hardening' -Control 'Hosts File Integrity' -Status 'WARN' -Severity 'Medium' `
                -CurrentValue "$($activeEntries.Count) active entry/entries: $($activeEntries -join ' | ')" `
                -RecommendedValue 'No unexpected active hosts file entries (or only known, IT-approved entries)' -CIS_Control 'CIS 9.2' -NIST_Control 'SC-20, SI-4' `
                -MITRE_Technique 'T1565.001 (Stored Data Manipulation)' -ISO27001_Control 'A.8.20' -NIS2_Article 'Art.21(2)(d)' `
                -Recommendation "Review each entry in $hostsPath. Custom entries are sometimes legitimate (local development, internal hostname overrides) but should be verified against IT-approved changes."
        } else {
            Add-AuditResult -Category 'Network Architecture & Protocol Hardening' -Control 'Hosts File Integrity' -Status 'PASS' -Severity 'Medium' `
                -CurrentValue 'No active (uncommented) entries' -RecommendedValue 'No active hosts file entries' -CIS_Control 'CIS 9.2' -NIST_Control 'SC-20, SI-4' `
                -ISO27001_Control 'A.8.20' -NIS2_Article 'Art.21(2)(d)' -Recommendation 'No action required.'
        }

        if ($writableByStandardUser) {
            Add-AuditResult -Category 'Network Architecture & Protocol Hardening' -Control 'Hosts File Write Permissions' -Status 'FAIL' -Severity 'High' `
                -CurrentValue 'Everyone/Authenticated Users/BUILTIN\Users has Write, Modify, or Full Control' -RecommendedValue 'Write access restricted to SYSTEM and Administrators only' `
                -CIS_Control 'CIS 9.2' -NIST_Control 'AC-3, AC-6' -MITRE_Technique 'T1565.001 (Stored Data Manipulation)' -ISO27001_Control 'A.8.3' -NIS2_Article 'Art.21(2)(d)' `
                -Recommendation "Restore the default ACL on $hostsPath so only SYSTEM and Administrators can write to it, then remove any Write/Modify/FullControl grant to Everyone/Users/Authenticated Users."
        } else {
            Add-AuditResult -Category 'Network Architecture & Protocol Hardening' -Control 'Hosts File Write Permissions' -Status 'PASS' -Severity 'High' `
                -CurrentValue 'Write access restricted to SYSTEM/Administrators' -RecommendedValue 'Write access restricted to SYSTEM and Administrators only' -CIS_Control 'CIS 9.2' `
                -NIST_Control 'AC-3, AC-6' -ISO27001_Control 'A.8.3' -NIS2_Article 'Art.21(2)(d)' -Recommendation 'No action required.'
        }
    } catch {
        Add-AuditResult -Category 'Network Architecture & Protocol Hardening' -Control 'Hosts File Integrity' -Status 'WARN' -Severity 'Low' -CurrentValue 'Query failed' `
            -Recommendation "Unable to audit hosts file: $($_.Exception.Message)"
    }
}

#endregion

#region ============================== 33. TARGETED GAP CLOSURE - CREDENTIAL, KERNEL, NETWORK & PRIVACY ==============================

function Test-LSASSCrashDumpExposure {
    <#
        Audits Windows Error Reporting LocalDumps configuration for LSASS. A full crash
        dump captures the same in-memory secrets a live LSASS memory dump would (NTLM
        hashes, Kerberos tickets, and plaintext passwords if WDigest is misconfigured), and
        if a crash is ever triggered, the resulting .dmp file can be exfiltrated at leisure -
        an alternate path to the same outcome LSA Protection is meant to prevent.
    #>
    Write-SectionBanner 'Credential Exposure - LSASS Crash Dump (WER) Exposure'
    try {
        $werGlobalPath = 'HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps'
        $werLsassPath = Join-Path $werGlobalPath 'lsass.exe'
        $globalDumpType = Get-RegistryValueSafe -Path $werGlobalPath -Name 'DumpType' -DefaultValue $null
        $lsassDumpType = Get-RegistryValueSafe -Path $werLsassPath -Name 'DumpType' -DefaultValue $null
        $effectiveDumpType = if ($null -ne $lsassDumpType) { $lsassDumpType } else { $globalDumpType }

        if ($null -eq $effectiveDumpType) {
            Add-AuditResult -Category 'Credential Exposure & Secret Leaks' -Control 'LSASS Crash Dump (WER) Exposure' -Status 'PASS' -Severity 'High' `
                -CurrentValue 'No LocalDumps policy configured for LSASS or globally' -RecommendedValue 'Not configured, or DumpType != Full (2) for lsass.exe' -CIS_Control 'CIS 18.3' `
                -NIST_Control 'SC-28, AU-4' -MITRE_Technique 'T1003.001 (LSASS Memory)' -ISO27001_Control 'A.8.5' -NIS2_Article 'Art.21(2)(h)' -NSA_Guidance 'NSA CSI: Mitigating Credential Theft' `
                -Recommendation 'No action required.'
        } elseif ([int]$effectiveDumpType -eq 2) {
            Add-AuditResult -Category 'Credential Exposure & Secret Leaks' -Control 'LSASS Crash Dump (WER) Exposure' -Status 'FAIL' -Severity 'High' `
                -CurrentValue 'DumpType=2 (Full dump) configured for LSASS or globally' -RecommendedValue 'Not configured, or DumpType != Full (2) for lsass.exe' -CIS_Control 'CIS 18.3' `
                -NIST_Control 'SC-28, AU-4' -MITRE_Technique 'T1003.001 (LSASS Memory)' -ISO27001_Control 'A.8.5' -NIS2_Article 'Art.21(2)(h)' -NSA_Guidance 'NSA CSI: Mitigating Credential Theft' `
                -Recommendation 'Remove or reduce the WER LocalDumps DumpType for lsass.exe. A full crash dump of LSASS contains the same in-memory secrets a live memory dump would, and the resulting .dmp file can be exfiltrated at leisure from the configured DumpFolder if a crash is ever triggered.'
        } else {
            Add-AuditResult -Category 'Credential Exposure & Secret Leaks' -Control 'LSASS Crash Dump (WER) Exposure' -Status 'PASS' -Severity 'High' `
                -CurrentValue "DumpType=$effectiveDumpType (not Full)" -RecommendedValue 'Not configured, or DumpType != Full (2) for lsass.exe' -CIS_Control 'CIS 18.3' -NIST_Control 'SC-28, AU-4' `
                -ISO27001_Control 'A.8.5' -NIS2_Article 'Art.21(2)(h)' -Recommendation 'No action required.'
        }
    } catch {
        Add-AuditResult -Category 'Credential Exposure & Secret Leaks' -Control 'LSASS Crash Dump (WER) Exposure' -Status 'WARN' -Severity 'Low' -CurrentValue 'Query failed' `
            -Recommendation "Unable to query WER LocalDumps configuration: $($_.Exception.Message)"
    }
}

function Test-CredentialGuardUEFILock {
    <#
        Audits whether a running Credential Guard is UEFI-locked (LsaCfgFlags=1). Without
        the lock, Credential Guard can be disabled remotely with a registry change plus
        reboot; UEFI-locked Credential Guard requires physical console presence to disable,
        materially raising the bar for an attacker who has obtained local admin rights.
    #>
    Write-SectionBanner 'Virtualization-Based Security - Credential Guard UEFI Lock Mode'
    try {
        $dg = Get-DeviceGuardStatus
        $running = @()
        if ($dg -and $dg.SecurityServicesRunning) { $running = $dg.SecurityServicesRunning }
        if ($running -notcontains 1) {
            Add-AuditResult -Category 'Virtualization-Based Security' -Control 'Credential Guard UEFI Lock Mode' -Status 'INFO' -Severity 'Informational' `
                -CurrentValue 'Credential Guard is not running' -Recommendation 'Not applicable - see the Credential Guard finding.'
            return
        }
        $lsaCfgFlags = Get-RegistryValueSafe -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\LSA' -Name 'LsaCfgFlags' -DefaultValue $null

        if ($lsaCfgFlags -eq 1) {
            Add-AuditResult -Category 'Virtualization-Based Security' -Control 'Credential Guard UEFI Lock Mode' -Status 'PASS' -Severity 'High' `
                -CurrentValue 'LsaCfgFlags=1 (Enabled with UEFI Lock)' -RecommendedValue '1 (UEFI Lock)' -CIS_Control 'CIS 18.4' -NIST_Control 'IA-5, SC-28' `
                -MITRE_Technique 'T1562.001 (Disable or Modify Tools)' -ISO27001_Control 'A.8.5' -NIS2_Article 'Art.21(2)(i)' -NSA_Guidance 'NSA CSI: Mitigating Credential Theft' -Recommendation 'No action required.'
        } else {
            Add-AuditResult -Category 'Virtualization-Based Security' -Control 'Credential Guard UEFI Lock Mode' -Status 'WARN' -Severity 'Medium' `
                -CurrentValue "LsaCfgFlags=$lsaCfgFlags (Enabled without UEFI Lock)" -RecommendedValue '1 (UEFI Lock)' -CIS_Control 'CIS 18.4' -NIST_Control 'IA-5, SC-28' -ISO27001_Control 'A.8.5' `
                -NIS2_Article 'Art.21(2)(i)' `
                -Recommendation 'Set LsaCfgFlags=1 via GPO "Turn On Virtualization Based Security" > Credential Guard Configuration = "Enabled with UEFI lock". Without the lock, a registry change plus reboot alone can disable Credential Guard.'
        }
    } catch {
        Add-AuditResult -Category 'Virtualization-Based Security' -Control 'Credential Guard UEFI Lock Mode' -Status 'WARN' -Severity 'Low' -CurrentValue 'Query failed' `
            -Recommendation "Unable to query Credential Guard lock mode: $($_.Exception.Message)"
    }
}

function Test-SafeDllSearchMode {
    <#
        Audits Safe DLL Search Mode, which - when enabled (the default) - places the system
        directories ahead of the current working directory in the DLL load search order. If
        disabled, any application launched from a user-writable/untrusted directory becomes
        substantially easier to hijack via a planted, identically-named malicious DLL.
    #>
    Write-SectionBanner 'Privilege Escalation - Safe DLL Search Mode'
    try {
        $path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
        $safeMode = Get-RegistryValueSafe -Path $path -Name 'SafeDllSearchMode' -DefaultValue 1

        if ([int]$safeMode -eq 1) {
            Add-AuditResult -Category 'Privilege Escalation - Service & File Permissions' -Control 'Safe DLL Search Mode' -Status 'PASS' -Severity 'High' `
                -CurrentValue 'Enabled (default)' -RecommendedValue 'Enabled' -CIS_Control 'CIS 18.3' -NIST_Control 'CM-7, SI-7' -MITRE_Technique 'T1574.001 (DLL Search Order Hijacking)' `
                -ISO27001_Control 'A.8.19' -NIS2_Article 'Art.21(2)(e)' -Recommendation 'No action required.'
        } else {
            Add-AuditResult -Category 'Privilege Escalation - Service & File Permissions' -Control 'Safe DLL Search Mode' -Status 'FAIL' -Severity 'High' `
                -CurrentValue 'SafeDllSearchMode=0 (Disabled)' -RecommendedValue 'Enabled (1, or not present)' -CIS_Control 'CIS 18.3' -NIST_Control 'CM-7, SI-7' `
                -MITRE_Technique 'T1574.001 (DLL Search Order Hijacking)' -ISO27001_Control 'A.8.19' -NIS2_Article 'Art.21(2)(e)' `
                -Recommendation 'Remove the SafeDllSearchMode value (or set it to 1) under HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager. With this disabled, the current working directory is searched for DLLs before the system directories, making DLL search-order hijacking dramatically easier.'
        }
    } catch {
        Add-AuditResult -Category 'Privilege Escalation - Service & File Permissions' -Control 'Safe DLL Search Mode' -Status 'WARN' -Severity 'Low' -CurrentValue 'Query failed' `
            -Recommendation "Unable to query SafeDllSearchMode: $($_.Exception.Message)"
    }
}

function Test-KernelDriverSignatureBypass {
    <#
        Audits the boot configuration flag "nointegritychecks", which - distinct from Test
        Signing Mode - disables kernel-mode driver signature enforcement outright and has no
        legitimate production use case; its presence is a strong bootkit/rootkit indicator.
    #>
    Write-SectionBanner 'Kernel & Driver Security - Kernel Driver Signature Enforcement Bypass (BCD)'
    try {
        $bcdOutput = & bcdedit.exe /enum '{current}' 2>$null
        if (-not $bcdOutput) { throw 'bcdedit.exe returned no output' }

        $noIntegrityLine = $bcdOutput | Where-Object { $_ -match '(?i)nointegritychecks' } | Select-Object -First 1
        $noIntegrityOn = $noIntegrityLine -and ($noIntegrityLine -match '(?i)Yes')

        if ($noIntegrityOn) {
            Add-AuditResult -Category 'Kernel & Driver Security' -Control 'Kernel Driver Signature Enforcement (BCD nointegritychecks)' -Status 'FAIL' -Severity 'Critical' `
                -CurrentValue 'nointegritychecks=Yes' -RecommendedValue 'Not set / No' -CIS_Control 'CIS 10.5' -NIST_Control 'SI-7, CM-7' `
                -MITRE_Technique 'T1014 (Rootkit), T1068 (Exploitation for Privilege Escalation)' -ISO27001_Control 'A.8.7' -NIS2_Article 'Art.21(2)(e)' `
                -Recommendation 'Run "bcdedit /set nointegritychecks off" and reboot. This boot flag disables kernel-mode driver signature enforcement entirely and is a classic bootkit/rootkit persistence indicator - it should never be present on a production endpoint.'
        } else {
            Add-AuditResult -Category 'Kernel & Driver Security' -Control 'Kernel Driver Signature Enforcement (BCD nointegritychecks)' -Status 'PASS' -Severity 'Critical' `
                -CurrentValue 'Not set (enforcement active)' -RecommendedValue 'Not set / No' -CIS_Control 'CIS 10.5' -NIST_Control 'SI-7, CM-7' -ISO27001_Control 'A.8.7' -NIS2_Article 'Art.21(2)(e)' `
                -Recommendation 'No action required.'
        }
    } catch {
        Add-AuditResult -Category 'Kernel & Driver Security' -Control 'Kernel Driver Signature Enforcement (BCD)' -Status 'WARN' -Severity 'Low' -CurrentValue 'Query failed' `
            -Recommendation "Unable to query BCD driver signature enforcement state: $($_.Exception.Message)"
    }
}

function Test-CPUSpeculativeExecutionMitigationOverride {
    <#
        Reports whether a CPU speculative-execution (Spectre/Meltdown-class) mitigation
        override is present. These are bitmask values that can selectively disable specific
        mitigations for performance - precise bit-level interpretation is not attempted here
        (accuracy risk); presence alone is reported for manual review against Microsoft
        KB4073119, since disabling the wrong mitigation can reopen a cross-process/cross-VM
        information-disclosure side channel.
    #>
    Write-SectionBanner 'Kernel & Driver Security - CPU Speculative Execution Mitigation Override'
    try {
        $mmPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management'
        $override = Get-RegistryValueSafe -Path $mmPath -Name 'FeatureSettingsOverride' -DefaultValue $null
        $overrideMask = Get-RegistryValueSafe -Path $mmPath -Name 'FeatureSettingsOverrideMask' -DefaultValue $null

        if ($null -eq $override -and $null -eq $overrideMask) {
            Add-AuditResult -Category 'Attack Surface Reduction & Exploit Prevention' -Control 'CPU Speculative Execution Mitigation Override' -Status 'PASS' -Severity 'Medium' `
                -CurrentValue 'No override present (OS default mitigations apply)' -RecommendedValue 'No override present' -CIS_Control 'CIS 10.5' -NIST_Control 'SI-16, SC-39' `
                -MITRE_Technique 'T1499 (Endpoint Denial of Service)' -ISO27001_Control 'A.8.7' -NIS2_Article 'Art.21(2)(b)' -Recommendation 'No action required.'
        } else {
            Add-AuditResult -Category 'Attack Surface Reduction & Exploit Prevention' -Control 'CPU Speculative Execution Mitigation Override' -Status 'WARN' -Severity 'Medium' `
                -CurrentValue "FeatureSettingsOverride=$override; FeatureSettingsOverrideMask=$overrideMask" -RecommendedValue 'No override present' -CIS_Control 'CIS 10.5' -NIST_Control 'SI-16, SC-39' `
                -ISO27001_Control 'A.8.7' -NIS2_Article 'Art.21(2)(b)' `
                -Recommendation 'A speculative-execution mitigation override is explicitly configured. These bitmask values are commonly set to trade security for performance; verify the specific bits in use are intentional and documented (Microsoft KB4073119) rather than a leftover troubleshooting change.'
        }
    } catch {
        Add-AuditResult -Category 'Attack Surface Reduction & Exploit Prevention' -Control 'CPU Speculative Execution Mitigation Override' -Status 'WARN' -Severity 'Low' -CurrentValue 'Query failed' `
            -Recommendation "Unable to query speculative execution mitigation override state: $($_.Exception.Message)"
    }
}

function Test-NetworkDiscoveryPublicProfileExposure {
    <#
        Audits whether the built-in Network Discovery firewall rule group (SSDP, Function
        Discovery, NetBIOS-based discovery) is enabled on the Public profile, which would
        broadcast this device's presence to every other host on an untrusted network segment
        such as coffee-shop or hotel Wi-Fi.
    #>
    Write-SectionBanner 'Network Architecture - Network Discovery Exposure on Public Profile'
    try {
        $rules = @(Get-NetFirewallRule -DisplayGroup 'Network Discovery' -ErrorAction Stop | Where-Object { $_.Enabled -eq 'True' })
        $publicExposed = @($rules | Where-Object { $_.Profile -match 'Public' -or $_.Profile -eq 'Any' })

        if ($publicExposed.Count -eq 0) {
            Add-AuditResult -Category 'Network Architecture & Protocol Hardening' -Control 'Network Discovery (SSDP/Function Discovery) on Public Profile' -Status 'PASS' -Severity 'Medium' `
                -CurrentValue 'No enabled Network Discovery firewall rules apply to the Public profile' -RecommendedValue 'Network Discovery disabled on the Public profile' -CIS_Control 'CIS 4.4' `
                -NIST_Control 'SC-7, CM-7' -MITRE_Technique 'T1046 (Network Service Discovery)' -ISO27001_Control 'A.8.20' -NIS2_Article 'Art.21(2)(d)' -Recommendation 'No action required.'
        } else {
            $names = ($publicExposed | ForEach-Object { $_.DisplayName }) -join ', '
            Add-AuditResult -Category 'Network Architecture & Protocol Hardening' -Control 'Network Discovery (SSDP/Function Discovery) on Public Profile' -Status 'FAIL' -Severity 'Medium' `
                -CurrentValue "Enabled on Public profile: $names" -RecommendedValue 'Network Discovery disabled on the Public profile' -CIS_Control 'CIS 4.4' -NIST_Control 'SC-7, CM-7' `
                -MITRE_Technique 'T1046 (Network Service Discovery)' -ISO27001_Control 'A.8.20' -NIS2_Article 'Art.21(2)(d)' `
                -Recommendation 'Disable the Network Discovery rule group for the Public profile: Set-NetFirewallRule -DisplayGroup "Network Discovery" -Profile Public -Enabled False. On an untrusted network, Network Discovery/SSDP broadcasts make this device trivially discoverable to every other device on the same segment.'
        }
    } catch {
        Add-AuditResult -Category 'Network Architecture & Protocol Hardening' -Control 'Network Discovery Exposure' -Status 'WARN' -Severity 'Low' -CurrentValue 'Query failed' `
            -Recommendation "Unable to query Network Discovery firewall rules: $($_.Exception.Message)"
    }
}

function Test-OneDriveKnownFolderMove {
    <#
        Audits whether Desktop/Documents/Pictures are redirected to a OneDrive-managed path
        for the current profile context - a real ransomware/data-loss resilience control
        (continuous cloud versioning of default user data locations) distinct from the
        local-only VSS/System Restore controls audited earlier.
    #>
    Write-SectionBanner 'Ransomware Recovery & Resilience - OneDrive Known Folder Move'
    try {
        $shellFoldersPath = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders'
        $desktop = Get-RegistryValueSafe -Path $shellFoldersPath -Name 'Desktop' -DefaultValue ''
        $documents = Get-RegistryValueSafe -Path $shellFoldersPath -Name 'Personal' -DefaultValue ''
        $pictures = Get-RegistryValueSafe -Path $shellFoldersPath -Name 'My Pictures' -DefaultValue ''
        $redirectedCount = @(@($desktop, $documents, $pictures) | Where-Object { $_ -match '(?i)OneDrive' }).Count

        if ($redirectedCount -eq 3) {
            Add-AuditResult -Category 'Ransomware Recovery & Resilience' -Control 'OneDrive Known Folder Move (Cloud Backup Redirection)' -Status 'PASS' -Severity 'Medium' `
                -CurrentValue 'Desktop, Documents, and Pictures are all redirected under a OneDrive path' -RecommendedValue 'All three Known Folders redirected to OneDrive (or an equivalent managed cloud backup)' `
                -CIS_Control 'CIS 10.1' -NIST_Control 'CP-9' -MITRE_Technique 'T1486 (Data Encrypted for Impact)' -ISO27001_Control 'A.8.13' -NIS2_Article 'Art.21(2)(c)' -Recommendation 'No action required.'
        } elseif ($redirectedCount -gt 0) {
            Add-AuditResult -Category 'Ransomware Recovery & Resilience' -Control 'OneDrive Known Folder Move (Cloud Backup Redirection)' -Status 'WARN' -Severity 'Medium' `
                -CurrentValue "$redirectedCount of 3 Known Folders (Desktop/Documents/Pictures) redirected to OneDrive" -RecommendedValue 'All three Known Folders redirected to OneDrive' -CIS_Control 'CIS 10.1' `
                -NIST_Control 'CP-9' -MITRE_Technique 'T1486 (Data Encrypted for Impact)' -ISO27001_Control 'A.8.13' -NIS2_Article 'Art.21(2)(c)' `
                -Recommendation 'Complete Known Folder Move for the remaining folder(s) via the OneDrive client (Settings > Sync and backup > Manage backup) or the "Silently move Windows known folders to OneDrive" GPO/Intune policy.'
        } else {
            Add-AuditResult -Category 'Ransomware Recovery & Resilience' -Control 'OneDrive Known Folder Move (Cloud Backup Redirection)' -Status 'INFO' -Severity 'Informational' `
                -CurrentValue 'No Known Folders are redirected to OneDrive for this profile context' -RecommendedValue 'Known Folders redirected to OneDrive, or an equivalent managed backup solution in place' `
                -CIS_Control 'CIS 10.1' -NIST_Control 'CP-9' -ISO27001_Control 'A.8.13' -NIS2_Article 'Art.21(2)(c)' `
                -Recommendation 'This finding reflects the elevated administrator''s own profile context, which may differ from the primary end user''s profile. If this organization does not use OneDrive, confirm an equivalent managed backup solution protects user data on this endpoint.'
        }
    } catch {
        Add-AuditResult -Category 'Ransomware Recovery & Resilience' -Control 'OneDrive Known Folder Move' -Status 'WARN' -Severity 'Low' -CurrentValue 'Query failed' `
            -Recommendation "Unable to query Known Folder redirection state: $($_.Exception.Message)"
    }
}

function Test-SysmonPresence {
    <#
        Reports Sysmon (System Monitor) service presence as a telemetry-depth awareness
        item. Rule-configuration quality cannot be reliably audited generically (schema and
        rule sets vary widely by version/deployment), so this deliberately stops at presence
        rather than asserting a judgement about coverage this script cannot verify.
    #>
    Write-SectionBanner 'Advanced Security Auditing - Sysmon Presence'
    try {
        $sysmonService = Get-Service -Name 'Sysmon*' -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($sysmonService -and $sysmonService.Status -eq 'Running') {
            Add-AuditResult -Category 'Advanced Security Auditing & Event Logging' -Control 'Sysmon (System Monitor) Presence' -Status 'PASS' -Severity 'Medium' `
                -CurrentValue "Service '$($sysmonService.Name)' running" -RecommendedValue 'Present and running, with a maintained rule configuration' -CIS_Control 'CIS 8.5' -NIST_Control 'AU-2, AU-12' `
                -MITRE_Technique 'T1562.001 (Disable or Modify Tools)' -ISO27001_Control 'A.8.15' -NIS2_Article 'Art.21(2)(b)' -NSA_Guidance 'NSA/CISA Audit Logging Best Practices' `
                -Recommendation 'No action required from a presence standpoint. Verify separately that the loaded configuration covers process creation, network connection, and image/driver load events at minimum.'
        } else {
            Add-AuditResult -Category 'Advanced Security Auditing & Event Logging' -Control 'Sysmon (System Monitor) Presence' -Status 'INFO' -Severity 'Informational' `
                -CurrentValue 'Not installed / not running' -RecommendedValue 'Present, if the organization relies on Sysmon telemetry to supplement MDE/EDR coverage' -CIS_Control 'CIS 8.5' `
                -NIST_Control 'AU-2, AU-12' -ISO27001_Control 'A.8.15' -NIS2_Article 'Art.21(2)(b)' `
                -Recommendation 'Not a defect by itself - many environments rely on Microsoft Defender for Endpoint''s built-in telemetry instead (audited separately). Consider deploying Sysmon with a maintained community configuration where deeper process/network/image-load telemetry is desired.'
        }
    } catch {
        Add-AuditResult -Category 'Advanced Security Auditing & Event Logging' -Control 'Sysmon Presence' -Status 'WARN' -Severity 'Low' -CurrentValue 'Query failed' `
            -Recommendation "Unable to query Sysmon service state: $($_.Exception.Message)"
    }
}

function Test-CameraMicrophonePrivacyPolicy {
    <#
        Audits the AppPrivacy CSP/GPO camera and microphone access policies. "Force Allow"
        removes the per-app consent prompt entirely, meaning any installed application -
        including malware - can access the camera/microphone silently.
    #>
    Write-SectionBanner 'Peripheral Security - Camera & Microphone Privacy Access Policy'
    try {
        $privacyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'
        $items = @(
            @{ Name = 'Camera'; Value = (Get-RegistryValueSafe -Path $privacyPath -Name 'LetAppsAccessCamera' -DefaultValue $null); Mitre = 'T1125 (Video Capture)' }
            @{ Name = 'Microphone'; Value = (Get-RegistryValueSafe -Path $privacyPath -Name 'LetAppsAccessMicrophone' -DefaultValue $null); Mitre = 'T1123 (Audio Capture)' }
        )
        foreach ($item in $items) {
            if ($null -eq $item.Value) {
                Add-AuditResult -Category 'Peripheral & Physical Attack Surface' -Control "$($item.Name) Access Policy" -Status 'INFO' -Severity 'Informational' `
                    -CurrentValue 'Not Configured (user/per-app Windows Settings apply)' -RecommendedValue 'Managed centrally where the device role warrants restricting access' -CIS_Control 'CIS 4.1' `
                    -NIST_Control 'AC-20' -ISO27001_Control 'A.8.20' -NIS2_Article 'Art.21(2)(d)' `
                    -Recommendation "Consider centrally managing $($item.Name.ToLower()) access via the AppPrivacy CSP/GPO if this device's role warrants it - absence of a policy is not itself a defect for a typical knowledge-worker endpoint."
            } elseif ([int]$item.Value -eq 1) {
                Add-AuditResult -Category 'Peripheral & Physical Attack Surface' -Control "$($item.Name) Access Policy" -Status 'WARN' -Severity 'Low' `
                    -CurrentValue 'Force Allow (all apps granted access, bypassing per-app consent)' -RecommendedValue 'User in control (default), or Force Deny for high-sensitivity roles' -CIS_Control 'CIS 4.1' `
                    -NIST_Control 'AC-20' -MITRE_Technique $item.Mitre -ISO27001_Control 'A.8.20' -NIS2_Article 'Art.21(2)(d)' `
                    -Recommendation "Force Allow removes the per-app consent prompt for $($item.Name.ToLower()) access. Set to User in control unless every app requires unprompted access for a specific, documented reason."
            } else {
                $desc = if ([int]$item.Value -eq 2) { 'Force Deny' } else { 'User in control' }
                Add-AuditResult -Category 'Peripheral & Physical Attack Surface' -Control "$($item.Name) Access Policy" -Status 'PASS' -Severity 'Low' `
                    -CurrentValue $desc -RecommendedValue 'User in control (default), or Force Deny for high-sensitivity roles' -CIS_Control 'CIS 4.1' -NIST_Control 'AC-20' -ISO27001_Control 'A.8.20' `
                    -NIS2_Article 'Art.21(2)(d)' -Recommendation 'No action required.'
            }
        }
    } catch {
        Add-AuditResult -Category 'Peripheral & Physical Attack Surface' -Control 'Camera & Microphone Privacy Access Policy' -Status 'WARN' -Severity 'Low' -CurrentValue 'Query failed' `
            -Recommendation "Unable to query camera/microphone privacy policy: $($_.Exception.Message)"
    }
}

#endregion

#region ============================== 34. SYSTEM INVENTORY & ASSET INFORMATION ==============================

function Test-LocalUserAndAdminInventory {
    <#
        Full roster of local accounts with enabled/admin/last-logon state, complementing
        (not replacing) the dedicated pass/fail account-hardening findings elsewhere.
    #>
    Write-SectionBanner 'System Inventory - Local Users & Administrators Roster'
    try {
        $users = @(Get-LocalUser -ErrorAction Stop)
        $adminMembers = @()
        try { $adminMembers = @(Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop | ForEach-Object { $_.Name }) } catch { $adminMembers = @() }

        $userSummary = $users | ForEach-Object {
            $isAdmin = ($adminMembers -contains "$env:COMPUTERNAME\$($_.Name)") -or ($adminMembers -contains $_.Name)
            $lastLogon = if ($_.LastLogon) { $_.LastLogon.ToString('yyyy-MM-dd') } else { 'Never' }
            "$($_.Name) [Enabled=$($_.Enabled); Admin=$isAdmin; LastLogon=$lastLogon]"
        }

        Add-AuditResult -Category 'System Inventory & Asset Information' -Control 'Local User & Administrator Roster' -Status 'INFO' -Severity 'Informational' `
            -CurrentValue "$($users.Count) local account(s): $($userSummary -join ' | ')" -RecommendedValue 'Reviewed periodically against expected roster' -CIS_Control 'CIS 5.1' -NIST_Control 'AC-2' `
            -ISO27001_Control 'A.5.16' -NIS2_Article 'Art.21(2)(i)' `
            -Recommendation 'Full inventory for asset/access review. Cross-reference against the Built-in Account Hardening, Local Administrators Group Membership, and Password Never Expires findings elsewhere in this report for the corresponding pass/fail judgments.'
    } catch {
        Add-AuditResult -Category 'System Inventory & Asset Information' -Control 'Local User & Administrator Roster' -Status 'WARN' -Severity 'Low' -CurrentValue 'Query failed' `
            -Recommendation "Unable to enumerate local users: $($_.Exception.Message)"
    }
}

function Test-CachedUserProfileInventory {
    <#
        Enumerates cached local user profiles (path, last-use time, loaded state). Disk-space
        size per profile is deliberately not computed here - a recursive size scan across
        every profile would materially slow the overall audit run.
    #>
    Write-SectionBanner 'System Inventory - Cached User Profiles'
    try {
        $profiles = @(Get-CimInstance -ClassName Win32_UserProfile -ErrorAction Stop | Where-Object { -not $_.Special })
        if ($profiles.Count -eq 0) {
            Add-AuditResult -Category 'System Inventory & Asset Information' -Control 'Cached User Profiles' -Status 'INFO' -Severity 'Informational' -CurrentValue 'No non-special user profiles found' `
                -Recommendation 'No action required.'
            return
        }
        $profileSummary = $profiles | ForEach-Object {
            $lastUseText = 'Unknown'
            try { if ($_.LastUseTime) { $lastUseText = ([Management.ManagementDateTimeConverter]::ToDateTime($_.LastUseTime)).ToString('yyyy-MM-dd') } } catch { }
            "$($_.LocalPath) [LastUse=$lastUseText; Loaded=$($_.Loaded); Roaming=$($_.RoamingConfigured)]"
        }
        Add-AuditResult -Category 'System Inventory & Asset Information' -Control 'Cached User Profiles' -Status 'INFO' -Severity 'Informational' `
            -CurrentValue "$($profiles.Count) profile(s): $($profileSummary -join ' | ')" -RecommendedValue 'Reviewed periodically; stale profiles removed per data-retention policy' -CIS_Control 'CIS 5.1' `
            -NIST_Control 'AC-2, MP-6' -ISO27001_Control 'A.8.10' -NIS2_Article 'Art.21(2)(i)' `
            -Recommendation 'Stale, long-unused cached profiles retain locally-stored data (cached credentials, browser history/tokens, saved files) indefinitely. Consider removing profiles with no recent last-use date via Remove-CimInstance, consistent with the organization''s data retention policy. Profile disk-space size is not computed here for performance reasons.'
    } catch {
        Add-AuditResult -Category 'System Inventory & Asset Information' -Control 'Cached User Profiles' -Status 'WARN' -Severity 'Low' -CurrentValue 'Query failed' `
            -Recommendation "Unable to enumerate cached user profiles: $($_.Exception.Message)"
    }
}

function Test-NetworkAdapterInventory {
    <# Enumerates network adapters and, if connected, the current Wi-Fi SSID/signal/authentication for context. #>
    Write-SectionBanner 'System Inventory - Network Adapters & Wi-Fi Connection'
    try {
        $adapters = @(Get-NetAdapter -ErrorAction Stop)
        $adapterSummary = $adapters | ForEach-Object { "$($_.Name) [$($_.InterfaceDescription)] MAC=$($_.MacAddress) Status=$($_.Status) LinkSpeed=$($_.LinkSpeed)" }
        Add-AuditResult -Category 'System Inventory & Asset Information' -Control 'Network Adapter Inventory' -Status 'INFO' -Severity 'Informational' `
            -CurrentValue "$($adapters.Count) adapter(s): $($adapterSummary -join ' | ')" -RecommendedValue 'Reviewed for unexpected/unauthorized adapters' -CIS_Control 'CIS 12.1' -NIST_Control 'CM-8' `
            -ISO27001_Control 'A.8.9' -NIS2_Article 'Art.21(2)(a)' -Recommendation 'No action required; asset inventory item. Review for unexpected virtual/bridge adapters that may indicate an unauthorized network configuration.'

        $wlanOutput = $null
        try { $wlanOutput = & netsh.exe wlan show interfaces 2>$null } catch { $wlanOutput = $null }
        if ($wlanOutput -and ($wlanOutput -match '(?i)SSID')) {
            $ssidLine = $wlanOutput | Where-Object { $_ -match '(?i)^\s*SSID\s*:' -and $_ -notmatch '(?i)BSSID' } | Select-Object -First 1
            $signalLine = $wlanOutput | Where-Object { $_ -match '(?i)^\s*Signal\s*:' } | Select-Object -First 1
            $authLine = $wlanOutput | Where-Object { $_ -match '(?i)^\s*Authentication\s*:' } | Select-Object -First 1
            $ssid = if ($ssidLine) { ($ssidLine -split ':', 2)[1].Trim() } else { 'Unknown' }
            $signal = if ($signalLine) { ($signalLine -split ':', 2)[1].Trim() } else { 'Unknown' }
            $auth = if ($authLine) { ($authLine -split ':', 2)[1].Trim() } else { 'Unknown' }
            Add-AuditResult -Category 'System Inventory & Asset Information' -Control 'Current Wi-Fi Connection' -Status 'INFO' -Severity 'Informational' `
                -CurrentValue "SSID=$ssid; Signal=$signal; Authentication=$auth" -RecommendedValue 'N/A (informational)' -Recommendation 'No action required; asset/context inventory item.'
        }
    } catch {
        Add-AuditResult -Category 'System Inventory & Asset Information' -Control 'Network Adapter Inventory' -Status 'WARN' -Severity 'Low' -CurrentValue 'Query failed' `
            -Recommendation "Unable to enumerate network adapters: $($_.Exception.Message)"
    }
}

function Get-InstalledApplicationsCache {
    <#
        Central Uninstall-registry accessor (32/64-bit, machine and user scope), shared
        between the Installed Application Inventory check and the HTML report's System
        Overview panel so the enumeration only runs once per audit run.
    #>
    if ($null -eq $Script:InstalledAppsCache) {
        try {
            $uninstallPaths = @(
                'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
                'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
                'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
            )
            $Script:InstalledAppsCache = @(Get-ItemProperty -Path $uninstallPaths -ErrorAction SilentlyContinue |
                Where-Object { $_.DisplayName -and -not $_.SystemComponent } |
                Select-Object DisplayName, DisplayVersion, Publisher, InstallDate -Unique | Sort-Object DisplayName)
        } catch { $Script:InstalledAppsCache = @() }
    }
    return $Script:InstalledAppsCache
}

function Test-InstalledApplicationInventory {
    <# Enumerates installed applications (32/64-bit, machine and user scope) from the standard Uninstall registry keys. #>
    Write-SectionBanner 'System Inventory - Installed Applications'
    try {
        $apps = @(Get-InstalledApplicationsCache)

        if ($apps.Count -eq 0) {
            Add-AuditResult -Category 'System Inventory & Asset Information' -Control 'Installed Application Inventory' -Status 'INFO' -Severity 'Informational' -CurrentValue 'No applications enumerated' `
                -Recommendation 'No action required.'
            return
        }

        $appSummary = (($apps | Select-Object -First 60 | ForEach-Object { "$($_.DisplayName) $($_.DisplayVersion) [$($_.Publisher)]" }) -join ' | ')
        $truncatedNote = if ($apps.Count -gt 60) { " (showing first 60 of $($apps.Count))" } else { '' }
        Add-AuditResult -Category 'System Inventory & Asset Information' -Control 'Installed Application Inventory' -Status 'INFO' -Severity 'Informational' `
            -CurrentValue "$($apps.Count) application(s)$($truncatedNote): $appSummary" -RecommendedValue 'Reviewed against approved software list; unrecognized entries investigated' -CIS_Control 'CIS 2.1' `
            -NIST_Control 'CM-8' -ISO27001_Control 'A.8.19' -NIS2_Article 'Art.21(2)(e)' `
            -Recommendation 'Full software inventory for asset/patch management review. This audit does not check individual application versions against known-vulnerable releases (no external CVE feed is available offline) - cross-reference against the organization''s vulnerability management tooling.'
    } catch {
        Add-AuditResult -Category 'System Inventory & Asset Information' -Control 'Installed Application Inventory' -Status 'WARN' -Severity 'Low' -CurrentValue 'Query failed' `
            -Recommendation "Unable to enumerate installed applications: $($_.Exception.Message)"
    }
}

function Test-ScreensaverLockPolicy {
    <#
        Audits the legacy screensaver-based session lock mechanism (ScreenSaveActive/
        ScreenSaverIsSecure/ScreenSaveTimeOut), distinct from the modern "Interactive logon:
        Machine inactivity limit" policy audited earlier in this report. Many environments
        still rely on this older mechanism instead of or alongside the modern one.
    #>
    Write-SectionBanner 'Identity & Session Security - Screensaver Lock Policy'
    try {
        $desktopPath = 'HKCU:\Control Panel\Desktop'
        $screenSaveActive = Get-RegistryValueSafe -Path $desktopPath -Name 'ScreenSaveActive' -DefaultValue '0'
        $screenSaverIsSecure = Get-RegistryValueSafe -Path $desktopPath -Name 'ScreenSaverIsSecure' -DefaultValue '0'
        $screenSaveTimeOut = Get-RegistryValueSafe -Path $desktopPath -Name 'ScreenSaveTimeOut' -DefaultValue '0'
        $timeoutInt = 0
        [void][int]::TryParse([string]$screenSaveTimeOut, [ref]$timeoutInt)

        if ([string]$screenSaveActive -eq '1' -and [string]$screenSaverIsSecure -eq '1' -and $timeoutInt -gt 0 -and $timeoutInt -le 900) {
            Add-AuditResult -Category 'Identity, Privilege Management & Access Control' -Control 'Screensaver Lock Policy (Legacy Session Lock Mechanism)' -Status 'PASS' -Severity 'Medium' `
                -CurrentValue "Active=$screenSaveActive; Secure=$screenSaverIsSecure; Timeout=${timeoutInt}s" -RecommendedValue 'Active=1; Secure=1; Timeout<=900s' -CIS_Control 'CIS 4.10' `
                -NIST_Control 'AC-11' -MITRE_Technique 'T1078 (Valid Accounts)' -ISO27001_Control 'A.8.1' -NIS2_Article 'Art.21(2)(i)' -Recommendation 'No action required.'
        } else {
            Add-AuditResult -Category 'Identity, Privilege Management & Access Control' -Control 'Screensaver Lock Policy (Legacy Session Lock Mechanism)' -Status 'WARN' -Severity 'Medium' `
                -CurrentValue "Active=$screenSaveActive; Secure=$screenSaverIsSecure; Timeout=${timeoutInt}s" -RecommendedValue 'Active=1; Secure=1; Timeout<=900s' -CIS_Control 'CIS 4.10' `
                -NIST_Control 'AC-11' -MITRE_Technique 'T1078 (Valid Accounts)' -ISO27001_Control 'A.8.1' -NIS2_Article 'Art.21(2)(i)' `
                -Recommendation 'This is the legacy screensaver-based lock mechanism (the modern "Interactive logon: Machine inactivity limit" policy, audited elsewhere, is the recommended primary control). If relied upon, configure via GPO "Password protect the screen saver" = Enabled with a timeout of 900 seconds or less. Note this check reflects the elevated administrator''s own HKCU profile context.'
        }
    } catch {
        Add-AuditResult -Category 'Identity, Privilege Management & Access Control' -Control 'Screensaver Lock Policy' -Status 'WARN' -Severity 'Low' -CurrentValue 'Query failed' `
            -Recommendation "Unable to query screensaver lock policy: $($_.Exception.Message)"
    }
}

function Test-DiskSpaceUtilization {
    <# Audits free space on every fixed volume; critically low free space also undermines VSS shadow-copy retention audited earlier. #>
    Write-SectionBanner 'System Inventory - Disk Space Utilization'
    try {
        $volumes = @(Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction Stop)
        foreach ($vol in $volumes) {
            if (-not $vol.Size -or $vol.Size -eq 0) { continue }
            $freePct = [math]::Round(($vol.FreeSpace / $vol.Size) * 100, 1)
            $sizeGb = [math]::Round($vol.Size / 1GB, 1)
            $freeGb = [math]::Round($vol.FreeSpace / 1GB, 1)

            if ($freePct -lt 10) {
                Add-AuditResult -Category 'System Inventory & Asset Information' -Control "Disk Space Utilization - $($vol.DeviceID)" -Status 'WARN' -Severity 'Medium' `
                    -CurrentValue "$freeGb GB free of $sizeGb GB ($freePct% free)" -RecommendedValue '>= 10-15% free space' -CIS_Control 'CIS 10.1' -NIST_Control 'CP-2' -ISO27001_Control 'A.8.6' `
                    -NIS2_Article 'Art.21(2)(c)' `
                    -Recommendation "Free up space on $($vol.DeviceID) - critically low free space can prevent Windows Update installation, shrink or disable VSS shadow storage (undermining the ransomware-recovery controls audited elsewhere), and cause application/log write failures."
            } else {
                Add-AuditResult -Category 'System Inventory & Asset Information' -Control "Disk Space Utilization - $($vol.DeviceID)" -Status 'PASS' -Severity 'Medium' `
                    -CurrentValue "$freeGb GB free of $sizeGb GB ($freePct% free)" -RecommendedValue '>= 10-15% free space' -CIS_Control 'CIS 10.1' -NIST_Control 'CP-2' -ISO27001_Control 'A.8.6' `
                    -NIS2_Article 'Art.21(2)(c)' -Recommendation 'No action required.'
            }
        }
    } catch {
        Add-AuditResult -Category 'System Inventory & Asset Information' -Control 'Disk Space Utilization' -Status 'WARN' -Severity 'Low' -CurrentValue 'Query failed' `
            -Recommendation "Unable to query disk space utilization: $($_.Exception.Message)"
    }
}

function Test-RDPSessionAndRedirectionSettings {
    <#
        Audits RDP device redirection (drives/clipboard) and idle-session timeout - both
        distinct from the connection-security settings (NLA, Security Layer, encryption
        level) already audited elsewhere.
    #>
    Write-SectionBanner 'Network Architecture - RDP Session Limits & Device Redirection'
    try {
        $fDenyTs = Get-RegistryValueSafe -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -DefaultValue 1
        if ([int]$fDenyTs -eq 1) {
            Add-AuditResult -Category 'Network Architecture & Protocol Hardening' -Control 'RDP Session Limits & Device Redirection' -Status 'INFO' -Severity 'Informational' -CurrentValue 'RDP is disabled' `
                -Recommendation 'Not applicable.'
            return
        }
        $rdpTcpPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
        $driveRedirect = Get-RegistryValueSafe -Path $rdpTcpPath -Name 'fDisableCdm' -DefaultValue 0
        $maxIdle = Get-RegistryValueSafe -Path $rdpTcpPath -Name 'MaxIdleTime' -DefaultValue 0

        if ([int]$driveRedirect -eq 1) {
            Add-AuditResult -Category 'Network Architecture & Protocol Hardening' -Control 'RDP Drive Redirection' -Status 'PASS' -Severity 'Medium' `
                -CurrentValue 'Disabled' -RecommendedValue 'Disabled unless explicitly required' -CIS_Control 'CIS 4.9' -NIST_Control 'AC-20, MP-7' -MITRE_Technique 'T1021.001 (Remote Desktop Protocol)' `
                -ISO27001_Control 'A.8.20' -NIS2_Article 'Art.21(2)(j)' -Recommendation 'No action required.'
        } else {
            Add-AuditResult -Category 'Network Architecture & Protocol Hardening' -Control 'RDP Drive Redirection' -Status 'WARN' -Severity 'Medium' `
                -CurrentValue 'Enabled (default)' -RecommendedValue 'Disabled unless explicitly required' -CIS_Control 'CIS 4.9' -NIST_Control 'AC-20, MP-7' `
                -MITRE_Technique 'T1021.001 (Remote Desktop Protocol), T1052.001 (Exfiltration over USB)' -ISO27001_Control 'A.8.20' -NIS2_Article 'Art.21(2)(j)' `
                -Recommendation 'Set the "Do not allow drive redirection" GPO to Enabled (writes fDisableCdm=1). Drive redirection lets an RDP client mount local drives inside the remote session (or vice versa on a jump host) - a two-way data exfiltration and malware-propagation path.'
        }

        if ([int]$maxIdle -gt 0 -and [int]$maxIdle -le 900000) {
            Add-AuditResult -Category 'Network Architecture & Protocol Hardening' -Control 'RDP Idle Session Timeout' -Status 'PASS' -Severity 'Low' `
                -CurrentValue "MaxIdleTime=$($maxIdle)ms" -RecommendedValue '<= 900000ms (15 minutes)' -CIS_Control 'CIS 4.9' -NIST_Control 'AC-11, AC-12' -ISO27001_Control 'A.8.1' -NIS2_Article 'Art.21(2)(j)' `
                -Recommendation 'No action required.'
        } else {
            Add-AuditResult -Category 'Network Architecture & Protocol Hardening' -Control 'RDP Idle Session Timeout' -Status 'WARN' -Severity 'Low' `
                -CurrentValue "MaxIdleTime=$maxIdle ms (0 = no limit)" -RecommendedValue '<= 900000ms (15 minutes)' -CIS_Control 'CIS 4.9' -NIST_Control 'AC-11, AC-12' -ISO27001_Control 'A.8.1' `
                -NIS2_Article 'Art.21(2)(j)' -Recommendation 'Set "Set time limit for active but idle Remote Desktop Services sessions" to 15 minutes or less (MaxIdleTime, in milliseconds).'
        }
    } catch {
        Add-AuditResult -Category 'Network Architecture & Protocol Hardening' -Control 'RDP Session Limits & Device Redirection' -Status 'WARN' -Severity 'Low' -CurrentValue 'Query failed' `
            -Recommendation "Unable to query RDP session/redirection settings: $($_.Exception.Message)"
    }
}

function Test-InstalledDriverInventory {
    <# Enumerates installed (not just currently-running) drivers and flags any older than 5 years for update review. #>
    Write-SectionBanner 'System Inventory - Installed Driver Inventory'
    try {
        $drivers = @(Get-CimInstance -ClassName Win32_PnPSignedDriver -ErrorAction Stop | Where-Object { $_.DeviceName })
        if ($drivers.Count -eq 0) {
            Add-AuditResult -Category 'System Inventory & Asset Information' -Control 'Installed Driver Inventory' -Status 'INFO' -Severity 'Informational' -CurrentValue 'No drivers enumerated' `
                -Recommendation 'No action required.'
            return
        }

        Add-AuditResult -Category 'System Inventory & Asset Information' -Control 'Installed Driver Inventory' -Status 'INFO' -Severity 'Informational' `
            -CurrentValue "$($drivers.Count) driver(s) enumerated" -RecommendedValue 'Reviewed against asset/patch management records' -CIS_Control 'CIS 2.1' -NIST_Control 'CM-8' -ISO27001_Control 'A.8.19' `
            -NIS2_Article 'Art.21(2)(e)' `
            -Recommendation 'Full driver inventory for asset/patch management review. Cross-reference against the Loaded Kernel Driver Signature Validity and Vulnerable Driver Blocklist findings elsewhere for the corresponding security judgments on currently-running drivers.'

        $staleDrivers = @($drivers | Where-Object { $_.DriverDate } | Where-Object {
            try { ([Management.ManagementDateTimeConverter]::ToDateTime($_.DriverDate)) -lt (Get-Date).AddYears(-5) } catch { $false }
        })
        if ($staleDrivers.Count -gt 0) {
            $staleSummary = (($staleDrivers | Select-Object -First 15 | ForEach-Object {
                $dateText = try { ([Management.ManagementDateTimeConverter]::ToDateTime($_.DriverDate)).ToString('yyyy-MM-dd') } catch { 'Unknown' }
                "$($_.DeviceName) [$($_.DriverVersion), $dateText]"
            }) -join ' | ')
            Add-AuditResult -Category 'System Inventory & Asset Information' -Control 'Drivers Older Than 5 Years' -Status 'WARN' -Severity 'Low' `
                -CurrentValue "$($staleDrivers.Count) driver(s) with a date older than 5 years: $staleSummary" -RecommendedValue 'Drivers kept reasonably current via Windows Update/OEM tooling' -CIS_Control 'CIS 7.1' `
                -NIST_Control 'SI-2' -ISO27001_Control 'A.8.8' -NIS2_Article 'Art.21(2)(e)' `
                -Recommendation 'Review the listed drivers for available updates via Windows Update (Optional updates) or the OEM support site. Very old drivers are more likely to contain unpatched vulnerabilities, particularly kernel-mode drivers (a documented BYOVD/LPE source).'
        }
    } catch {
        Add-AuditResult -Category 'System Inventory & Asset Information' -Control 'Installed Driver Inventory' -Status 'WARN' -Severity 'Low' -CurrentValue 'Query failed' `
            -Recommendation "Unable to enumerate installed drivers: $($_.Exception.Message)"
    }
}

function Test-SystemHardwareInventory {
    <# Reports manufacturer/model/CPU/RAM/OS version/architecture as context alongside every other finding. #>
    Write-SectionBanner 'System Inventory - Hardware & OS Version Summary'
    try {
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        $cpu = Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop | Select-Object -First 1
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $ramGb = [math]::Round($cs.TotalPhysicalMemory / 1GB, 1)

        Add-AuditResult -Category 'System Inventory & Asset Information' -Control 'System Hardware & OS Version Summary' -Status 'INFO' -Severity 'Informational' `
            -CurrentValue "Manufacturer=$($cs.Manufacturer); Model=$($cs.Model); CPU=$($cpu.Name); RAM=${ramGb}GB; OS=$($os.Caption) (Build $($os.BuildNumber)); Architecture=$($os.OSArchitecture)" `
            -RecommendedValue 'N/A (informational)' -CIS_Control 'CIS 1.1' -NIST_Control 'CM-8' -ISO27001_Control 'A.8.9' -NIS2_Article 'Art.21(2)(a)' `
            -Recommendation 'No action required; asset inventory item for context alongside every other finding in this report.'
    } catch {
        Add-AuditResult -Category 'System Inventory & Asset Information' -Control 'System Hardware & OS Version Summary' -Status 'WARN' -Severity 'Low' -CurrentValue 'Query failed' `
            -Recommendation "Unable to query system hardware/OS summary: $($_.Exception.Message)"
    }
}

function Test-WindowsUpdateSettingsDeep {
    <#
        Audits Windows Update deferral periods and management source, complementing the
        existing Windows Update Compliance checks (service health, pending reboot, patch
        recency) with the deferral/policy dimension not yet covered.
    #>
    Write-SectionBanner 'Advanced Security Auditing - Windows Update Settings (Deferral & Management Source)'
    try {
        $wuPolicyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
        $auPolicyPath = Join-Path $wuPolicyPath 'AU'
        $deferFeature = Get-RegistryValueSafe -Path $wuPolicyPath -Name 'DeferFeatureUpdatesPeriodInDays' -DefaultValue $null
        $deferQuality = Get-RegistryValueSafe -Path $wuPolicyPath -Name 'DeferQualityUpdatesPeriodInDays' -DefaultValue $null
        $wuServer = Get-RegistryValueSafe -Path $wuPolicyPath -Name 'WUServer' -DefaultValue $null
        $auOptions = Get-RegistryValueSafe -Path $auPolicyPath -Name 'AUOptions' -DefaultValue $null

        $managementSource = if ($wuServer) { "WSUS ($wuServer)" } elseif (Get-Service -Name 'IntuneManagementExtension' -ErrorAction SilentlyContinue) { 'Intune-managed' } else { 'Windows Update (direct)' }
        $deferFeatureText = if ($deferFeature) { "$deferFeature day(s)" } else { 'Not Configured' }
        $deferQualityText = if ($deferQuality) { "$deferQuality day(s)" } else { 'Not Configured' }

        Add-AuditResult -Category 'Advanced Security Auditing & Event Logging' -Control 'Windows Update Deferral & Management Configuration' -Status 'INFO' -Severity 'Informational' `
            -CurrentValue "ManagementSource=$managementSource; DeferFeatureUpdates=$deferFeatureText; DeferQualityUpdates=$deferQualityText; AUOptions=$auOptions" `
            -RecommendedValue 'Quality update deferral <= 7 days; feature update deferral aligned to org patch cadence' -CIS_Control 'CIS 7.3' -NIST_Control 'SI-2, CM-3' -ISO27001_Control 'A.8.8' `
            -NIS2_Article 'Art.21(2)(e)' `
            -Recommendation 'See the separate Patch Recency finding for whether updates are actually installing on schedule. Quality (security) update deferral longer than about 7 days materially delays critical security fix deployment - keep it short even if feature update deferral is longer for stability testing.'

        if ($deferQuality -and [int]$deferQuality -gt 7) {
            Add-AuditResult -Category 'Advanced Security Auditing & Event Logging' -Control 'Quality (Security) Update Deferral Period' -Status 'WARN' -Severity 'Medium' `
                -CurrentValue "$deferQuality day(s)" -RecommendedValue '<= 7 days' -CIS_Control 'CIS 7.3' -NIST_Control 'SI-2' -MITRE_Technique 'T1190 (Exploit Public-Facing Application)' `
                -ISO27001_Control 'A.8.8' -NIS2_Article 'Art.21(2)(e)' -Recommendation 'Reduce DeferQualityUpdatesPeriodInDays to 7 or fewer.'
        }
    } catch {
        Add-AuditResult -Category 'Advanced Security Auditing & Event Logging' -Control 'Windows Update Settings' -Status 'WARN' -Severity 'Low' -CurrentValue 'Query failed' `
            -Recommendation "Unable to query Windows Update deferral/management settings: $($_.Exception.Message)"
    }
}

#endregion

#region ============================== SCORING & RISK ENGINE ==============================

function Get-CompliancePosture {
    <#
        Computes a weighted 0-100 compliance score and an overall risk badge from the
        accumulated findings. Critical/High severity failures are penalized more heavily
        than Medium/Low. WARN findings receive half credit. INFO findings are excluded from
        scoring entirely (they carry no pass/fail judgement).
    #>
    $severityWeights = @{ 'Critical' = 10; 'High' = 7; 'Medium' = 4; 'Low' = 2; 'Informational' = 0 }

    $maxPoints = 0.0
    $earnedPoints = 0.0

    foreach ($r in $Script:AuditResults) {
        if ($r.Status -eq 'INFO') { continue }
        $weight = $severityWeights[$r.Severity]
        if (-not $weight) { $weight = 0 }
        if ($weight -eq 0) { continue }

        $maxPoints += $weight
        switch ($r.Status) {
            'PASS' { $earnedPoints += $weight }
            'WARN' { $earnedPoints += ($weight * 0.5) }
            'FAIL' { $earnedPoints += 0 }
        }
    }

    $score = 100.0
    if ($maxPoints -gt 0) { $score = [math]::Round(($earnedPoints / $maxPoints) * 100, 1) }

    $total = $Script:AuditResults.Count
    $passCount = @($Script:AuditResults | Where-Object { $_.Status -eq 'PASS' }).Count
    $failCount = @($Script:AuditResults | Where-Object { $_.Status -eq 'FAIL' }).Count
    $warnCount = @($Script:AuditResults | Where-Object { $_.Status -eq 'WARN' }).Count
    $infoCount = @($Script:AuditResults | Where-Object { $_.Status -eq 'INFO' }).Count

    $criticalFails = @($Script:AuditResults | Where-Object { $_.Status -eq 'FAIL' -and $_.Severity -eq 'Critical' }).Count
    $highFails = @($Script:AuditResults | Where-Object { $_.Status -eq 'FAIL' -and $_.Severity -eq 'High' }).Count

    if ($criticalFails -ge 1) {
        $risk = 'CRITICAL'
    } elseif ($highFails -ge 3 -or $score -lt 60) {
        $risk = 'HIGH'
    } elseif ($score -lt 80) {
        $risk = 'MEDIUM'
    } else {
        $risk = 'LOW'
    }

    return [PSCustomObject]@{
        Score          = $score
        RiskLevel      = $risk
        Total          = $total
        PassCount      = $passCount
        FailCount      = $failCount
        WarnCount      = $warnCount
        InfoCount      = $infoCount
        CriticalFails  = $criticalFails
        HighFails      = $highFails
    }
}

#endregion

#region ============================== HTML DASHBOARD GENERATION ==============================

function Get-HtmlEncoded {
    param([Parameter(Mandatory = $false)][string]$Text)
    if ($null -eq $Text) { return '' }
    return [System.Net.WebUtility]::HtmlEncode($Text)
}

function Get-ExpandableCellHtml {
    <#
        Renders a finding's text field (Measured/Expected/Remediation) for the HTML report.
        Short values are shown in full inline, with the ' | ' list-item separator used
        throughout this script's -CurrentValue/-RecommendedValue/-Recommendation strings
        (e.g. installed-application or firewall-rule inventories) converted to real line
        breaks. Values that are long delimited lists (more than 3 items) or a long single
        block of prose (over 320 characters) instead render a short preview plus a
        "View details" button that opens the shared results modal (see Get-HtmlTemplate)
        with the complete, formatted content - keeping a narrow table column readable
        without truncating the underlying data.
    #>
    param(
        [Parameter(Mandatory = $true)]  [AllowEmptyString()] [string]$RawText,
        [Parameter(Mandatory = $true)]  [string]$Title,
        [Parameter(Mandatory = $true)]  [System.Collections.Specialized.OrderedDictionary]$ModalRegistry
    )

    if ([string]::IsNullOrWhiteSpace($RawText)) { return (Get-HtmlEncoded $RawText) }

    $items = @($RawText -split ' \| ' | Where-Object { $_ -ne '' })
    if ($items.Count -eq 0) { $items = @($RawText) }

    $isExpandable = ($items.Count -gt 3) -or ($RawText.Length -gt 320)
    if (-not $isExpandable) {
        return (($items | ForEach-Object { Get-HtmlEncoded $_ }) -join '<br>')
    }

    $modalId = [string]($ModalRegistry.Count + 1)

    if ($items.Count -gt 1) {
        $bodyHtml = '<ul class="modal-list">' + (($items | ForEach-Object { "<li>$(Get-HtmlEncoded $_)</li>" }) -join '') + '</ul>'
        $previewHtml = (($items | Select-Object -First 2 | ForEach-Object { Get-HtmlEncoded $_ }) -join '<br>')
        $btnLabel = "View all $($items.Count) items"
    } else {
        $bodyHtml = "<p>$(Get-HtmlEncoded $RawText)</p>"
        $preview = $RawText.Substring(0, [Math]::Min(200, $RawText.Length))
        if ($RawText.Length -gt 200) {
            $lastSpace = $preview.LastIndexOf(' ')
            if ($lastSpace -gt 100) { $preview = $preview.Substring(0, $lastSpace) }
            $preview += '...'
        }
        $previewHtml = Get-HtmlEncoded $preview
        $btnLabel = 'View full text'
    }

    $ModalRegistry[$modalId] = [ordered]@{ title = $Title; body = $bodyHtml }

    return "<div class=`"expand-preview`">$previewHtml</div><button type=`"button`" class=`"expand-btn`" data-modal-id=`"$modalId`">$btnLabel &rarr;</button>"
}

function Get-FrameworkChipsHtml {
    <#
        Renders a finding's compliance-framework mappings (CIS/NIST/MITRE/ISO27001/NIS2/NSA)
        as a compact wrapping chip grid instead of one fixed-label row per framework, so the
        Framework Mapping column stays narrow and legible instead of forcing the table to
        overflow. Frameworks with no mapping ('N/A') are omitted rather than shown empty.
    #>
    param([Parameter(Mandatory = $true)][PSObject]$Result)
    $map = [ordered]@{
        'CIS'       = $Result.CIS_Control
        'NIST'      = $Result.NIST_Control
        'MITRE'     = $Result.MITRE_Technique
        'ISO27001'  = $Result.ISO27001_Control
        'NIS2'      = $Result.NIS2_Article
        'NSA'       = $Result.NSA_Guidance
    }
    $chips = [System.Text.StringBuilder]::new()
    foreach ($entry in $map.GetEnumerator()) {
        $val = $entry.Value
        if ([string]::IsNullOrWhiteSpace($val) -or $val -eq 'N/A') { continue }
        [void]$chips.Append("<span class=`"fw-chip`" title=`"$(Get-HtmlEncoded $entry.Key)`"><b>$(Get-HtmlEncoded $entry.Key)</b>$(Get-HtmlEncoded $val)</span>")
    }
    if ($chips.Length -eq 0) { return '<span class="fw-chip fw-chip-empty">N/A</span>' }
    return $chips.ToString()
}

function Get-SystemInformationSummary {
    <#
        Collects a compact system-overview snapshot (identity, uptime, domain/join state,
        network, storage, hardware, application count) for display in the System Overview
        panel at the top of the HTML dashboard. This is informational context, not an audit
        finding, so it does not call Add-AuditResult - each field independently defaults to
        'Unknown' on failure rather than aborting the whole summary.
    #>
    $summary = [PSCustomObject]@{
        ComputerName      = $Script:ComputerName
        Domain            = 'Unknown'
        OSVersion         = 'Unknown'
        Manufacturer      = 'Unknown'
        Model             = 'Unknown'
        CPU               = 'Unknown'
        RAM               = 'Unknown'
        Uptime            = 'Unknown'
        LastBootTime      = 'Unknown'
        CurrentUser       = 'Unknown'
        IPAddresses       = 'Unknown'
        DiskSummary       = 'Unknown'
        InstalledAppCount = 'Unknown'
        BitLockerSummary  = 'Unknown'
    }

    try {
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        $summary.Manufacturer = $cs.Manufacturer
        $summary.Model = $cs.Model
        $ramGb = [math]::Round($cs.TotalPhysicalMemory / 1GB, 1)
        $summary.RAM = "$ramGb GB"

        if ($cs.PartOfDomain) {
            $summary.Domain = $cs.Domain
        } else {
            $summary.Domain = "WORKGROUP: $($cs.Workgroup)"
        }
        try {
            $dsreg = Get-DsregStatusCache
            if ($dsreg) {
                $aadJoined = Get-DsregValue $dsreg 'AzureAdJoined'
                if ($aadJoined -eq 'YES') { $summary.Domain += ' (Entra ID Joined)' }
            }
        } catch { }
    } catch { }

    try {
        $cpu = Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop | Select-Object -First 1
        $summary.CPU = "$($cpu.Name.Trim()) ($($cpu.NumberOfCores)C/$($cpu.NumberOfLogicalProcessors)T)"
    } catch { }

    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $summary.OSVersion = "$($os.Caption) (Build $($os.BuildNumber), $($os.OSArchitecture))"
        $lastBoot = $os.LastBootUpTime
        $summary.LastBootTime = $lastBoot.ToString('yyyy-MM-dd HH:mm:ss')
        $uptimeSpan = (Get-Date) - $lastBoot
        $summary.Uptime = "{0}d {1}h {2}m" -f $uptimeSpan.Days, $uptimeSpan.Hours, $uptimeSpan.Minutes
    } catch { }

    try {
        $summary.CurrentUser = "$env:USERDOMAIN\$env:USERNAME (elevated session)"
    } catch { }

    try {
        $ips = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop |
            Where-Object { $_.IPAddress -notmatch '^(127\.|169\.254\.)' } | Select-Object -ExpandProperty IPAddress -Unique)
        $summary.IPAddresses = if ($ips.Count -gt 0) { $ips -join ', ' } else { 'No active IPv4 address found' }
    } catch { }

    try {
        $volumes = @(Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction Stop)
        $diskParts = @($volumes | Where-Object { $_.Size -gt 0 } | ForEach-Object {
            $sizeGb = [math]::Round($_.Size / 1GB, 1)
            $freeGb = [math]::Round($_.FreeSpace / 1GB, 1)
            $pctFree = [math]::Round(($_.FreeSpace / $_.Size) * 100, 0)
            "$($_.DeviceID) $freeGb GB free / $sizeGb GB ($pctFree% free)"
        })
        if ($diskParts.Count -gt 0) { $summary.DiskSummary = $diskParts -join '; ' }
    } catch { }

    try {
        $apps = Get-InstalledApplicationsCache
        $summary.InstalledAppCount = "$($apps.Count)"
    } catch { }

    try {
        $blVolumes = @(Get-BitLockerVolume -ErrorAction Stop)
        if ($blVolumes.Count -gt 0) {
            $encryptedCount = @($blVolumes | Where-Object { $_.VolumeStatus -eq 'FullyEncrypted' }).Count
            $summary.BitLockerSummary = "$encryptedCount of $($blVolumes.Count) volume(s) fully encrypted"
        } else {
            $summary.BitLockerSummary = 'No volumes found'
        }
    } catch { }

    return $summary
}

function New-HtmlReport {
    <#
        Renders the complete, self-contained HTML executive dashboard from $Script:AuditResults
        using a static template with {{TOKEN}} placeholders replaced by literal .Replace() calls
        (no PowerShell string interpolation inside the template, to keep embedded JS/CSS safe).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [string]$OutputPath,
        [Parameter(Mandatory = $true)] [PSObject]$Posture
    )

    $sysInfo = Get-SystemInformationSummary

    $osInfo = 'Unknown'
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $osInfo = "$($os.Caption) (Build $($os.BuildNumber))"
    } catch { $osInfo = $env:OS }

    $duration = New-TimeSpan -Start $Script:StartTime -End (Get-Date)
    $durationText = "{0:mm}m {0:ss}s" -f $duration

    # ---- Build category filter <option> list ----
    $categories = @($Script:AuditResults | Select-Object -ExpandProperty Category -Unique | Sort-Object)
    $categoryOptionsSb = [System.Text.StringBuilder]::new()
    foreach ($cat in $categories) {
        [void]$categoryOptionsSb.Append("<option value=`"" + (Get-HtmlEncoded $cat) + "`">" + (Get-HtmlEncoded $cat) + "</option>`n")
    }

    # ---- Build table rows ----
    # $modalRegistry accumulates {id -> {title, body}} for every field too long to show
    # inline; its contents are serialized to JSON below and read by the report's modal JS.
    $modalRegistry = [ordered]@{}
    $rowsSb = [System.Text.StringBuilder]::new()
    foreach ($r in $Script:AuditResults) {
        $statusClass = "status-$($r.Status.ToLower())"
        $severityClass = "sev-$($r.Severity.ToLower())"
        $mvStatusClass = "mv-status-$($r.Status.ToLower())"
        $measuredHtml = Get-ExpandableCellHtml -RawText $r.CurrentValue -Title "$($r.Control) - Measured Value" -ModalRegistry $modalRegistry
        $expectedHtml = Get-ExpandableCellHtml -RawText $r.RecommendedValue -Title "$($r.Control) - Expected Value" -ModalRegistry $modalRegistry
        $remediationHtml = Get-ExpandableCellHtml -RawText $r.Recommendation -Title "$($r.Control) - Remediation Guidance" -ModalRegistry $modalRegistry
        $rowHtml = @"
<tr class="finding-row" data-status="$($r.Status)" data-severity="$($r.Severity)" data-category="$(Get-HtmlEncoded $r.Category)" data-search="$(Get-HtmlEncoded ("$($r.Control) $($r.Category) $($r.Recommendation)".ToLower()))">
  <td class="col-control"><strong>$(Get-HtmlEncoded $r.Control)</strong><div class="cell-sub">$(Get-HtmlEncoded $r.Category)</div></td>
  <td><span class="badge $statusClass">$(Get-HtmlEncoded $r.Status)</span></td>
  <td><span class="badge $severityClass">$(Get-HtmlEncoded $r.Severity)</span></td>
  <td class="col-value">
    <div class="mv-block">
      <div class="mv-label">Measured</div>
      <div class="mv-content $mvStatusClass">$measuredHtml</div>
    </div>
    <div class="mv-divider"></div>
    <div class="mv-block">
      <div class="mv-label">Expected</div>
      <div class="mv-content mv-expected">$expectedHtml</div>
    </div>
  </td>
  <td class="col-frameworks"><div class="fw-chips">$(Get-FrameworkChipsHtml $r)</div></td>
  <td class="col-remediation">$remediationHtml</td>
</tr>
"@
        [void]$rowsSb.Append($rowHtml)
    }

    $modalDataJson = if ($modalRegistry.Count -eq 0) { '{}' } else { ($modalRegistry | ConvertTo-Json -Depth 6 -Compress) }
    $modalDataJson = $modalDataJson.Replace('</', '<\/')

    $scoreDeg = [math]::Round(($Posture.Score / 100) * 360, 0)
    $riskClass = "risk-$($Posture.RiskLevel.ToLower())"

    $html = Get-HtmlTemplate
    $html = $html.Replace('{{COMPUTERNAME}}', (Get-HtmlEncoded $Script:ComputerName))
    $html = $html.Replace('{{OSINFO}}', (Get-HtmlEncoded $osInfo))
    $html = $html.Replace('{{TIMESTAMP}}', (Get-HtmlEncoded (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')))
    $html = $html.Replace('{{DURATION}}', (Get-HtmlEncoded $durationText))
    $html = $html.Replace('{{VERSION}}', (Get-HtmlEncoded $Script:ScriptVersion))
    $html = $html.Replace('{{SCORE}}', [string]$Posture.Score)
    $html = $html.Replace('{{SCORE_DEG}}', [string]$scoreDeg)
    $html = $html.Replace('{{RISK_LEVEL}}', (Get-HtmlEncoded $Posture.RiskLevel))
    $html = $html.Replace('{{RISK_CLASS}}', $riskClass)
    $html = $html.Replace('{{TOTAL}}', [string]$Posture.Total)
    $html = $html.Replace('{{PASS_COUNT}}', [string]$Posture.PassCount)
    $html = $html.Replace('{{FAIL_COUNT}}', [string]$Posture.FailCount)
    $html = $html.Replace('{{WARN_COUNT}}', [string]$Posture.WarnCount)
    $html = $html.Replace('{{INFO_COUNT}}', [string]$Posture.InfoCount)
    $html = $html.Replace('{{CRITICAL_FAILS}}', [string]$Posture.CriticalFails)
    $html = $html.Replace('{{HIGH_FAILS}}', [string]$Posture.HighFails)
    $html = $html.Replace('{{CATEGORY_OPTIONS}}', $categoryOptionsSb.ToString())
    $html = $html.Replace('{{TABLE_ROWS}}', $rowsSb.ToString())
    $html = $html.Replace('{{MODAL_DATA_JSON}}', $modalDataJson)

    $html = $html.Replace('{{SYS_DOMAIN}}', (Get-HtmlEncoded $sysInfo.Domain))
    $html = $html.Replace('{{SYS_OSVERSION}}', (Get-HtmlEncoded $sysInfo.OSVersion))
    $html = $html.Replace('{{SYS_MANUFACTURER}}', (Get-HtmlEncoded $sysInfo.Manufacturer))
    $html = $html.Replace('{{SYS_MODEL}}', (Get-HtmlEncoded $sysInfo.Model))
    $html = $html.Replace('{{SYS_CPU}}', (Get-HtmlEncoded $sysInfo.CPU))
    $html = $html.Replace('{{SYS_RAM}}', (Get-HtmlEncoded $sysInfo.RAM))
    $html = $html.Replace('{{SYS_UPTIME}}', (Get-HtmlEncoded $sysInfo.Uptime))
    $html = $html.Replace('{{SYS_LASTBOOT}}', (Get-HtmlEncoded $sysInfo.LastBootTime))
    $html = $html.Replace('{{SYS_CURRENTUSER}}', (Get-HtmlEncoded $sysInfo.CurrentUser))
    $html = $html.Replace('{{SYS_IP}}', (Get-HtmlEncoded $sysInfo.IPAddresses))
    $html = $html.Replace('{{SYS_DISK}}', (Get-HtmlEncoded $sysInfo.DiskSummary))
    $html = $html.Replace('{{SYS_APPCOUNT}}', (Get-HtmlEncoded $sysInfo.InstalledAppCount))
    $html = $html.Replace('{{SYS_BITLOCKER}}', (Get-HtmlEncoded $sysInfo.BitLockerSummary))

    Set-Content -LiteralPath $OutputPath -Value $html -Encoding UTF8 -Force
}

function Get-HtmlTemplate {
    <#
        Static HTML/CSS/JS shell for the EndpointPostureCheck dashboard. Uses {{TOKEN}}
        placeholders only - no PowerShell variable interpolation - so this MUST remain a
        single-quoted here-string.
    #>
    return @'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>EndpointPostureCheck - {{COMPUTERNAME}}</title>
<style>
  :root {
    --bg: #0b1220;
    --panel: #121b2e;
    --panel-alt: #17233a;
    --border: #24324d;
    --text: #e6ecf5;
    --text-muted: #93a2bd;
    --accent: #3b9dff;
    --accent-soft: rgba(59,157,255,0.15);
    --green: #33c481;
    --red: #ff5c72;
    --amber: #ffb84d;
    --blue: #4fb0ff;
    --crit: #ff3b5c;
    --high: #ff7a45;
    --med: #ffc043;
    --low: #5b9dff;
    --info-sev: #8a97ad;
    --radius: 10px;
    --shadow: 0 6px 20px rgba(0,0,0,0.35);
  }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    background: linear-gradient(180deg, #0b1220 0%, #0d1526 100%);
    color: var(--text);
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    font-size: 14px;
    line-height: 1.5;
  }
  a { color: var(--accent); }
  .wrap { max-width: 1400px; margin: 0 auto; padding: 24px 20px 60px; }

  header.brand {
    display: flex; align-items: center; justify-content: space-between;
    padding: 18px 24px; background: var(--panel);
    border: 1px solid var(--border); border-radius: var(--radius);
    box-shadow: var(--shadow); margin-bottom: 20px; flex-wrap: wrap; gap: 12px;
  }
  .brand-title { display: flex; align-items: center; gap: 12px; }
  .brand-title .logo {
    width: 40px; height: 40px; border-radius: 8px;
    background: linear-gradient(135deg, var(--accent), #7b5cff);
    display: flex; align-items: center; justify-content: center;
    font-weight: 800; font-size: 18px; color: #fff; flex-shrink: 0;
  }
  .brand-title h1 { margin: 0; font-size: 19px; letter-spacing: 0.3px; }
  .brand-title .sub { color: var(--text-muted); font-size: 12.5px; margin-top: 2px; }
  .brand-meta { text-align: right; font-size: 12.5px; color: var(--text-muted); }
  .brand-meta div { margin: 2px 0; }
  .brand-meta strong { color: var(--text); }

  .sysinfo-panel { margin-bottom: 20px; }
  .sysinfo-panel .panel-title {
    margin: 0 0 12px 0; font-size: 13px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.6px; color: var(--text-muted);
  }
  .sysinfo-grid {
    display: grid; grid-template-columns: repeat(4, 1fr); gap: 14px 20px;
  }
  @media (max-width: 900px) { .sysinfo-grid { grid-template-columns: repeat(2, 1fr); } }
  @media (max-width: 520px) { .sysinfo-grid { grid-template-columns: 1fr; } }
  .sysinfo-tile { min-width: 0; }
  .sysinfo-label {
    color: var(--text-muted); font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 3px;
  }
  .sysinfo-value {
    color: var(--text); font-size: 13.5px; font-weight: 600; word-break: break-word;
  }

  .summary-grid {
    display: grid;
    grid-template-columns: 220px repeat(5, 1fr);
    gap: 16px; margin-bottom: 22px;
  }
  @media (max-width: 1100px) { .summary-grid { grid-template-columns: 1fr 1fr 1fr; } }
  @media (max-width: 640px) { .summary-grid { grid-template-columns: 1fr 1fr; } }

  .card {
    background: var(--panel); border: 1px solid var(--border); border-radius: var(--radius);
    padding: 16px; box-shadow: var(--shadow);
  }
  .score-card { display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 10px; }
  .score-ring {
    width: 140px; height: 140px; border-radius: 50%;
    background: conic-gradient(var(--accent) {{SCORE_DEG}}deg, #24324d 0deg);
    display: flex; align-items: center; justify-content: center; position: relative;
  }
  .score-ring::before {
    content: ""; position: absolute; width: 108px; height: 108px; border-radius: 50%; background: var(--panel);
  }
  .score-ring .score-value { position: relative; z-index: 1; font-size: 28px; font-weight: 800; }
  .score-ring .score-value small { display: block; font-size: 11px; color: var(--text-muted); font-weight: 500; }
  .risk-badge-wrap { text-align: center; }
  .risk-pill {
    display: inline-block; padding: 4px 14px; border-radius: 999px; font-weight: 700; font-size: 12px; letter-spacing: 0.6px;
  }
  .risk-low { background: rgba(51,196,129,0.18); color: var(--green); border: 1px solid var(--green); }
  .risk-medium { background: rgba(255,192,67,0.18); color: var(--amber); border: 1px solid var(--amber); }
  .risk-high { background: rgba(255,122,69,0.18); color: var(--high); border: 1px solid var(--high); }
  .risk-critical { background: rgba(255,59,92,0.18); color: var(--crit); border: 1px solid var(--crit); }

  .stat-card { display: flex; flex-direction: column; justify-content: center; gap: 4px; }
  .stat-card .stat-num { font-size: 30px; font-weight: 800; }
  .stat-card .stat-label { color: var(--text-muted); font-size: 12.5px; text-transform: uppercase; letter-spacing: 0.6px; }
  .stat-total .stat-num { color: var(--text); }
  .stat-pass .stat-num { color: var(--green); }
  .stat-fail .stat-num { color: var(--red); }
  .stat-warn .stat-num { color: var(--amber); }
  .stat-info .stat-num { color: var(--blue); }

  .controls {
    display: flex; flex-wrap: wrap; gap: 10px; align-items: center;
    background: var(--panel); border: 1px solid var(--border); border-radius: var(--radius);
    padding: 14px 16px; margin-bottom: 16px; box-shadow: var(--shadow);
  }
  .controls .filter-btn {
    background: var(--panel-alt); border: 1px solid var(--border); color: var(--text);
    padding: 7px 14px; border-radius: 999px; cursor: pointer; font-size: 12.5px; font-weight: 600;
    transition: all 0.15s ease;
  }
  .controls .filter-btn:hover { border-color: var(--accent); }
  .controls .filter-btn.active { background: var(--accent-soft); border-color: var(--accent); color: var(--accent); }
  .controls select, .controls input[type="text"] {
    background: var(--panel-alt); border: 1px solid var(--border); color: var(--text);
    padding: 7px 12px; border-radius: 6px; font-size: 12.5px;
  }
  .controls input[type="text"] { min-width: 220px; }
  .controls .spacer { flex: 1; }
  .controls .result-count { color: var(--text-muted); font-size: 12.5px; }

  table { width: 100%; min-width: 980px; table-layout: fixed; border-collapse: collapse; background: var(--panel); border: 1px solid var(--border); border-radius: var(--radius); overflow: hidden; }
  thead th {
    text-align: left; font-size: 11.5px; text-transform: uppercase; letter-spacing: 0.5px;
    color: var(--text-muted); background: var(--panel-alt); padding: 12px 14px; border-bottom: 1px solid var(--border);
    position: sticky; top: 0;
  }
  tbody td { padding: 12px 14px; border-bottom: 1px solid var(--border); vertical-align: top; overflow-wrap: break-word; word-break: break-word; }
  tbody tr:hover { background: rgba(59,157,255,0.05); }
  tbody tr.hidden-row { display: none; }
  .col-control { width: 15%; }
  .cell-sub { color: var(--text-muted); font-size: 11.5px; margin-top: 3px; }
  .col-status { width: 8%; }
  .col-severity { width: 8%; }
  .col-value { width: 24%; font-size: 12.5px; }
  .mv-block { margin-bottom: 6px; }
  .mv-block:last-child { margin-bottom: 0; }
  .mv-label {
    font-size: 9.5px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.6px;
    color: var(--text-muted); margin-bottom: 3px;
  }
  .mv-content {
    background: var(--panel-alt); border: 1px solid var(--border); border-left: 3px solid var(--border);
    border-radius: 6px; padding: 6px 9px; max-height: 150px; overflow-y: auto;
    line-height: 1.55; color: var(--text);
  }
  .mv-content.mv-expected { color: var(--text-muted); border-left-color: var(--border); }
  .mv-content.mv-status-pass { border-left-color: var(--green); }
  .mv-content.mv-status-fail { border-left-color: var(--red); }
  .mv-content.mv-status-warn { border-left-color: var(--amber); }
  .mv-content.mv-status-info { border-left-color: var(--blue); }
  .mv-divider { height: 1px; background: var(--border); margin: 6px 0; }
  .col-frameworks { width: 20%; font-size: 10.5px; color: var(--text-muted); }
  .fw-chips { display: flex; flex-wrap: wrap; gap: 4px; }
  .fw-chip {
    display: inline-flex; align-items: center; gap: 4px; background: var(--panel-alt);
    border: 1px solid var(--border); border-radius: 5px; padding: 2px 6px; font-size: 10px;
    white-space: nowrap; max-width: 100%; overflow: hidden; text-overflow: ellipsis;
  }
  .fw-chip b { color: var(--accent); font-weight: 700; }
  .fw-chip-empty { color: var(--text-muted); font-style: italic; }
  .col-remediation { width: 25%; font-size: 12.5px; color: var(--text); }

  .badge { display: inline-block; padding: 3px 10px; border-radius: 999px; font-size: 11px; font-weight: 800; letter-spacing: 0.4px; }
  .status-pass { background: rgba(51,196,129,0.18); color: var(--green); border: 1px solid var(--green); }
  .status-fail { background: rgba(255,92,114,0.18); color: var(--red); border: 1px solid var(--red); }
  .status-warn { background: rgba(255,184,77,0.18); color: var(--amber); border: 1px solid var(--amber); }
  .status-info { background: rgba(79,176,255,0.18); color: var(--blue); border: 1px solid var(--blue); }

  .sev-critical { background: rgba(255,59,92,0.18); color: var(--crit); border: 1px solid var(--crit); }
  .sev-high { background: rgba(255,122,69,0.18); color: var(--high); border: 1px solid var(--high); }
  .sev-medium { background: rgba(255,192,67,0.18); color: var(--med); border: 1px solid var(--med); }
  .sev-low { background: rgba(91,157,255,0.18); color: var(--low); border: 1px solid var(--low); }
  .sev-informational { background: rgba(138,151,173,0.18); color: var(--info-sev); border: 1px solid var(--info-sev); }

  footer { text-align: center; color: var(--text-muted); font-size: 11.5px; margin-top: 28px; padding-bottom: 10px; }
  .table-scroll { overflow-x: auto; }

  .expand-preview { color: inherit; }
  .expand-btn {
    display: inline-flex; align-items: center; gap: 4px; margin-top: 6px;
    background: none; border: none; color: var(--accent); font-size: 11.5px; font-weight: 700;
    letter-spacing: 0.2px; cursor: pointer; padding: 0; font-family: inherit;
  }
  .expand-btn:hover, .expand-btn:focus-visible { text-decoration: underline; }

  .modal-overlay {
    position: fixed; inset: 0; background: rgba(5,9,18,0.72);
    display: none; align-items: flex-start; justify-content: center;
    padding: 8vh 20px; z-index: 1000; overflow-y: auto;
  }
  .modal-overlay.open { display: flex; }
  .modal-box {
    background: var(--panel); border: 1px solid var(--border); border-radius: var(--radius);
    box-shadow: var(--shadow); max-width: 720px; width: 100%; max-height: 80vh;
    display: flex; flex-direction: column; overflow: hidden;
  }
  .modal-header {
    display: flex; align-items: flex-start; justify-content: space-between; gap: 16px;
    padding: 16px 20px; border-bottom: 1px solid var(--border); flex-shrink: 0;
  }
  .modal-header h2 { margin: 0; font-size: 14.5px; font-weight: 700; color: var(--text); }
  .modal-close {
    background: var(--panel-alt); border: 1px solid var(--border); color: var(--text-muted);
    width: 28px; height: 28px; border-radius: 6px; cursor: pointer; font-size: 16px; line-height: 1;
    display: flex; align-items: center; justify-content: center; flex-shrink: 0;
  }
  .modal-close:hover, .modal-close:focus-visible { border-color: var(--accent); color: var(--accent); }
  .modal-body { padding: 16px 20px; overflow-y: auto; font-size: 13px; line-height: 1.6; color: var(--text); }
  .modal-list { margin: 0; padding-left: 20px; }
  .modal-list li { margin-bottom: 7px; word-break: break-word; }
  .modal-list li:last-child { margin-bottom: 0; }
  .modal-body p { margin: 0; word-break: break-word; }
</style>
</head>
<body>
<div class="wrap">

  <header class="brand">
    <div class="brand-title">
      <div class="logo">EP</div>
      <div>
        <h1>EndpointPostureCheck</h1>
        <div class="sub">Enterprise Endpoint Security Posture Audit &middot; v{{VERSION}}</div>
      </div>
    </div>
    <div class="brand-meta">
      <div>Host: <strong>{{COMPUTERNAME}}</strong></div>
      <div>OS: <strong>{{OSINFO}}</strong></div>
      <div>Scanned: <strong>{{TIMESTAMP}}</strong> &middot; Duration: <strong>{{DURATION}}</strong></div>
    </div>
  </header>

  <section class="card sysinfo-panel">
    <div class="panel-title">System Overview</div>
    <div class="sysinfo-grid">
      <div class="sysinfo-tile"><div class="sysinfo-label">Computer Name</div><div class="sysinfo-value">{{COMPUTERNAME}}</div></div>
      <div class="sysinfo-tile"><div class="sysinfo-label">Domain / Workgroup</div><div class="sysinfo-value">{{SYS_DOMAIN}}</div></div>
      <div class="sysinfo-tile"><div class="sysinfo-label">Current User (Session)</div><div class="sysinfo-value">{{SYS_CURRENTUSER}}</div></div>
      <div class="sysinfo-tile"><div class="sysinfo-label">Operating System</div><div class="sysinfo-value">{{SYS_OSVERSION}}</div></div>
      <div class="sysinfo-tile"><div class="sysinfo-label">Uptime</div><div class="sysinfo-value">{{SYS_UPTIME}}</div></div>
      <div class="sysinfo-tile"><div class="sysinfo-label">Last Boot</div><div class="sysinfo-value">{{SYS_LASTBOOT}}</div></div>
      <div class="sysinfo-tile"><div class="sysinfo-label">Manufacturer / Model</div><div class="sysinfo-value">{{SYS_MANUFACTURER}} {{SYS_MODEL}}</div></div>
      <div class="sysinfo-tile"><div class="sysinfo-label">CPU</div><div class="sysinfo-value">{{SYS_CPU}}</div></div>
      <div class="sysinfo-tile"><div class="sysinfo-label">RAM</div><div class="sysinfo-value">{{SYS_RAM}}</div></div>
      <div class="sysinfo-tile"><div class="sysinfo-label">IPv4 Address(es)</div><div class="sysinfo-value">{{SYS_IP}}</div></div>
      <div class="sysinfo-tile"><div class="sysinfo-label">Disk Space</div><div class="sysinfo-value">{{SYS_DISK}}</div></div>
      <div class="sysinfo-tile"><div class="sysinfo-label">BitLocker</div><div class="sysinfo-value">{{SYS_BITLOCKER}}</div></div>
      <div class="sysinfo-tile"><div class="sysinfo-label">Installed Applications</div><div class="sysinfo-value">{{SYS_APPCOUNT}}</div></div>
    </div>
  </section>

  <section class="summary-grid">
    <div class="card score-card">
      <div class="score-ring"><div class="score-value">{{SCORE}}%<small>Compliance</small></div></div>
      <div class="risk-badge-wrap"><span class="risk-pill {{RISK_CLASS}}">{{RISK_LEVEL}} RISK</span></div>
    </div>
    <div class="card stat-card stat-total"><div class="stat-num">{{TOTAL}}</div><div class="stat-label">Controls Evaluated</div></div>
    <div class="card stat-card stat-pass"><div class="stat-num">{{PASS_COUNT}}</div><div class="stat-label">Pass</div></div>
    <div class="card stat-card stat-fail"><div class="stat-num">{{FAIL_COUNT}}</div><div class="stat-label">Fail</div></div>
    <div class="card stat-card stat-warn"><div class="stat-num">{{WARN_COUNT}}</div><div class="stat-label">Warn</div></div>
    <div class="card stat-card stat-info"><div class="stat-num">{{INFO_COUNT}}</div><div class="stat-label">Info</div></div>
  </section>

  <section class="controls">
    <button class="filter-btn active" data-filter="all">All</button>
    <button class="filter-btn" data-filter="fail">Failures Only</button>
    <button class="filter-btn" data-filter="warn">Warnings Only</button>
    <button class="filter-btn" data-filter="crithigh">Critical / High Only</button>
    <select id="categorySelect">
      <option value="">All Categories</option>
      {{CATEGORY_OPTIONS}}
    </select>
    <input type="text" id="searchBox" placeholder="Search controls, categories, remediation..." />
    <div class="spacer"></div>
    <div class="result-count"><span id="visibleCount">{{TOTAL}}</span> of {{TOTAL}} controls shown</div>
  </section>

  <div class="table-scroll">
  <table id="findingsTable">
    <colgroup>
      <col class="col-control">
      <col class="col-status">
      <col class="col-severity">
      <col class="col-value">
      <col class="col-frameworks">
      <col class="col-remediation">
    </colgroup>
    <thead>
      <tr>
        <th>Control</th>
        <th>Status</th>
        <th>Severity</th>
        <th>Measured vs Expected</th>
        <th>Framework Mapping</th>
        <th>Remediation Guidance</th>
      </tr>
    </thead>
    <tbody>
      {{TABLE_ROWS}}
    </tbody>
  </table>
  </div>

  <footer>
    Generated by EndpointPostureCheck v{{VERSION}} on {{TIMESTAMP}} &middot; {{CRITICAL_FAILS}} critical failure(s), {{HIGH_FAILS}} high-severity failure(s) detected &middot; For authorized internal security assessment use only.
  </footer>

</div>

<div class="modal-overlay" id="detailModal">
  <div class="modal-box" role="dialog" aria-modal="true" aria-labelledby="modalTitle">
    <div class="modal-header">
      <h2 id="modalTitle"></h2>
      <button type="button" class="modal-close" id="modalCloseBtn" aria-label="Close">&times;</button>
    </div>
    <div class="modal-body" id="modalBody"></div>
  </div>
</div>

<script>
(function () {
  var modalData = {{MODAL_DATA_JSON}};
  var modalOverlay = document.getElementById('detailModal');
  var modalTitleEl = document.getElementById('modalTitle');
  var modalBodyEl = document.getElementById('modalBody');

  function openModal(id) {
    var entry = modalData[id];
    if (!entry) { return; }
    modalTitleEl.textContent = entry.title;
    modalBodyEl.innerHTML = entry.body;
    modalOverlay.classList.add('open');
  }

  function closeModal() {
    modalOverlay.classList.remove('open');
    modalBodyEl.innerHTML = '';
  }

  document.addEventListener('click', function (e) {
    var trigger = e.target.closest('.expand-btn');
    if (trigger) {
      openModal(trigger.getAttribute('data-modal-id'));
      return;
    }
    if (e.target.id === 'modalCloseBtn' || e.target === modalOverlay) {
      closeModal();
    }
  });

  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape') { closeModal(); }
  });
})();

(function () {
  var activeFilter = 'all';
  var activeCategory = '';
  var searchTerm = '';

  var rows = Array.prototype.slice.call(document.querySelectorAll('.finding-row'));
  var filterBtns = Array.prototype.slice.call(document.querySelectorAll('.filter-btn'));
  var categorySelect = document.getElementById('categorySelect');
  var searchBox = document.getElementById('searchBox');
  var visibleCountEl = document.getElementById('visibleCount');

  function applyFilters() {
    var visible = 0;
    rows.forEach(function (row) {
      var status = row.getAttribute('data-status');
      var severity = row.getAttribute('data-severity');
      var category = row.getAttribute('data-category');
      var searchData = row.getAttribute('data-search') || '';

      var passesFilter = true;
      if (activeFilter === 'fail') { passesFilter = status === 'FAIL'; }
      else if (activeFilter === 'warn') { passesFilter = status === 'WARN'; }
      else if (activeFilter === 'crithigh') { passesFilter = (severity === 'Critical' || severity === 'High'); }

      var passesCategory = activeCategory === '' || category === activeCategory;
      var passesSearch = searchTerm === '' || searchData.indexOf(searchTerm) !== -1;

      if (passesFilter && passesCategory && passesSearch) {
        row.classList.remove('hidden-row');
        visible++;
      } else {
        row.classList.add('hidden-row');
      }
    });
    visibleCountEl.textContent = visible;
  }

  filterBtns.forEach(function (btn) {
    btn.addEventListener('click', function () {
      filterBtns.forEach(function (b) { b.classList.remove('active'); });
      btn.classList.add('active');
      activeFilter = btn.getAttribute('data-filter');
      applyFilters();
    });
  });

  categorySelect.addEventListener('change', function () {
    activeCategory = categorySelect.value;
    applyFilters();
  });

  searchBox.addEventListener('input', function () {
    searchTerm = searchBox.value.toLowerCase();
    applyFilters();
  });
})();
</script>

</body>
</html>
'@
}

#endregion

#region ============================== JSON EXPORT ==============================

function Export-JsonReport {
    <#
        Exports the complete structured audit result set, plus posture metadata, to JSON.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [string]$OutputPath,
        [Parameter(Mandatory = $true)] [PSObject]$Posture
    )

    $osInfo = 'Unknown'
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $osInfo = "$($os.Caption) (Build $($os.BuildNumber))"
    } catch { $osInfo = $env:OS }

    $exportObject = [PSCustomObject]@{
        ToolName      = 'EndpointPostureCheck'
        ToolVersion   = $Script:ScriptVersion
        ComputerName  = $Script:ComputerName
        OperatingSystem = $osInfo
        ScanStartTime = (Get-Date -Date $Script:StartTime -Format 'yyyy-MM-dd HH:mm:ss')
        ScanEndTime   = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
        ComplianceScore = $Posture.Score
        RiskLevel     = $Posture.RiskLevel
        Summary       = [PSCustomObject]@{
            TotalControls = $Posture.Total
            Pass          = $Posture.PassCount
            Fail          = $Posture.FailCount
            Warn          = $Posture.WarnCount
            Info          = $Posture.InfoCount
            CriticalFails = $Posture.CriticalFails
            HighFails     = $Posture.HighFails
        }
        Findings      = $Script:AuditResults
    }

    $exportObject | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $OutputPath -Encoding UTF8 -Force
}

#endregion

#region ============================== REMEDIATION SCRIPT GENERATOR ==============================

function Get-RemediationSnippet {
    <#
        Returns a block of real, executable PowerShell remediation commands for a given FAIL
        finding. Uses pattern matching against the Control name (including regex capture of
        dynamic per-instance identifiers such as volume letters, ASR rule names, Schannel
        protocol/role pairs, firewall profile names, etc.) so that every distinct finding
        produced by the audit engine maps to concrete guidance. Findings that do not match a
        known pattern still receive a fully commented manual-remediation block built from
        their own Recommendation text - nothing is silently dropped.
    #>
    param([Parameter(Mandatory = $true)][PSObject]$Finding)

    $c = $Finding.Control
    $snippet = $null

    switch -Regex ($c) {
        'TPM 2\.0 Presence & Readiness' {
            $snippet = @"
# Enable/initialize the TPM. Firmware-level enablement (UEFI setup) cannot be scripted;
# this completes OS-side provisioning once the firmware TPM is turned on.
Initialize-Tpm -AllowClear -AllowPhysicalPresence
"@
        }
        'TPM Ownership' {
            $snippet = 'Initialize-Tpm -AllowClear -AllowPhysicalPresence'
        }
        'Secure Boot & UEFI' {
            $snippet = @"
# Secure Boot / UEFI mode cannot be enabled remotely via script - it requires a firmware
# setup change. Document as a manual remediation task for the next maintenance window:
Write-Warning 'MANUAL ACTION REQUIRED: Enter UEFI firmware setup (F2/F10/Del at boot), enable Secure Boot, and/or convert the disk to GPT using MBR2GPT.exe /convert /allowFullOS prior to switching firmware mode from Legacy/CSM to UEFI.'
"@
        }
        'Hardware-Enforced Kernel DMA Protection' {
            $snippet = @"
`$dmaPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection'
if (-not (Test-Path `$dmaPath)) { New-Item -Path `$dmaPath -Force | Out-Null }
Set-ItemProperty -Path `$dmaPath -Name 'DeviceEnumerationPolicy' -Type DWord -Value 0
"@
        }
        'Virtualization-Based Security \(VBS\)|Hypervisor-Enforced Code Integrity' {
            $snippet = @"
`$dgPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard'
if (-not (Test-Path `$dgPath)) { New-Item -Path `$dgPath -Force | Out-Null }
Set-ItemProperty -Path `$dgPath -Name 'EnableVirtualizationBasedSecurity' -Type DWord -Value 1
Set-ItemProperty -Path `$dgPath -Name 'RequirePlatformSecurityFeatures' -Type DWord -Value 3
`$hvciPath = Join-Path `$dgPath 'Scenarios\HypervisorEnforcedCodeIntegrity'
if (-not (Test-Path `$hvciPath)) { New-Item -Path `$hvciPath -Force | Out-Null }
Set-ItemProperty -Path `$hvciPath -Name 'Enabled' -Type DWord -Value 1
Write-Warning 'A reboot is required for VBS/HVCI changes to take effect.'
"@
        }
        'Credential Guard' {
            $snippet = @"
`$lsaCgPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\LSA'
Set-ItemProperty -Path `$lsaCgPath -Name 'LsaCfgFlags' -Type DWord -Value 1
`$dgPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\CredentialGuard'
if (-not (Test-Path `$dgPath)) { New-Item -Path `$dgPath -Force | Out-Null }
Set-ItemProperty -Path `$dgPath -Name 'Enabled' -Type DWord -Value 1
Write-Warning 'A reboot is required for Credential Guard to activate.'
"@
        }
        'System Guard Secure Launch' {
            $snippet = @"
`$slPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\SystemGuard'
if (-not (Test-Path `$slPath)) { New-Item -Path `$slPath -Force | Out-Null }
Set-ItemProperty -Path `$slPath -Name 'Enabled' -Type DWord -Value 1
Write-Warning 'System Guard Secure Launch requires DRTM-capable firmware (Intel TXT / AMD SKINIT); verify hardware support before enabling.'
"@
        }
        'LSA Protection \(RunAsPPL\)' {
            $snippet = @"
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RunAsPPL' -Type DWord -Value 1
Write-Warning 'A reboot is required for LSA Protection (RunAsPPL) to take effect.'
"@
        }
        'BitLocker Encryption Status - .*\(([A-Za-z]:)\)' {
            $mp = $Matches[1]
            $snippet = "Enable-BitLocker -MountPoint '$mp' -EncryptionMethod XtsAes256 -UsedSpaceOnly -RecoveryPasswordProtector`nResume-BitLocker -MountPoint '$mp'"
        }
        'BitLocker Cipher Strength - .*\(([A-Za-z]:)\)' {
            $mp = $Matches[1]
            $snippet = @"
# Re-encrypting to change cipher requires decrypting first, then re-enabling with the new method.
Disable-BitLocker -MountPoint '$mp'
Write-Warning 'Wait for decryption to complete (Get-BitLockerVolume), then run:'
# Enable-BitLocker -MountPoint '$mp' -EncryptionMethod XtsAes256 -UsedSpaceOnly -RecoveryPasswordProtector
"@
        }
        'BitLocker Key Protector Architecture' {
            $snippet = @"
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\FVE' -Name 'UseTPMPIN' -Type DWord -Value 1 -ErrorAction SilentlyContinue
Add-BitLockerKeyProtector -MountPoint 'C:' -TpmAndPinProtector -Pin (Read-Host -AsSecureString 'Enter new BitLocker PIN')
"@
        }
        'BitLocker Recovery Key Backup' {
            $snippet = @"
Add-BitLockerKeyProtector -MountPoint 'C:' -RecoveryPasswordProtector
# Escrow to Entra ID (if Entra-joined):
# BackupToAAD-BitLockerKeyProtector -MountPoint 'C:' -KeyProtectorId ((Get-BitLockerVolume -MountPoint 'C:').KeyProtector | Where-Object {`$_.KeyProtectorType -eq 'RecoveryPassword'}).KeyProtectorId
"@
        }
        'Defender (Real-Time Monitoring|Behavior Monitoring)' {
            $snippet = 'Set-MpPreference -DisableRealtimeMonitoring $false' + "`n" + 'Set-MpPreference -DisableBehaviorMonitoring $false'
        }
        'Defender (IOAV|On-Access)' {
            $snippet = 'Set-MpPreference -DisableIOAVProtection $false'
        }
        'AMSI Script Scanning' {
            $snippet = 'Set-MpPreference -DisableScriptScanning $false'
        }
        'Cloud-Delivered Protection \(MAPS\)' {
            $snippet = 'Set-MpPreference -MAPSReporting Advanced'
        }
        'Automatic Sample Submission' {
            $snippet = 'Set-MpPreference -SubmitSamplesConsent SendSafeSamples'
        }
        'Cloud Block-at-First-Sight Level' {
            $snippet = 'Set-MpPreference -CloudBlockLevel High'
        }
        'Antivirus Signature Freshness' {
            $snippet = 'Update-MpSignature'
        }
        'Antimalware Engine & Platform Health' {
            $snippet = "Start-Service -Name WinDefend -ErrorAction SilentlyContinue`nGet-Service WinDefend | Select-Object Status,StartType"
        }
        'Tamper Protection' {
            $snippet = "Write-Warning 'Tamper Protection cannot be enabled via local PowerShell by design (this is intentional - it prevents script-based tampering). Enable it via Windows Security app, Intune Endpoint Security policy, or Microsoft 365 Defender portal > Endpoints > Configuration Management.'"
        }
        'Potentially Unwanted Application \(PUA\) Protection' {
            $snippet = 'Set-MpPreference -PUAProtection Enabled'
        }
        'Microsoft Defender for Endpoint \(MDE\) Onboarding' {
            $snippet = "Write-Warning 'Onboard this device via the onboarding package/script generated from the Microsoft 365 Defender portal (Settings > Endpoints > Onboarding), or push the Intune/GPO-based onboarding configuration profile.'"
        }
        '^ASR Rule: (.+)$' {
            $ruleName = $Matches[1]
            $guid = $null
            foreach ($kv in $Script:ASRRuleMap.GetEnumerator()) { if ($kv.Value -eq $ruleName) { $guid = $kv.Key } }
            if ($guid) {
                $snippet = "Add-MpPreference -AttackSurfaceReductionRules_Ids $guid -AttackSurfaceReductionRules_Actions Enabled"
            } else {
                $snippet = "Write-Warning 'Could not resolve GUID for ASR rule: $ruleName - configure via Intune Endpoint Security > Attack Surface Reduction.'"
            }
        }
        'ASR Rules - Overall Configuration' {
            $snippet = @"
# Baseline: enable Block mode for all mapped ASR rules.
`$asrRules = @(
"@ + "`n" + (($Script:ASRRuleMap.Keys | ForEach-Object { "    '$_'" }) -join ",`n") + "`n)`nforeach (`$id in `$asrRules) { Add-MpPreference -AttackSurfaceReductionRules_Ids `$id -AttackSurfaceReductionRules_Actions Enabled }"
        }
        'Data Execution Prevention \(DEP\)' {
            $snippet = 'Set-ProcessMitigation -System -Enable DEP'
        }
        'Address Space Layout Randomization \(ASLR\)' {
            $snippet = 'Set-ProcessMitigation -System -Enable ForceRelocateImages,BottomUp,HighEntropy'
        }
        'Control Flow Guard \(CFG\)' {
            $snippet = 'Set-ProcessMitigation -System -Enable CFG'
        }
        'Heap Integrity' {
            $snippet = 'Set-ProcessMitigation -System -Enable TerminateOnError'
        }
        'Windows Defender Application Control \(WDAC\)' {
            $snippet = "Write-Warning 'WDAC policy authoring/deployment is environment-specific and cannot be safely auto-generated. Build a policy with New-CIPolicy -Level Publisher -FilePath policy.xml -ScanPath C:\ -UserPEs -MultiplePolicyFormat, convert with ConvertFrom-CIPolicy, then deploy via Intune or copy to $env:WINDIR\System32\CodeIntegrity\CIPolicies\Active\.'"
        }
        '^AppLocker Rule Collection - (.+)$|^AppLocker Rule Enforcement$' {
            $snippet = "Write-Warning 'Author AppLocker rules via Local Security Policy > Application Control Policies > AppLocker (right-click each rule collection > Create Default Rules, then add publisher/path rules as needed), then set enforcement mode to Enabled and restart the Application Identity service: Set-Service -Name AppIDSvc -StartupType Automatic; Start-Service AppIDSvc'"
        }
        'Windows Installer AlwaysInstallElevated' {
            $snippet = @"
Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name 'AlwaysInstallElevated' -ErrorAction SilentlyContinue
Remove-ItemProperty -Path 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name 'AlwaysInstallElevated' -ErrorAction SilentlyContinue
"@
        }
        'Unquoted Service Path Vulnerabilities' {
            $snippet = "Write-Warning 'Review each affected service reported in the audit findings and re-quote its ImagePath: sc.exe config <ServiceName> binPath= `"\`"C:\Path With Space\service.exe\`"`"'"
        }
        'Built-in Administrator Account State' {
            $snippet = 'Disable-LocalUser -Name (Get-LocalUser | Where-Object { $_.SID -like "*-500" }).Name'
        }
        'Built-in Guest Account State' {
            $snippet = 'Disable-LocalUser -Name (Get-LocalUser | Where-Object { $_.SID -like "*-501" }).Name'
        }
        'Local Administrator Password Solution \(LAPS\)' {
            $snippet = "Write-Warning 'Deploy Windows LAPS via GPO/Intune: install the LAPS ADMX templates, then configure Computer Configuration > Administrative Templates > System > LAPS > Enable Windows LAPS = Enabled, and set backup directory (AD or Entra ID) and password complexity policy.'"
        }
        'Account Lockout Threshold' {
            $snippet = "net accounts /lockoutthreshold:5"
        }
        'Minimum Password Length' {
            $snippet = "net accounts /minpwlen:14"
        }
        'Password Complexity Requirements' {
            $snippet = @"
`$cfgFile = "`$env:TEMP\pwdcomplexity.cfg"
secedit /export /cfg `$cfgFile /quiet
(Get-Content `$cfgFile) -replace 'PasswordComplexity = 0','PasswordComplexity = 1' | Set-Content `$cfgFile
secedit /configure /db "`$env:windir\security\local.sdb" /cfg `$cfgFile /quiet
Remove-Item `$cfgFile -Force
"@
        }
        'Maximum Password Age' {
            $snippet = "net accounts /maxpwage:365"
        }
        'Password History Enforcement' {
            $snippet = "net accounts /uniquepw:24"
        }
        'UAC Enforcement \(EnableLUA\)' {
            $snippet = "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableLUA' -Type DWord -Value 1`nWrite-Warning 'A reboot is required for this change to take effect.'"
        }
        'UAC Elevation Prompt Behavior' {
            $snippet = "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'ConsentPromptBehaviorAdmin' -Type DWord -Value 2"
        }
        'UAC Secure Desktop Prompting' {
            $snippet = "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'PromptOnSecureDesktop' -Type DWord -Value 1"
        }
        'Admin Approval Mode \(Token Filtering\)' {
            $snippet = "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'FilterAdministratorToken' -Type DWord -Value 1"
        }
        '^Windows Firewall - (\w+) Profile State$' {
            $profileName = $Matches[1]
            $snippet = "Set-NetFirewallProfile -Profile $profileName -Enabled True"
        }
        '^Windows Firewall - (\w+) Default Inbound Action$' {
            $profileName = $Matches[1]
            $snippet = "Set-NetFirewallProfile -Profile $profileName -DefaultInboundAction Block"
        }
        'SMBv1 Protocol' {
            $snippet = "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart`nSet-SmbServerConfiguration -EnableSMB1Protocol `$false -Force"
        }
        'Link-Local Multicast Name Resolution \(LLMNR\)' {
            $snippet = @"
`$dnsClientPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
if (-not (Test-Path `$dnsClientPath)) { New-Item -Path `$dnsClientPath -Force | Out-Null }
Set-ItemProperty -Path `$dnsClientPath -Name 'EnableMulticast' -Type DWord -Value 0
"@
        }
        'NetBIOS over TCP/IP' {
            $snippet = "Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' | ForEach-Object { Invoke-CimMethod -InputObject `$_ -MethodName SetTcpipNetbios -Arguments @{TcpipNetbiosOptions = 2} }"
        }
        'Multicast DNS \(mDNS\)' {
            $snippet = @"
`$dnsClientPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
if (-not (Test-Path `$dnsClientPath)) { New-Item -Path `$dnsClientPath -Force | Out-Null }
Set-ItemProperty -Path `$dnsClientPath -Name 'EnableMDNS' -Type DWord -Value 0
"@
        }
        'WPAD Auto-Discovery' {
            $snippet = "Set-Service -Name WinHttpAutoProxySvc -StartupType Disabled -ErrorAction SilentlyContinue"
        }
        'Remote Desktop Protocol \(RDP\) State' {
            $snippet = "Write-Warning 'If RDP is not operationally required, disable it:'`nSet-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -Type DWord -Value 1"
        }
        'RDP Network Level Authentication \(NLA\)' {
            $snippet = "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'UserAuthentication' -Type DWord -Value 1"
        }
        'Default Administrative Shares' {
            $snippet = "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'AutoShareWks' -Type DWord -Value 0`nRestart-Service -Name LanmanServer -Force"
        }
        'SMB Server Signing Requirement' {
            $snippet = 'Set-SmbServerConfiguration -RequireSecuritySignature $true -Force'
        }
        'SMB Client Signing Requirement' {
            $snippet = 'Set-SmbClientConfiguration -RequireSecuritySignature $true -Force'
        }
        'SMB Encryption \(Server\)' {
            $snippet = 'Set-SmbServerConfiguration -EncryptData $true -Force'
        }
        '^Schannel Protocol - (.+?) \((Client|Server)\)$' {
            $proto = $Matches[1]
            $role = $Matches[2]
            $isLegacy = $proto -in @('SSL 2.0', 'SSL 3.0', 'TLS 1.0', 'TLS 1.1')
            $valueToSet = if ($isLegacy) { 0 } else { 1 }
            $snippet = @"
`$path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$proto\$role'
if (-not (Test-Path `$path)) { New-Item -Path `$path -Force | Out-Null }
Set-ItemProperty -Path `$path -Name 'Enabled' -Type DWord -Value $valueToSet
Set-ItemProperty -Path `$path -Name 'DisabledByDefault' -Type DWord -Value $(if ($isLegacy) { 1 } else { 0 })
Write-Warning 'A reboot is required for Schannel protocol changes to take effect.'
"@
        }
        'Weak Cipher Suite Exposure' {
            $snippet = "Write-Warning 'Review the weak suite list in the audit findings, then remove each with: Disable-TlsCipherSuite -Name <SuiteName>. Consider applying the full GPO `"SSL Cipher Suite Order`" with an approved modern-only list instead of removing suites individually.'"
        }
        '^Schannel Hashing Algorithm - (MD5|SHA)$' {
            $alg = $Matches[1]
            $snippet = @"
`$path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\$alg'
if (-not (Test-Path `$path)) { New-Item -Path `$path -Force | Out-Null }
Set-ItemProperty -Path `$path -Name 'Enabled' -Type DWord -Value 0
"@
        }
        'Legacy PowerShell v2 Engine' {
            $snippet = 'Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart'
        }
        'PowerShell (Script Block|Module|Transcription) Logging' {
            $subKey = switch -Regex ($c) {
                'Script Block' { 'ScriptBlockLogging'; break }
                'Module' { 'ModuleLogging'; break }
                'Transcription' { 'Transcription'; break }
            }
            $valueName = switch ($subKey) {
                'ScriptBlockLogging' { 'EnableScriptBlockLogging' }
                'ModuleLogging' { 'EnableModuleLogging' }
                'Transcription' { 'EnableTranscripting' }
            }
            $snippet = @"
`$path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\$subKey'
if (-not (Test-Path `$path)) { New-Item -Path `$path -Force | Out-Null }
Set-ItemProperty -Path `$path -Name '$valueName' -Type DWord -Value 1
"@
        }
        'PowerShell Execution Policy' {
            $snippet = 'Set-ExecutionPolicy RemoteSigned -Scope LocalMachine -Force'
        }
        'PowerShell Language Mode' {
            $snippet = "Write-Warning 'Constrained Language Mode is enforced via a deployed WDAC policy, not a direct setting. Build/deploy a WDAC policy so standard users are automatically placed into ConstrainedLanguage mode.'"
        }
        '^Advanced Audit Policy - (.+)$' {
            $subcat = $Matches[1]
            $snippet = "auditpol /set /subcategory:`"$subcat`" /success:enable /failure:enable"
        }
        'Process Creation Command-Line Auditing' {
            $snippet = @"
`$auditPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
if (-not (Test-Path `$auditPath)) { New-Item -Path `$auditPath -Force | Out-Null }
Set-ItemProperty -Path `$auditPath -Name 'ProcessCreationIncludeCmdLine_Enabled' -Type DWord -Value 1
auditpol /set /subcategory:"Process Creation" /success:enable
"@
        }
        'LAN Manager Authentication Level' {
            $snippet = "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LmCompatibilityLevel' -Type DWord -Value 5"
        }
        'LM Hash Storage Prevention' {
            $snippet = "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'NoLmHash' -Type DWord -Value 1`nWrite-Warning 'Force a password change on all local accounts to purge any previously stored LM hash.'"
        }
        'Anonymous SAM/Share Enumeration Restriction' {
            $snippet = @"
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RestrictAnonymous' -Type DWord -Value 1
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RestrictAnonymousSAM' -Type DWord -Value 1
"@
        }
        'Everyone Permissions Applied to Anonymous Users' {
            $snippet = "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'EveryoneIncludesAnonymous' -Type DWord -Value 0"
        }
        'SMB Insecure Guest Logon' {
            $snippet = @"
`$path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation'
if (-not (Test-Path `$path)) { New-Item -Path `$path -Force | Out-Null }
Set-ItemProperty -Path `$path -Name 'AllowInsecureGuestAuth' -Type DWord -Value 0
"@
        }
        '^User Right - Deny (Network|Remote Interactive) Logon for Guest$' {
            $rightName = if ($Matches[1] -eq 'Network') { 'SeDenyNetworkLogonRight' } else { 'SeDenyRemoteInteractiveLogonRight' }
            $snippet = "Write-Warning 'User Rights Assignment changes are not auto-applied to avoid overwriting existing, unrelated privilege grants on this right. Add the Guests group (or its SID S-1-5-32-546) to `"$rightName`" via Local Security Policy (secpol.msc) > Local Policies > User Rights Assignment, or via a change-controlled secedit /configure import.'"
        }
        'User Right - Debug Programs \(SeDebugPrivilege\)' {
            $snippet = "Write-Warning 'User Rights Assignment changes are not auto-applied to avoid overwriting existing, unrelated privilege grants on this right. Restrict `"Debug programs`" (SeDebugPrivilege) to the Administrators group only via Local Security Policy (secpol.msc) > Local Policies > User Rights Assignment, or via a change-controlled secedit /configure import.'"
        }
        'Local Administrators Group Membership' {
            $snippet = "Write-Warning 'Group membership changes are not auto-applied - removing the wrong account can lock out legitimate administration. Review the member list captured in this finding and remove unjustified accounts manually: Remove-LocalGroupMember -Group Administrators -Member <AccountName>.'"
        }
        'Machine Inactivity Lock Timeout' {
            $snippet = "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'InactivityTimeoutSecs' -Type DWord -Value 900"
        }
        'Suppress Last Signed-In Username at Logon' {
            $snippet = "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'DontDisplayLastUserName' -Type DWord -Value 1"
        }
        'Cached Domain Credentials Count' {
            $snippet = "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'CachedLogonsCount' -Type String -Value '4'"
        }
        'Point-and-Print Driver Installation Restriction' {
            $snippet = @"
`$path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint'
if (-not (Test-Path `$path)) { New-Item -Path `$path -Force | Out-Null }
Set-ItemProperty -Path `$path -Name 'RestrictDriverInstallationToAdministrators' -Type DWord -Value 1
"@
        }
        'WinRM Unencrypted Traffic' {
            $snippet = @"
`$path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'
if (-not (Test-Path `$path)) { New-Item -Path `$path -Force | Out-Null }
Set-ItemProperty -Path `$path -Name 'AllowUnencryptedTraffic' -Type DWord -Value 0
"@
        }
        'WinRM Basic Authentication \(Service\)' {
            $snippet = @"
`$path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'
if (-not (Test-Path `$path)) { New-Item -Path `$path -Force | Out-Null }
Set-ItemProperty -Path `$path -Name 'AllowBasic' -Type DWord -Value 0
"@
        }
        'Remote Registry Service' {
            $snippet = "Stop-Service -Name RemoteRegistry -Force -ErrorAction SilentlyContinue`nSet-Service -Name RemoteRegistry -StartupType Disabled"
        }
        'Autorun/Autoplay for Removable Drives' {
            $snippet = @"
`$path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
if (-not (Test-Path `$path)) { New-Item -Path `$path -Force | Out-Null }
Set-ItemProperty -Path `$path -Name 'NoDriveTypeAutoRun' -Type DWord -Value 255
"@
        }
        'Windows Defender SmartScreen \(Explorer/Apps\)' {
            $snippet = @"
`$path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
if (-not (Test-Path `$path)) { New-Item -Path `$path -Force | Out-Null }
Set-ItemProperty -Path `$path -Name 'EnableSmartScreen' -Type DWord -Value 1
Set-ItemProperty -Path `$path -Name 'ShellSmartScreenLevel' -Type String -Value 'Block'
"@
        }
        'Windows Update Service Health' {
            $snippet = "Set-Service -Name wuauserv -StartupType Manual`nStart-Service -Name wuauserv"
        }
        'Patch Recency' {
            $snippet = "Write-Warning 'Patch installation cannot be safely automated blind (may require a maintenance window/reboot). Trigger an update scan/install via Settings > Windows Update, or (Get-CimInstance -Namespace root\\ccm\\clientsdk -ClassName CCM_SoftwareUpdatesManager) / Intune remediation, then verify WSUS/Intune connectivity if updates continue to lag.'"
        }
        'Windows Time Service State' {
            $snippet = "Set-Service -Name W32Time -StartupType Automatic`nStart-Service -Name W32Time"
        }
        'Time Source Configuration' {
            $snippet = "Write-Warning 'Review your organization''s approved NTP source before applying. Example for a domain-joined device (uses domain hierarchy automatically): w32tm /config /syncfromflags:domhier /update. Example for a standalone device: w32tm /config /manualpeerlist:`"time.windows.com`" /syncfromflags:manual /reliable:yes /update'"
        }
        '^Event Log Maximum Size - (.+)$' {
            $logName = $Matches[1]
            $sizeMap = @{ 'Security' = '196608KB'; 'Application' = '32768KB'; 'System' = '32768KB'; 'Setup' = '32768KB' }
            $sizeVal = $sizeMap[$logName]
            if (-not $sizeVal) { $sizeVal = '32768KB' }
            $snippet = "Limit-EventLog -LogName '$logName' -MaximumSize $sizeVal"
        }
        '^Unquoted Service Path - Writable Break Point \((.+)\)$' {
            $svcName = $Matches[1]
            $snippet = "Write-Warning 'Quote the binary path for service `"$svcName`" - the exact new binPath value depends on the current unquoted path recorded in this finding. Run: sc.exe qc `"$svcName`" to view the current path, then sc.exe config `"$svcName`" binPath= `"\`"<full path from qc output>\`"`"'"
        }
        '^Service Executable ACL - Writable by Low-Privilege User \((.+)\)$' {
            $svcName = $Matches[1]
            $snippet = "Write-Warning 'Tighten the ACL on the executable backing service `"$svcName`" - run sc.exe qc `"$svcName`" to find its binary path, then: icacls `"<path-from-qc>`" /remove:g `"Everyone`" `"Authenticated Users`" `"Users`"'"
        }
        '^Service Registry Key ACL - Writable by Low-Privilege User \((.+)\)$' {
            $svcName = $Matches[1]
            $snippet = "Write-Warning 'Registry ACL changes are not auto-applied to avoid corrupting other inherited permissions. Restore default permissions on HKLM:\SYSTEM\CurrentControlSet\Services\$svcName via regedit (right-click > Permissions > Advanced > Disable inheritance > convert, then remove the Everyone/Authenticated Users/Users grant) or a change-controlled Set-Acl script.'"
        }
        'Writable PATH Directories' {
            $snippet = "Write-Warning 'Review each writable PATH directory listed in this finding and either remove the low-privilege write grant (icacls `"<dir>`" /remove:g `"Everyone`" `"Authenticated Users`" `"Users`") or remove the directory from the PATH environment variable entirely if it is not a legitimate, admin-controlled tool location.'"
        }
        'LSASS Handle Access Auditing Prerequisite' {
            $snippet = 'auditpol /set /subcategory:"Handle Manipulation" /success:enable /failure:enable'
        }
        'WDigest Plaintext Credential Caching' {
            $snippet = "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name 'UseLogonCredential' -Type DWord -Value 0"
        }
        'Plaintext Autologon Credentials in Registry' {
            $snippet = @"
`$winlogonPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
Remove-ItemProperty -Path `$winlogonPath -Name 'DefaultPassword' -ErrorAction SilentlyContinue
Set-ItemProperty -Path `$winlogonPath -Name 'AutoAdminLogon' -Type String -Value '0'
"@
        }
        '^Unattended Install File with Embedded Credential - (.+)$' {
            $filePath = $Matches[1]
            $snippet = "Remove-Item -LiteralPath '$filePath' -Force"
        }
        'GPP Cached Credentials \(cpassword\)' {
            $gppHistoryPath = Join-Path $env:ProgramData 'Microsoft\Group Policy\History'
            $snippet = "Write-Warning 'Remove each cpassword-bearing file listed in this finding, then remediate the source Group Policy Preferences item at the domain level (MS14-025) and rotate every credential that was ever distributed via GPP.'" + "`n" + "Get-ChildItem -LiteralPath '$gppHistoryPath' -Recurse -Filter *.xml -ErrorAction SilentlyContinue | Select-String -Pattern cpassword | Select-Object -ExpandProperty Path -Unique | Remove-Item -Force"
        }
        '^Registry Hive File Permissions - (SAM|SYSTEM|SECURITY)$' {
            $hiveName = $Matches[1]
            $snippet = "icacls `"$env:WINDIR\System32\config\$hiveName`" /reset"
        }
        '^Dangerous Privilege Assignment - (.+)$' {
            $privName = $Matches[1]
            $snippet = "Write-Warning 'User Rights Assignment changes are not auto-applied to avoid overwriting existing, unrelated privilege grants. Remove the unexpected principal(s) listed in this finding from `"$privName`" via Local Security Policy (secpol.msc) > Local Policies > User Rights Assignment.'"
        }
        'COM CLSID Hijacking \(HKCU Override\)' {
            $snippet = "Write-Warning 'Investigate each CLSID/DLL pair listed in this finding before removal. If illegitimate: Remove-Item -Path `"HKCU:\Software\Classes\CLSID\<GUID>`" -Recurse -Force'"
        }
        'Orphaned Privileged Scheduled Tasks' {
            $snippet = "Write-Warning 'For each task listed in this finding, either restore the missing target binary or remove the stale task: Unregister-ScheduledTask -TaskName `"<name>`" -TaskPath `"<path>`" -Confirm:`$false'"
        }
        'Privileged Scheduled Task Target ACLs' {
            $snippet = "Write-Warning 'Tighten the ACL on each privileged scheduled-task target listed in this finding: icacls `"<target-path>`" /remove:g `"Everyone`" `"Authenticated Users`" `"Users`"'"
        }
        'Microsoft Vulnerable Driver Blocklist' {
            $snippet = @"
`$path = 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config'
if (-not (Test-Path `$path)) { New-Item -Path `$path -Force | Out-Null }
Set-ItemProperty -Path `$path -Name 'VulnerableDriverBlocklistEnable' -Type DWord -Value 1
"@
        }
        'Kernel-Mode Test Signing' {
            $snippet = "bcdedit /set testsigning off`nWrite-Warning 'A reboot is required for this change to take effect.'"
        }
        'Loaded Kernel Driver Signature Validity' {
            $snippet = "Write-Warning 'Do not remove drivers automatically - investigate each one listed in this finding first (correlate with MDE/Defender alerts and hardware/software inventory). If confirmed malicious, boot into Safe Mode or use offline remediation tooling to remove the driver file and its service registration.'"
        }
        '^Registry Autorun Key ACL - (.+)$' {
            $keyPath = $Matches[1]
            $snippet = "Write-Warning 'Registry ACL changes are not auto-applied to avoid corrupting other inherited permissions. Restore default permissions on $keyPath via regedit (right-click > Permissions > Advanced) or a change-controlled Set-Acl script, removing the Everyone/Authenticated Users/Users grant.'"
        }
        'Winlogon Shell Value' {
            $snippet = "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'Shell' -Type String -Value 'explorer.exe'"
        }
        'Winlogon Userinit Value' {
            $snippet = "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'Userinit' -Type String -Value 'C:\Windows\system32\userinit.exe,'"
        }
        'AppInit_DLLs Injection Mechanism' {
            $snippet = @"
`$path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows'
Set-ItemProperty -Path `$path -Name 'AppInit_DLLs' -Type String -Value ''
Set-ItemProperty -Path `$path -Name 'LoadAppInit_DLLs' -Type DWord -Value 0
"@
        }
        'IFEO Accessibility Binary Hijack \(Sticky Keys Backdoor\)' {
            $snippet = @"
`$accessibilityBins = @('sethc.exe','utilman.exe','osk.exe','magnify.exe','narrator.exe','displayswitch.exe')
foreach (`$bin in `$accessibilityBins) {
    `$ifeoKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\`$bin"
    if (Test-Path `$ifeoKey) { Remove-ItemProperty -Path `$ifeoKey -Name 'Debugger' -ErrorAction SilentlyContinue }
}
Write-Warning 'Also run sfc /scannow to verify the accessibility binaries themselves have not been replaced.'
"@
        }
        'Accessibility Binary File Integrity' {
            $snippet = "sfc /scannow`nWrite-Warning 'Treat this endpoint as potentially compromised pending investigation - a replaced accessibility binary indicates a SYSTEM-level backdoor was likely staged at the lock screen.'"
        }
        'Common Startup Folder ACL' {
            $snippet = "Write-Warning 'Tighten the ACL on `"$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp`" via icacls, removing the Everyone/Authenticated Users/Users write grant identified in this finding.'"
        }
        'UAC Auto-Elevation Bypass Indicators' {
            $snippet = @"
Write-Warning 'These keys indicate a possible active compromise. Capture the command value(s) shown in this finding for forensic analysis BEFORE removal.'
`$bypassPaths = @(
    'HKCU:\Software\Classes\ms-settings\Shell\Open\command',
    'HKCU:\Software\Classes\mscfile\shell\open\command',
    'HKCU:\Software\Classes\exefile\shell\runas\command',
    'HKCU:\Software\Classes\Folder\shell\open\command'
)
foreach (`$p in `$bypassPaths) { if (Test-Path `$p) { Remove-Item -Path `$p -Recurse -Force } }
"@
        }
        '^AppLocker Enforcement - (.+)$' {
            $collectionLabel = $Matches[1]
            $typeMap = @{ 'Executable Rules (EXE)' = 'Exe'; 'Windows Installer Rules (MSI)' = 'Msi'; 'Script Rules (PS1/BAT/CMD/VBS/JS)' = 'Script'; 'Packaged App Rules (AppX)' = 'Appx'; 'DLL Rules' = 'Dll' }
            $type = $typeMap[$collectionLabel]
            if (-not $type) { $type = '<Exe|Msi|Script|Appx|Dll>' }
            $snippet = "Write-Warning 'AppLocker enforcement mode changes are not auto-applied - deploying rules blind can break legitimate applications. Define/verify rules for the $type collection, then set enforcement via Local Security Policy (secpol.msc) > Application Control Policies > AppLocker > $type Rules > Properties > Enforce rules, or the equivalent Set-AppLockerPolicy -PolicyObject cmdlet after building/testing a policy object.'"
        }
        '^Writable Directory Within Default-Allowed Windows Path - (.+)$' {
            $dirPath = $Matches[1]
            $snippet = "icacls `"$dirPath`" /remove:g `"Everyone`" `"Authenticated Users`" `"Users`""
        }
        '^Writable \.NET Framework Directory - (.+)$' {
            $dirPath = $Matches[1]
            $snippet = "icacls `"$dirPath`" /remove:g `"Everyone`" `"Authenticated Users`" `"Users`""
        }
        'Overly Permissive AppLocker Path Rules' {
            $snippet = "Write-Warning 'Policy rule changes are not auto-applied. Review the drive-root-level wildcard rule(s) listed in this finding in Local Security Policy > AppLocker, and replace each with a narrower Publisher or Hash rule, or a path rule scoped to a specific non-writable subdirectory.'"
        }
        'Custom AppLocker Path Rule Targeting a Writable Directory' {
            $snippet = "Write-Warning 'Review each custom path rule / writable directory pair listed in this finding. Prefer tightening the directory ACL (icacls) over relaxing the rule; if the directory must remain writable, replace the AppLocker path rule with a Publisher or Hash rule instead.'"
        }
        '^LOLBAS Exposure - (.+)$' {
            $binName = $Matches[1]
            $snippet = "Write-Warning 'AppLocker Deny rules are not auto-applied to avoid breaking legitimate use of $binName in this environment (e.g. developer workstations for csc.exe/msbuild.exe). Add a Deny rule scoped to $binName - or to a Hash/Publisher condition for it - via Local Security Policy > AppLocker > Executable Rules > Create New Rule, restricted appropriately for accounts that do not have a legitimate need for it.'"
        }
        'AppIDSvc Service State' {
            $snippet = 'Set-Service -Name AppIDSvc -StartupType Manual'
        }
        '^AppLocker Policy Registry Key ACL - (.+)$' {
            $keyPath = $Matches[1]
            $snippet = "Write-Warning 'Registry ACL changes are not auto-applied to avoid corrupting other inherited permissions. Restore default permissions on $keyPath via regedit (right-click > Permissions > Advanced) or a change-controlled Set-Acl script, removing the Everyone/Authenticated Users/Users grant.'"
        }
        '^AppLocker Event Log Channel - (.+)$' {
            $channelName = $Matches[1]
            $snippet = "wevtutil sl `"$channelName`" /e:true"
        }
        'Primary Refresh Token \(PRT\) & TPM Binding' {
            $snippet = "Write-Warning 'PRT/device-key TPM binding cannot be forced via script - it depends on TPM availability at initial Entra ID join. Verify the TPM is present/ready (see the TPM finding), then re-register the device: dsregcmd /leave, followed by re-joining Entra ID so a new, hardware-bound device key is issued.'"
        }
        '^MDM Policy Registry Key ACL - (.+)$' {
            $keyPath = $Matches[1]
            $snippet = "Write-Warning 'Registry ACL changes are not auto-applied to avoid corrupting other inherited permissions. Restore default permissions on $keyPath via regedit (right-click > Permissions > Advanced) or a change-controlled Set-Acl script, removing the Everyone/Authenticated Users/Users grant.'"
        }
        'MDM Enrollment Scheduled Task Integrity' {
            $snippet = "Write-Warning 'Do not delete Intune/MDM enrollment tasks blindly - doing so can break device management. Investigate each task listed in this finding; if a target is missing, consider re-triggering enrollment sync (Settings > Accounts > Access work or school > Info > Sync) or re-enrolling the device. If a target is writable, tighten its ACL: icacls `"<target-path>`" /remove:g `"Everyone`" `"Authenticated Users`" `"Users`"'"
        }
        'Volume Shadow Copy Service \(VSS\) State' {
            $snippet = 'Set-Service -Name VSS -StartupType Manual'
        }
        'Windows Recovery Environment \(WinRE\) State' {
            $snippet = 'reagentc /enable'
        }
        'Wi-Fi Profile Security' {
            $snippet = "Write-Warning 'Review the weak-authentication profile(s) listed in this finding, then remove each with: netsh wlan delete profile name=`"<profile-name>`", unless a specific low-risk business reason exists to retain it.'"
        }
        'Auto-Connect to Open/Unvalidated Networks' {
            $snippet = "Write-Warning 'Review the auto-connecting profile(s) listed in this finding, then set each to manual connection: netsh wlan set profileparameter name=`"<profile-name>`" connectionmode=manual'"
        }
        'Wi-Fi Sense / Auto-Connect to Suggested Hotspots' {
            $snippet = @"
`$path = 'HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots'
if (-not (Test-Path `$path)) { New-Item -Path `$path -Force | Out-Null }
Set-ItemProperty -Path `$path -Name 'value' -Type DWord -Value 0
"@
        }
        'Connection Manager - Block Non-Domain Networks \(Dual-Homing Prevention\)' {
            $snippet = @"
`$path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy'
if (-not (Test-Path `$path)) { New-Item -Path `$path -Force | Out-Null }
Set-ItemProperty -Path `$path -Name 'fBlockNonDomain' -Type DWord -Value 1
"@
        }
        '^IPv6 Transition Protocol - (Teredo|6to4|ISATAP)$' {
            $protoName = $Matches[1]
            $cmdName = switch ($protoName) { 'Teredo' { 'teredo' }; '6to4' { '6to4' }; 'ISATAP' { 'isatap' } }
            $snippet = "netsh interface $cmdName set state disabled"
        }
        'PSReadLine Command History Credential Leakage' {
            $snippet = "Write-Warning 'Review each flagged history file listed in this finding, remove the offending lines or clear the file, and rotate any credentials that were exposed. Example (clears the current user''s history - confirm the correct file/profile first): Remove-Item (Get-PSReadLineOption).HistorySavePath -Force'"
        }
        'Third-Party Deployment Agent Secret Files' {
            $snippet = "Write-Warning 'Do not delete deployment logs blindly - they may be needed for troubleshooting/compliance. Review each file listed in this finding for a genuine embedded credential, rotate any exposed credential immediately, then redact/purge the offending file or configure the source tool to stop logging secrets in plaintext.'"
        }
        'DMA Lock-Screen Policy \(Disable New DMA Devices When Locked\)' {
            $snippet = @"
`$path = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE'
if (-not (Test-Path `$path)) { New-Item -Path `$path -Force | Out-Null }
Set-ItemProperty -Path `$path -Name 'DisableExternalDMAUnderLock' -Type DWord -Value 1
"@
        }
        'Diagnostic Data Collection Level \(AllowTelemetry\)' {
            $snippet = @"
`$path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
if (-not (Test-Path `$path)) { New-Item -Path `$path -Force | Out-Null }
Set-ItemProperty -Path `$path -Name 'AllowTelemetry' -Type DWord -Value 1
"@
        }
        'Windows Recall Snapshot Storage Location' {
            $snippet = "Write-Warning 'Tighten the ACL on the snapshot storage directory identified in this finding via icacls, removing the Everyone/Authenticated Users/Users write grant, so Recall snapshot content is not readable by other standard users.'"
        }
        'Controlled Folder Access \(Ransomware Protection\)' {
            $snippet = 'Set-MpPreference -EnableControlledFolderAccess Enabled'
        }
        'Network Protection' {
            $snippet = 'Set-MpPreference -EnableNetworkProtection Enabled'
        }
        'Defender Exclusions - Overly Broad Path Exclusions' {
            $snippet = "Write-Warning 'Review each overly broad exclusion listed in this finding, then remove it: Remove-MpPreference -ExclusionPath `"<path>`". Removing an exclusion blindly via script is not attempted here since it could reintroduce a legitimate, needed performance/compatibility workaround - verify first.'"
        }
        'Custom SMB Share Permissions' {
            $snippet = "Write-Warning 'Review each insecure share listed in this finding, then tighten it: Revoke-SmbShareAccess -Name `"<share>`" -AccountName `"Everyone`" -Force, and grant access only to the specific groups that need it via Grant-SmbShareAccess. Also review the underlying NTFS folder ACL.'"
        }
        'Firewall Rules - High-Risk Ports Open to Any Remote Address' {
            $snippet = "Write-Warning 'Review each rule listed in this finding, then scope its remote address: Set-NetFirewallRule -DisplayName `"<rule-name>`" -RemoteAddress <management-subnet-CIDR>, or disable it if the exposure was unintentional.'"
        }
        'RDP Security Layer \(SSL/TLS Enforcement\)' {
            $snippet = "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'SecurityLayer' -Type DWord -Value 2"
        }
        'RDP Minimum Encryption Level' {
            $snippet = "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'MinEncryptionLevel' -Type DWord -Value 3"
        }
        'Structured Exception Handling Overwrite Protection \(SEHOP\)' {
            $snippet = "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel' -Name 'DisableExceptionChainValidation' -Type DWord -Value 0`nWrite-Warning 'A reboot is required for this change to take effect.'"
        }
        'Print Spooler RPC Authentication Level \(Privacy\)' {
            $snippet = "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Print' -Name 'RpcAuthnLevelPrivacyEnabled' -Type DWord -Value 1"
        }
        '^Firewall Logging - (\w+) Profile \(Blocked Connections\)$' {
            $profileName = $Matches[1]
            $snippet = "Set-NetFirewallProfile -Profile $profileName -LogBlocked True"
        }
        'LSASS Crash Dump \(WER\) Exposure' {
            $snippet = @"
Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps\lsass.exe' -Name 'DumpType' -ErrorAction SilentlyContinue
Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps' -Name 'DumpType' -ErrorAction SilentlyContinue
"@
        }
        'Safe DLL Search Mode' {
            $snippet = "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name 'SafeDllSearchMode' -Type DWord -Value 1"
        }
        'Kernel Driver Signature Enforcement \(BCD nointegritychecks\)' {
            $snippet = "bcdedit /set nointegritychecks off`nWrite-Warning 'A reboot is required for this change to take effect. Treat this endpoint as potentially compromised pending investigation - this flag has no legitimate production use case.'"
        }
        'Network Discovery \(SSDP/Function Discovery\) on Public Profile' {
            $snippet = "Set-NetFirewallRule -DisplayGroup 'Network Discovery' -Profile Public -Enabled False"
        }
        default {
            $snippet = $null
        }
    }

    return $snippet
}

function New-RemediationScript {
    <#
        Generates the companion Remediate-EndpointPostureCheck.ps1 script: one commented,
        modular remediation block per FAIL finding from the current audit run.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$OutputPath)

    $failFindings = @($Script:AuditResults | Where-Object { $_.Status -eq 'FAIL' } | Sort-Object -Property @{Expression = {
        switch ($_.Severity) { 'Critical' { 0 }; 'High' { 1 }; 'Medium' { 2 }; 'Low' { 3 }; default { 4 } }
    }}, Category)

    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine('#Requires -Version 5.1')
    [void]$sb.AppendLine('#Requires -RunAsAdministrator')
    [void]$sb.AppendLine('<#')
    [void]$sb.AppendLine('.SYNOPSIS')
    [void]$sb.AppendLine('    Remediate-EndpointPostureCheck - companion remediation script auto-generated by')
    [void]$sb.AppendLine('    Invoke-EndpointPostureCheck.ps1.')
    [void]$sb.AppendLine('.DESCRIPTION')
    [void]$sb.AppendLine("    Generated on $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') for host $Script:ComputerName.")
    [void]$sb.AppendLine("    Contains one modular, commented remediation block per FAIL finding identified during")
    [void]$sb.AppendLine("    the audit run ($($failFindings.Count) finding(s)). Review every block BEFORE executing -")
    [void]$sb.AppendLine('    some actions (disabling RDP, changing Schannel protocols, enforcing SMB signing) can')
    [void]$sb.AppendLine('    affect connectivity or compatibility with legacy systems and should be change-controlled.')
    [void]$sb.AppendLine('.NOTES')
    [void]$sb.AppendLine('    Run block-by-block or section-by-section in a test/pilot ring before broad deployment.')
    [void]$sb.AppendLine('    Blocks marked "MANUAL ACTION REQUIRED" cannot be safely automated (e.g. firmware/UEFI')
    [void]$sb.AppendLine('    settings, WDAC/AppLocker policy authoring) and are provided as guidance only.')
    [void]$sb.AppendLine('#>')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('[CmdletBinding(SupportsShouldProcess = $true)]')
    [void]$sb.AppendLine('param(')
    [void]$sb.AppendLine('    # Run with -WhatIf to preview actions without applying them.')
    [void]$sb.AppendLine('    [switch]$Force')
    [void]$sb.AppendLine(')')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('if (-not $Force -and -not $PSCmdlet.ShouldProcess("this endpoint", "Apply EndpointPostureCheck remediation")) {')
    [void]$sb.AppendLine('    Write-Host "Running in preview mode. Re-run with -Force to apply changes, or use -WhatIf to simulate." -ForegroundColor Yellow')
    [void]$sb.AppendLine('}')
    [void]$sb.AppendLine('')

    if ($failFindings.Count -eq 0) {
        [void]$sb.AppendLine('Write-Host "No FAIL findings were present in the source audit run - nothing to remediate." -ForegroundColor Green')
    } else {
        $groupedByCategory = $failFindings | Group-Object -Property Category
        foreach ($group in $groupedByCategory) {
            [void]$sb.AppendLine('#' + ('=' * 78))
            [void]$sb.AppendLine("# CATEGORY: $($group.Name)")
            [void]$sb.AppendLine('#' + ('=' * 78))
            [void]$sb.AppendLine('')

            foreach ($finding in $group.Group) {
                [void]$sb.AppendLine('# ' + ('-' * 74))
                [void]$sb.AppendLine("# Control      : $($finding.Control)")
                [void]$sb.AppendLine("# Severity     : $($finding.Severity)")
                [void]$sb.AppendLine("# Current      : $($finding.CurrentValue)")
                [void]$sb.AppendLine("# Expected     : $($finding.RecommendedValue)")
                [void]$sb.AppendLine("# CIS          : $($finding.CIS_Control)")
                [void]$sb.AppendLine("# NIST 800-53  : $($finding.NIST_Control)")
                [void]$sb.AppendLine("# MITRE ATT&CK : $($finding.MITRE_Technique)")
                [void]$sb.AppendLine("# Guidance     : $($finding.Recommendation)")
                [void]$sb.AppendLine('# ' + ('-' * 74))

                $snippet = Get-RemediationSnippet -Finding $finding
                if ($snippet) {
                    [void]$sb.AppendLine("if (`$PSCmdlet.ShouldProcess('$($finding.Control -replace "'","''")', 'Remediate')) {")
                    foreach ($line in ($snippet -split "`n")) {
                        [void]$sb.AppendLine('    ' + $line.TrimEnd())
                    }
                    [void]$sb.AppendLine('}')
                } else {
                    [void]$sb.AppendLine("Write-Warning 'MANUAL ACTION REQUIRED for `"$($finding.Control -replace "'","''")`": $($finding.Recommendation -replace "'","''")'" )
                }
                [void]$sb.AppendLine('')
            }
        }
        [void]$sb.AppendLine('Write-Host "Remediation pass complete. Re-run Invoke-EndpointPostureCheck.ps1 to verify improved posture." -ForegroundColor Cyan')
    }

    Set-Content -LiteralPath $OutputPath -Value $sb.ToString() -Encoding UTF8 -Force
}

#endregion

#region ============================== MAIN EXECUTION ==============================

# --- Elevation gate (redundant safety net in addition to #Requires -RunAsAdministrator,
#     in case the script block is dot-sourced or the requires directive is bypassed) ---
if (-not (Test-IsElevated)) {
    Write-Host ''
    Write-Host '=================================================================================' -ForegroundColor Red
    Write-Host '  EndpointPostureCheck requires elevated (Administrator) privileges to run.'      -ForegroundColor Red
    Write-Host '  Please re-launch PowerShell "Run as Administrator" and try again.'               -ForegroundColor Red
    Write-Host '=================================================================================' -ForegroundColor Red
    Write-Host ''
    exit 1
}

Write-Host ''
Write-Host '#################################################################################' -ForegroundColor DarkCyan
Write-Host '##                                                                             ##' -ForegroundColor DarkCyan
Write-Host '##                    E N D P O I N T P O S T U R E C H E C K                   ##' -ForegroundColor Cyan
Write-Host "##          Enterprise Windows 11 Endpoint Security Posture Auditor  v$($Script:ScriptVersion)      ##" -ForegroundColor DarkCyan
Write-Host '##                                                                             ##' -ForegroundColor DarkCyan
Write-Host '#################################################################################' -ForegroundColor DarkCyan
Write-Host "Target Host : $Script:ComputerName" -ForegroundColor Gray
Write-Host "Start Time  : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
Write-Host ''

# --- Resolve output paths ---
$basePath = if ([string]::IsNullOrWhiteSpace($ReportPath)) { (Get-Location).ProviderPath } else { $ReportPath }

$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$defaultHtmlName = "EndpointPostureCheck_${Script:ComputerName}_${timestamp}.html"
$defaultJsonName = "EndpointPostureCheck_${Script:ComputerName}_${timestamp}.json"

if (Test-Path -LiteralPath $basePath -PathType Container) {
    $htmlOutputPath = Join-Path -Path $basePath -ChildPath $defaultHtmlName
    $jsonOutputPath = Join-Path -Path $basePath -ChildPath $defaultJsonName
    $remediationOutputPath = Join-Path -Path $basePath -ChildPath 'Remediate-EndpointPostureCheck.ps1'
} elseif (-not [string]::IsNullOrWhiteSpace($ReportPath)) {
    # Treat as an explicit file path for the HTML report; derive siblings in the same folder.
    $htmlOutputPath = $ReportPath
    $parentDir = Split-Path -Path $ReportPath -Parent
    if ([string]::IsNullOrWhiteSpace($parentDir)) { $parentDir = (Get-Location).ProviderPath }
    if (-not (Test-Path -LiteralPath $parentDir)) { New-Item -Path $parentDir -ItemType Directory -Force | Out-Null }
    $jsonOutputPath = Join-Path -Path $parentDir -ChildPath $defaultJsonName
    $remediationOutputPath = Join-Path -Path $parentDir -ChildPath 'Remediate-EndpointPostureCheck.ps1'
} else {
    $htmlOutputPath = Join-Path -Path $basePath -ChildPath $defaultHtmlName
    $jsonOutputPath = Join-Path -Path $basePath -ChildPath $defaultJsonName
    $remediationOutputPath = Join-Path -Path $basePath -ChildPath 'Remediate-EndpointPostureCheck.ps1'
}

# --- Ordered list of every audit domain check function ---
$auditChecks = @(
    'Test-TPMStatus',
    'Test-SecureBootAndUEFI',
    'Test-DMAProtection',
    'Test-VBSAndHVCI',
    'Test-CredentialGuard',
    'Test-SystemGuard',
    'Test-LSAProtection',
    'Test-BitLocker',
    'Test-DefenderRealTimeProtection',
    'Test-DefenderCloudProtection',
    'Test-DefenderHealthAndSignatures',
    'Test-DefenderTamperAndPUA',
    'Test-MDEOnboarding',
    'Test-ASRRules',
    'Test-ExploitProtection',
    'Test-WDAC',
    'Test-AppLocker',
    'Test-InstallerAndServicePathSecurity',
    'Test-LocalAccounts',
    'Test-LAPS',
    'Test-PasswordAndLockoutPolicy',
    'Test-UAC',
    'Test-Firewall',
    'Test-LegacyProtocols',
    'Test-RDPAndAdminShares',
    'Test-SMBSigningAndEncryption',
    'Test-SchannelProtocols',
    'Test-CipherSuitesAndHashing',
    'Test-PowerShellSecurity',
    'Test-AdvancedAuditPolicy',
    'Test-ProcessCreationLogging',
    'Test-NTLMAndAnonymousAccessHardening',
    'Test-SMBInsecureGuestLogon',
    'Test-RestrictNTLMUsage',
    'Test-UserRightsAssignment',
    'Test-PrivilegedGroupMembership',
    'Test-InteractiveLogonHardening',
    'Test-PrintSpoolerExposure',
    'Test-WinRMHardening',
    'Test-RemoteRegistryService',
    'Test-RemovableMediaControl',
    'Test-SmartScreenAndSmartAppControl',
    'Test-WindowsRecallControl',
    'Test-DeviceIdentityAndJoinState',
    'Test-WindowsUpdateCompliance',
    'Test-TimeSyncIntegrity',
    'Test-EventLogConfiguration',
    'Test-HardwareStackProtection',
    'Test-DNSSecurity',
    'Test-UnquotedServicePathsWritable',
    'Test-ServiceExecutableACLs',
    'Test-ServiceRegistryKeyACLs',
    'Test-WritablePathDirectories',
    'Test-CriticalDirectoryPermissions',
    'Test-LSASSAccessAuditing',
    'Test-WDigestCredentialCaching',
    'Test-PlaintextAutologonCredentials',
    'Test-UnattendedInstallFiles',
    'Test-GPPCachedCredentials',
    'Test-SAMSystemHiveProtection',
    'Test-LSASecurityPackages',
    'Test-DangerousPrivilegeAssignments',
    'Test-COMCLSIDHijacking',
    'Test-OrphanedPrivilegedScheduledTasks',
    'Test-UACInstallerDetection',
    'Test-VulnerableDriverProtections',
    'Test-RegistryAutorunPersistence',
    'Test-IFEODebuggerHijacks',
    'Test-AccessibilityBinaryIntegrity',
    'Test-StartupFolderPermissions',
    'Test-WMIEventSubscriptionPersistence',
    'Test-EventLogChannelACLTampering',
    'Test-UACBypassIndicators',
    'Test-AppLockerEnforcementModeDeep',
    'Test-AppLockerRuleScopeCoverage',
    'Test-AppLockerWritableSystemDirectories',
    'Test-AppLockerDotNetFrameworkWritablePaths',
    'Test-AppLockerPathRuleOverPermissiveness',
    'Test-AppLockerLOLBASExposure',
    'Test-AppLockerPublisherRuleOverTrust',
    'Test-AppLockerServiceIntegrity',
    'Test-AppLockerPolicyRegistryKeyACLs',
    'Test-AppLockerEventLogTelemetry',
    'Test-PRTTpmBinding',
    'Test-SeamlessSSOAndKerberosCloudTGT',
    'Test-WHfBTpmEnforcement',
    'Test-MDMPolicyRegistryACL',
    'Test-MDMScheduledTaskIntegrity',
    'Test-VSSServiceAndPermissions',
    'Test-ShadowStorageAllocation',
    'Test-WinREStatus',
    'Test-SystemRestoreConfiguration',
    'Test-WifiProfileSecurity',
    'Test-ConnectionManagerDualHoming',
    'Test-Wired8021XEnforcement',
    'Test-IPv6TransitionProtocols',
    'Test-WSLConfiguration',
    'Test-WSLMDESensorIntegration',
    'Test-WindowsSandboxConfiguration',
    'Test-WindowsDefenderApplicationGuard',
    'Test-HyperVVirtualSwitchSecurity',
    'Test-ExportablePrivateKeyCertificates',
    'Test-DeveloperSecretFileExposure',
    'Test-ThirdPartyAgentSecretExposure',
    'Test-CredentialManagerStoredCredentials',
    'Test-ThunderboltDMALockScreenPolicy',
    'Test-BluetoothSecurity',
    'Test-WindowsCopilotPolicy',
    'Test-WindowsRecallSecurityControls',
    'Test-TelemetryLevel',
    'Test-ControlledFolderAccess',
    'Test-DefenderNetworkProtection',
    'Test-DefenderExclusions',
    'Test-SMBShareSecurity',
    'Test-FirewallRuleBroadAllowRules',
    'Test-RDPSecurityLayerAndTLS',
    'Test-PasswordNeverExpiresAccounts',
    'Test-RemoteDesktopUsersGroupMembership',
    'Test-SEHOPMitigation',
    'Test-PrintSpoolerRPCHardening',
    'Test-BitLockerEncryptionType',
    'Test-BitLockerAutoUnlockExposure',
    'Test-SecureBootCertificateStatus',
    'Test-USBDeviceConnectionHistory',
    'Test-FirewallLoggingConfiguration',
    'Test-FirewallInboundActiveRulesInventory',
    'Test-HostsFileIntegrity',
    'Test-LSASSCrashDumpExposure',
    'Test-CredentialGuardUEFILock',
    'Test-SafeDllSearchMode',
    'Test-KernelDriverSignatureBypass',
    'Test-CPUSpeculativeExecutionMitigationOverride',
    'Test-NetworkDiscoveryPublicProfileExposure',
    'Test-OneDriveKnownFolderMove',
    'Test-SysmonPresence',
    'Test-CameraMicrophonePrivacyPolicy',
    'Test-LocalUserAndAdminInventory',
    'Test-CachedUserProfileInventory',
    'Test-NetworkAdapterInventory',
    'Test-InstalledApplicationInventory',
    'Test-ScreensaverLockPolicy',
    'Test-DiskSpaceUtilization',
    'Test-RDPSessionAndRedirectionSettings',
    'Test-InstalledDriverInventory',
    'Test-SystemHardwareInventory',
    'Test-WindowsUpdateSettingsDeep'
)

$totalChecks = $auditChecks.Count
$currentCheck = 0

foreach ($checkName in $auditChecks) {
    $currentCheck++
    Write-Progress -Activity 'EndpointPostureCheck - Running Audit' -Status $checkName -PercentComplete (($currentCheck / $totalChecks) * 100)
    try {
        & $checkName
    } catch {
        Add-AuditResult -Category 'Audit Engine' -Control $checkName -Status 'WARN' -Severity 'Low' `
            -CurrentValue 'Unhandled exception' -RecommendedValue 'Check completes without error' `
            -Recommendation "An unexpected error interrupted this check and was safely contained by the audit engine: $($_.Exception.Message)"
    }
}
Write-Progress -Activity 'EndpointPostureCheck - Running Audit' -Completed

# --- Scoring & risk ---
$posture = Get-CompliancePosture

Write-Host ''
Write-Host '=================================================================================' -ForegroundColor DarkCyan
Write-Host ' AUDIT SUMMARY' -ForegroundColor Cyan
Write-Host '=================================================================================' -ForegroundColor DarkCyan
Write-Host ("  Compliance Score : {0}%" -f $posture.Score) -ForegroundColor $(if ($posture.Score -ge 80) { 'Green' } elseif ($posture.Score -ge 60) { 'Yellow' } else { 'Red' })
Write-Host ("  Risk Level       : {0}" -f $posture.RiskLevel) -ForegroundColor $(switch ($posture.RiskLevel) { 'LOW' { 'Green' }; 'MEDIUM' { 'Yellow' }; 'HIGH' { 'DarkYellow' }; 'CRITICAL' { 'Red' }; default { 'Gray' } })
Write-Host ("  Total Controls   : {0}" -f $posture.Total) -ForegroundColor Gray
Write-Host ("  PASS / FAIL / WARN / INFO : {0} / {1} / {2} / {3}" -f $posture.PassCount, $posture.FailCount, $posture.WarnCount, $posture.InfoCount) -ForegroundColor Gray
Write-Host ("  Critical Failures: {0}   High-Severity Failures: {1}" -f $posture.CriticalFails, $posture.HighFails) -ForegroundColor Gray
Write-Host '=================================================================================' -ForegroundColor DarkCyan
Write-Host ''

# --- HTML dashboard (always generated) ---
try {
    New-HtmlReport -OutputPath $htmlOutputPath -Posture $posture
    Write-Host "[+] HTML dashboard written to : $htmlOutputPath" -ForegroundColor Green
} catch {
    Write-Host "[!] Failed to write HTML dashboard: $($_.Exception.Message)" -ForegroundColor Red
}

# --- Optional JSON export ---
if ($ExportJson) {
    try {
        Export-JsonReport -OutputPath $jsonOutputPath -Posture $posture
        Write-Host "[+] JSON export written to     : $jsonOutputPath" -ForegroundColor Green
    } catch {
        Write-Host "[!] Failed to write JSON export: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# --- Optional remediation script generation ---
if ($GenerateRemediationScript) {
    try {
        New-RemediationScript -OutputPath $remediationOutputPath
        $failCountForMsg = @($Script:AuditResults | Where-Object { $_.Status -eq 'FAIL' }).Count
        Write-Host "[+] Remediation script written : $remediationOutputPath ($failCountForMsg FAIL finding(s) addressed)" -ForegroundColor Green
    } catch {
        Write-Host "[!] Failed to write remediation script: $($_.Exception.Message)" -ForegroundColor Red
    }
}

Write-Host ''
Write-Host "EndpointPostureCheck completed in $((New-TimeSpan -Start $Script:StartTime -End (Get-Date)).ToString('mm\m\ ss\s'))." -ForegroundColor Cyan
Write-Host ''

#endregion

