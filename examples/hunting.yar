/*
   Example hunting rules for kira-scan --yara (they run unchanged in YARA itself).
   They look for capabilities, not for specific malware, so expect them to fire on legitimate tools too.
*/
import "pe"

rule LOLBin_AppV_Injector
{
    meta:
        description = "signed App-V injector, loads a DLL into any process (T1218.013)"
        score = 20
    strings:
        $switch = "/INJECTRUNNING" wide
        $name = "Application Virtualization Injector" wide
    condition:
        uint16(0) == 0x5A4D and all of them
        and pe.imports(/^(kernel32|api-ms-win-core-processthreads-l1-1-\d)\.dll$/i, /^CreateRemoteThread$/)
}

rule Writable_Code_Section
{
    meta:
        description = "a section that is both writable and executable: self-modifying code or an unpacking stub"
        score = 25
    condition:
        pe.is_pe and for any s in pe.sections : (
            s.characteristics & pe.SECTION_MEM_EXECUTE and s.characteristics & pe.SECTION_MEM_WRITE
        )
}

rule PowerShell_Download_Cradle
{
    meta:
        description = "PowerShell that downloads code and runs it in memory"
        score = 60
    strings:
        $dl1 = "DownloadString" nocase ascii wide
        $dl2 = "DownloadData" nocase ascii wide
        $dl3 = "Invoke-WebRequest" nocase ascii wide
        $dl4 = /\biwr\s+-?u/ nocase
        $run1 = "Invoke-Expression" nocase ascii wide
        $run2 = /\biex\s*[(\s]/ nocase
        $run3 = "[Reflection.Assembly]::Load" nocase ascii wide
        $b64 = /-e(nc(odedcommand)?)?\s+[A-Za-z0-9+\/]{40,}/ nocase
    condition:
        filesize < 2MB and (any of ($dl*) and any of ($run*) or $b64)
}
