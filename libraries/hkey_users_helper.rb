# Enumerates the loaded interactive-user registry hives (HKEY_USERS) that CIS
# "section 19" user policy checks must audit.
#
# The hive selection uses exactly the same procedure as the CIS reference SCE
# script (Microsoft/UserHiveAudit.ps1): logon sessions are enumerated through the
# LSA APIs (LsaEnumerateLogonSessions / LsaGetLogonSessionData) and filtered by
# logon-session type so only genuine interactive logons are considered. This is
# authoritative and matches CIS-CAT Assessor, unlike a "Volatile Environment"
# heuristic. Results are cached briefly to avoid re-running the enumeration for
# every section 19 control.
class HkeyUsersHelper < Inspec.resource(1)
  name 'hkey_users_helper'
  supports platform: 'windows'
  desc 'Enumerates loaded interactive HKEY_USERS hives (via LSA logon sessions) for CIS section 19 user policy checks.'
  example "
    describe hkey_users_helper do
      its('error?') { should eq false }
    end
  "

  # @param opts [Hash] :include_local_accounts and :include_entra_id_accounts
  #   mirror the ARGS switches of UserHiveAudit.ps1. Both default to false, which
  #   matches the default CIS behaviour of auditing Active Directory accounts only.
  def initialize(opts = {})
    opts ||= {}
    @include_local_accounts = opts.fetch(:include_local_accounts, false) ? true : false
    @include_entra_id_accounts = opts.fetch(:include_entra_id_accounts, false) ? true : false
  end

  # HKEY_USERS hive paths (e.g. "HKEY_USERS\\S-1-5-21-...") for interactive logons.
  def hives
    enumerate[:hives]
  end

  # True when hive enumeration failed, so controls can surface the failure instead
  # of treating it as "no users found" and passing by accident.
  def error?
    enumerate[:error]
  end

  private

  def enumerate
    @enumerate ||= begin
      result = inspec.powershell(ps_switches + PS_ENUMERATION_SCRIPT)
      error = result.exit_status != 0 || (result.stdout&.include?('HKU_ENUMERATION_ERROR') || false)
      hives = error ? [] : (result.stdout || '').to_s.split(/\r?\n/).map(&:strip).reject(&:empty?).map { |sid| "HKEY_USERS\\#{sid}" }

      { hives: hives, error: error }
    end
  end

  def ps_switches
    "$IncludeLocalAccounts = #{@include_local_accounts ? '$true' : '$false'}\n" \
      "$IncludeEntraIdAccounts = #{@include_entra_id_accounts ? '$true' : '$false'}\n"
  end

  PS_ENUMERATION_SCRIPT = <<~'PSSCRIPT'
    $ErrorActionPreference = 'Stop'
    try {
      # The SIDs of local accounts begin with the machine SID; capture it so those
      # accounts can be excluded. On systems without a local SAM (e.g. domain
      # controllers) there is no machine SID and local-account filtering is skipped.
      $machineSid_ = $null
      try {
        $lu = @(Get-LocalUser -ErrorAction SilentlyContinue)
        if ($lu.Count -gt 0 -and $lu[0].SID) { $machineSid_ = $lu[0].SID.AccountDomainSid.Value + '-' }
      } catch { $machineSid_ = $null }

      function IsLocalUserAccount([string] $userSid) {
        if ([string]::IsNullOrEmpty($machineSid_)) { return $false }
        if ($userSid.Length -lt $machineSid_.Length) { return $false }
        return ($machineSid_ -eq $userSid.Substring(0, $machineSid_.Length))
      }

      # LSA logon-session interop (from CIS UserHiveAudit.ps1, authored by Aaron Margosis, Tanium)
      Add-Type -TypeDefinition @'
      public enum SECURITY_LOGON_TYPE {
          UndefinedLogonType = 0,
          Interactive = 2,
          Network,
          Batch,
          Service,
          Proxy,
          Unlock,
          NetworkCleartext,
          NewCredentials,
          RemoteInteractive,
          CachedInteractive,
          CachedRemoteInteractive,
          CachedUnlock,
      }

      [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
      public struct LUID {
          public int LowPart;
          public int HighPart;
      }

      [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
      public struct Anonymous_b4d9893f_84b2_4c09_b43e_a6bcbb785d60 {
          public int LowPart;
          public int HighPart;
      }

      [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
      public struct Anonymous_91b81ffc_5d42_450d_a9f8_fdb76b505fb9 {
          public int LowPart;
          public int HighPart;
      }

      [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Explicit)]
      public struct LARGE_INTEGER {
          [System.Runtime.InteropServices.FieldOffsetAttribute(0)]
          public Anonymous_b4d9893f_84b2_4c09_b43e_a6bcbb785d60 DUMMYSTRUCTNAME;
          [System.Runtime.InteropServices.FieldOffsetAttribute(0)]
          public Anonymous_91b81ffc_5d42_450d_a9f8_fdb76b505fb9 u;
          [System.Runtime.InteropServices.FieldOffsetAttribute(0)]
          public long QuadPart;
      }

      [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
      public struct LSA_UNICODE_STRING {
          public short Length;
          public short MaximumLength;
          [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.LPWStr)]
          public string Buffer;
      }

      [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
      public struct LSA_LAST_INTER_LOGON_INFO {
          public LARGE_INTEGER LastSuccessfulLogon;
          public LARGE_INTEGER LastFailedLogon;
          public int FailedAttemptCountSinceLastSuccessfulLogon;
      }

      [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
      public struct SECURITY_LOGON_SESSION_DATA {
          public int Size;
          public LUID LogonId;
          public LSA_UNICODE_STRING UserName;
          public LSA_UNICODE_STRING LogonDomain;
          public LSA_UNICODE_STRING AuthenticationPackage;
          public int LogonType;
          public int Session;
          public System.IntPtr Sid;
          public LARGE_INTEGER LogonTime;
          public LSA_UNICODE_STRING LogonServer;
          public LSA_UNICODE_STRING DnsDomainName;
          public LSA_UNICODE_STRING Upn;
          public int UserFlags;
          public LSA_LAST_INTER_LOGON_INFO LastLogonInfo;
          public LSA_UNICODE_STRING LogonScript;
          public LSA_UNICODE_STRING ProfilePath;
          public LSA_UNICODE_STRING HomeDirectory;
          public LSA_UNICODE_STRING HomeDirectoryDrive;
          public LARGE_INTEGER LogoffTime;
          public LARGE_INTEGER KickOffTime;
          public LARGE_INTEGER PasswordLastSet;
          public LARGE_INTEGER PasswordCanChange;
          public LARGE_INTEGER PasswordMustChange;
      }

      public partial class NativeMethods {
          [System.Runtime.InteropServices.DllImportAttribute(
              "Secur32.dll",
              EntryPoint="LsaEnumerateLogonSessions",
              CallingConvention=System.Runtime.InteropServices.CallingConvention.StdCall)]
          public static extern int LsaEnumerateLogonSessions(
              ref int LogonSessionCount,
              ref System.IntPtr LogonSessionList) ;

          [System.Runtime.InteropServices.DllImportAttribute(
              "Secur32.dll",
              EntryPoint="LsaGetLogonSessionData",
              CallingConvention=System.Runtime.InteropServices.CallingConvention.StdCall)]
          public static extern int LsaGetLogonSessionData(
              ref LUID LogonId,
              ref System.IntPtr ppLogonSessionData) ;

          [System.Runtime.InteropServices.DllImportAttribute(
              "Secur32.dll",
              EntryPoint="LsaFreeReturnBuffer",
              CallingConvention=System.Runtime.InteropServices.CallingConvention.StdCall)]
          public static extern int LsaFreeReturnBuffer(System.IntPtr Buffer) ;
      }
'@

      # Compatible replacement for [IntPtr]::Add for older PowerShell versions.
      function IntPtrAdd([System.IntPtr] $pointer, [int] $offset) {
        return [System.IntPtr]($pointer.ToInt64() + $offset)
      }

      # Return a PSCustomObject (SID, user name, logon type) for each LSA logon session.
      function GetSelectedLogonSessionData() {
        [uint32] $sessionCount = 0
        [IntPtr] $ppLuids = [IntPtr]::Zero
        $LuidDataSize = [System.Runtime.InteropServices.Marshal]::SizeOf([System.Type][LUID])

        $ret = [NativeMethods]::LsaEnumerateLogonSessions([ref] $sessionCount, [ref] $ppLuids)
        if (0 -ne $ret) {
          Write-Error ("LsaEnumerateLogonSessions failed with NTSTATUS 0x" + $ret.ToString("X8"))
        } else {
          for ($ixSession = 0; $ixSession -lt $sessionCount; $ixSession++) {
            $luidOffset = $LuidDataSize * $ixSession
            $luid = [System.Runtime.InteropServices.Marshal]::PtrToStructure((IntPtrAdd -pointer $ppLuids -offset $luidOffset), [type][LUID])

            [IntPtr]$ppLogonSessionData = [IntPtr]::Zero
            $ret = [NativeMethods]::LsaGetLogonSessionData([ref]$luid, [ref]$ppLogonSessionData)
            if (0 -ne $ret) {
              Write-Error ("LsaGetLogonSessionData failed with NTSTATUS 0x" + $ret.ToString("X8"))
            } else {
              $logonSessionData = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ppLogonSessionData, [type][SECURITY_LOGON_SESSION_DATA])
              if ($logonSessionData.LogonDomain.Buffer.Length -gt 0 -or $logonSessionData.UserName.Buffer.Length -gt 0) {
                $UserName = $logonSessionData.LogonDomain.Buffer + "\" + $logonSessionData.UserName.Buffer
              } else {
                $UserName = [String]::Empty
              }
              $LogonType = [SECURITY_LOGON_TYPE] ($logonSessionData.LogonType)
              if ([IntPtr]::Zero -ne $logonSessionData.Sid) {
                $SID = ([System.Security.Principal.SecurityIdentifier]::new($logonSessionData.Sid)).ToString()
              } else {
                $SID = [string]::Empty
              }

              [PSCustomObject] @{
                UserName = $UserName;
                LogonType = $LogonType;
                SID = $SID
              }

              [void] [NativeMethods]::LsaFreeReturnBuffer($ppLogonSessionData)
            }
          }

          [void] [NativeMethods]::LsaFreeReturnBuffer($ppLuids)
        }
      }

      # Enumerate the SIDs whose HKEY_USERS hive should be inspected.
      function Get-HivesToInspect {
        param(
          [switch] $IncludeLocalAccounts,
          [switch] $IncludeEntraIdAccounts
        )

        # Keep only genuine interactive logon types.
        $sessions = GetSelectedLogonSessionData | Where-Object { $_.LogonType -notin @(
            [SECURITY_LOGON_TYPE]::UndefinedLogonType,
            [SECURITY_LOGON_TYPE]::Network,
            [SECURITY_LOGON_TYPE]::Batch,
            [SECURITY_LOGON_TYPE]::Service,
            [SECURITY_LOGON_TYPE]::Proxy
          ) }

        if ($IncludeEntraIdAccounts) {
          $sessions = $sessions | Where-Object {
            $_.SID.StartsWith("S-1-5-21-") -or   # AD + local accounts
            $_.SID.StartsWith("S-1-12-1-")        # Entra ID accounts
          }
        } else {
          $sessions = $sessions | Where-Object {
            $_.SID.StartsWith("S-1-5-21-")        # AD + local accounts
          }
        }

        if (-not $IncludeLocalAccounts) {
          $sessions = $sessions | Where-Object { -not (IsLocalUserAccount -userSid $_.SID) }
        }

        # Ensure the corresponding HKEY_USERS subkey is actually loaded.
        [void] (New-PSDrive -PSProvider Registry -Name HKU_Script -Root HKEY_USERS -Scope Script)
        $result = $sessions.SID | Sort-Object -Unique | Where-Object { Test-Path -Path "HKU_Script:\$_" }
        Remove-PSDrive HKU_Script

        return $result
      }

      # Cache the hive list briefly so repeated section 19 controls don't re-enumerate.
      function Get-CachedHivesToInspect {
        param(
          [switch] $IncludeLocalAccounts,
          [switch] $IncludeEntraIdAccounts,
          [int] $CacheExpiryMinutes = 3
        )

        # Cache key includes the account filters so results never leak between settings.
        $flags = "L$([int][bool]$IncludeLocalAccounts)E$([int][bool]$IncludeEntraIdAccounts)"
        $cachefilepath = Join-Path $env:TEMP ("CIS_InSpec_UserHiveList_" + $flags + ".txt")

        $bRefreshCache = $true
        $cachefilecontent = $null
        $cachefile = Get-Item $cachefilepath -ErrorAction SilentlyContinue

        if ($null -ne $cachefile -and $cachefile.LastWriteTime.AddMinutes($CacheExpiryMinutes) -ge [DateTime]::Now) {
          $bRefreshCache = $false
          $cachefilecontent = @(Get-Content $cachefilepath -ErrorVariable readerror)
          if ($readerror.Count -gt 0) {
            $bRefreshCache = $true
          } else {
            foreach ($sid in $cachefilecontent) {
              if (-not $sid.StartsWith("S-1-")) { $bRefreshCache = $true }
            }
          }
        }

        if ($bRefreshCache) {
          $cachefilecontent = @( Get-HivesToInspect -IncludeLocalAccounts:$IncludeLocalAccounts -IncludeEntraIdAccounts:$IncludeEntraIdAccounts )
          try {
            $cachefilecontent | Out-File -Encoding ascii -LiteralPath $cachefilepath -Force -ErrorAction SilentlyContinue
          } catch { }
        }

        return $cachefilecontent
      }

      $sids = @( Get-CachedHivesToInspect -IncludeLocalAccounts:$IncludeLocalAccounts -IncludeEntraIdAccounts:$IncludeEntraIdAccounts )
      $sids | ForEach-Object { Write-Output $_ }
    }
    catch {
      Write-Output 'HKU_ENUMERATION_ERROR'
      exit 1
    }
  PSSCRIPT
end
