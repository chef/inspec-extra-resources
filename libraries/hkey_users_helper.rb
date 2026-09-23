# Helper methods for enumerating loaded interactive user registry hives (section 19)
class HkeyUsersHelper < Inspec.resource(1)
  name 'hkey_users_helper'
  supports platform: 'windows'
  desc 'Helper resource to enumerate loaded interactive HKEY_USERS hives used by CIS section 19 user policy checks.'

  # HKEY_USERS hive paths for interactive, non-local logons.
  def hives
    enumerate[:hives]
  end

  # True when hive enumeration failed, so controls can surface the failure instead of treating it as "no users found".
  def error?
    enumerate[:error]
  end

  private

  def enumerate
    @enumerate ||= begin
      script = <<~'PSSCRIPT'
        $ErrorActionPreference = 'Stop'
        try {
          # Get the machine SID to identify and exclude local user accounts
          $machinePrefix = $null
          $lu = @(Get-LocalUser)
          if ($lu.Count) { $machinePrefix = $lu[0].SID.AccountDomainSid.Value + '-' }

          # Find all user registry hives that are currently loaded and represent interactive logons
          Get-ChildItem 'Registry::HKEY_USERS' | Select-Object -ExpandProperty PSChildName | Where-Object {
            $_ -like 'S-1-5-21-*' -and                                                    # AD/interactive accounts
            $_ -notlike '*_Classes' -and                                                  # exclude _Classes shadow hive
            (Test-Path "Registry::HKEY_USERS\$_\Volatile Environment") -and               # interactive logon only
            ([string]::IsNullOrEmpty($machinePrefix) -or $_ -notlike "$machinePrefix*")   # exclude local accounts
          } | Sort-Object -Unique                                                         # Remove any duplicates
        }
        catch {
          Write-Output 'HKU_ENUMERATION_ERROR'
          exit 1
        }
      PSSCRIPT

      result = inspec.powershell(script)
      error = result.exit_status != 0 || (result.stdout&.include?('HKU_ENUMERATION_ERROR') || false)
      hives = error ? [] : (result.stdout || '').to_s.split(/\r?\n/).map(&:strip).reject(&:empty?).map { |sid| "HKEY_USERS\\#{sid}" }

      { hives: hives, error: error }
    end
  end
end
