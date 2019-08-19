class RegistrySecurityDescriptor < Inspec.resource(1)
  name 'registry_security_descriptor'
  supports platform: 'windows'
  desc 'Represents the security descriptor for a registry key in Windows'
  example "
  # return all user rights associated with registry key
  registry_rights = registry_security_descriptor('HKLM:\\System\\CurrentControlSet\\Control\\SecurePipeServers\\Winreg')
  permitted_sids = ['S-1-5-32-551', 'S-1-5-19']
  permitted_sids.each do |trustee|
    describe registry_rights.permissions[trustee] do
      its(['Delete']) { should cmp 0 }
      its(['ReadControl']) { should cmp 0 }
    end
  end

  # return all user rights associated with registry key and verify if trustee sid(s) exist
  registry_rights = registry_security_descriptor('HKLM:\\System\\CurrentControlSet\\Control\\SecurePipeServers\\Winreg')
  describe registry_rights do
    its('permissions') { should include('S-1-5-32-551', 'S-1-5-19') }
  end

  # return a specific users' rights associated with a registry key
  describe registry_security_descriptor('HKLM:\\System\\CurrentControlSet\\Control\\SecurePipeServers\\Winreg').permissions_for_trustee('S-1-5-19') do
    # Assert the permission associated with the specified registry key
    its(['ReadControl']) { should cmp '0' }
  end

  # return a list of user sid's who have rights associated with a registry key
  describe registry_security_descriptor('HKLM:\\System\\CurrentControlSet\\Control\\SecurePipeServers\\Winreg') do
    # Assert the permission associated with the specified registry key
    its ('trustees_with_any_permission') { should include 'S-1-5-32-546' }
  end
  "

  ACCESS_RIGHTS_BINARY = {
    'Delete' =>                       0b10000000000000000,
    'ReadControl' =>                 0b100000000000000000,
    'WriteDac' =>                   0b1000000000000000000,
    'WriteOwner' =>                0b10000000000000000000,
    'AccessSystemSecurity' => 0b1000000000000000000000000,
    'Synchronize' =>              0b100000000000000000000,
    'KeyAllAccess' =>              0b11110000000000111111,
    'KeyCreateLink' =>                           0b100000,
    'KeyCreateSubKey' =>                            0b100,
    'KeyEnumerateSubKeys' =>                       0b1000,
    'KeyExecute' =>                  0b100000000000011001,
    'KeyNotify' =>                                0b10000,
    'KeyQueryValue' =>                                0b1,
    'KeyRead' =>                     0b100000000000011001,
    'KeySetValue' =>                                 0b10,
    'KeyWow6432Key' =>                       0b1000000000,
    'KeyWow6464Key' =>                        0b100000000,
    'KeyWow64Res' =>                         0b1100000000,
    'KeyWrite' =>                     0b00000000000000110
  }.freeze

  def initialize(path, options = {})
    @path = path
    @trustee_access_mask = nil
  end

  def permissions
    fetch_results
    return nil unless @trustee_access_mask
    results = {}
    @trustee_access_mask.each do |trusteesid, accessmask|
      accessrights = {}
      ACCESS_RIGHTS_BINARY.each do |k,v|
        if accessmask.to_i & v == 0
          accessrights[k] = 0
        else
          accessrights[k] = 1
        end
      end
      results[trusteesid] = accessrights
    end
    results
  end

  def permissions_for_trustee(trustee)
    fetch_results
    return nil unless @trustee_access_mask || trustee
    results = {}
    accessmask = @trustee_access_mask[trustee]
    ACCESS_RIGHTS_BINARY.each do |k,v|
      results[k] = (accessmask.to_i & v == 0) ? 0 : 1
    end
    results
  end

  def trustees_with_any_permission
    fetch_results
    return [] unless @trustee_access_mask
    trustees = []
    @trustee_access_mask.each do |trusteesid, accessmask|
      trustees.push(trusteesid)
    end
    trustees
  end

  private
  def fetch_results
    return if @trustee_access_mask
    sddl = inspec.powershell("(Get-Acl #{@path}).SDDL").stdout.strip.gsub("\r\n","")
    raise "The provided Registry Key '#{@path}' does not have an SDDL associated." if sddl == ""
    @trustee_access_mask = {}
    access_details = inspec.powershell("(Invoke-CimMethod Win32_SecurityDescriptorHelper -MethodName SDDLToWin32SD -Arguments @{ SDDL = '#{sddl}' }).Descriptor.DACL | Select @{Name=\"SID\";Expression={$_.Trustee.SIDString}},AccessMask").stdout.strip.split("\r\n")[2..-1].map { |entry| entry.split }
    access_details.each do |access_detail|
      trusteesid = access_detail[0]
      accessmask = access_detail[1]
      if @trustee_access_mask.key?(trusteesid) && @trustee_access_mask[trusteesid]
        @trustee_access_mask[trusteesid] = (accessmask.to_i + @trustee_access_mask[trusteesid].to_i).to_s
      else
        @trustee_access_mask[trusteesid] = accessmask
      end
    end
  end
end
