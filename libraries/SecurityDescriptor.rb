class SecurityDescriptor < Inspec.resource(1)
  name 'security_descriptor'
  supports supports platform: 'windows'
  desc 'Represents the security descriptor for a file in Windows'
  example "
  describe security_descriptor('C:\\windows\\system32\\EventVwr.exe') do
    # Assert the set of entities with a given permission
    its('ReadAndExecute') { should_not include 'S-1-5-32-546' }
    # Assert the permissions for a given entity
    its('S-1-5-32-544') { should_not include 'Write' }
  end
  "

  def initialize(filename, options = {})
    @filename = filename
    @results = nil
  end

  %w{Read ReadAndExecute Write Modify Sychronize FullControl}.each do |perm|
    define_method perm do
      fetch_results unless @results
      # Return keys that have this permission, with the domain stripped
      @results.select { |k,v| v.include?(perm) }.keys.map { |key| key.split("\\")[-1] }
    end
  end

  def method_missing(name)
    fetch_results unless @results
    # Return the results for this entity if it exists (with some domain name) in the result set
    entity_key = @results.keys.select { |key| key.split("\\")[-1] == name.to_s }[0]
    return @results[entity_key] if entity_key
    # Entity not in the result set is "no permissions"
    []
  end

  def to_s
    "Security Descriptor for #{@filename}"
  end

  private

  def fetch_results
    @results = {}
    cmd = inspec.powershell("Get-Acl #{@filename} | select -expand access")
    raise cmd.stderr.strip unless cmd.stderr == ''
    access_details = cmd.stdout.strip.split("\r\n\r\n").map { |entry| entry.split("\r\n") }
    access_details.each do |access_detail|
      entity = access_detail.select { |a| a =~ %r{^IdentityReference} }[0].tr(' ', '').split(':')[-1]
      permissions = access_detail.select { |a| a =~ %r{^FileSystemRights} }[0].tr(' ', '').split(':')[-1].split(',')
      # Get-Acl displays entity names in its results rather than SIDs.
      # It is preferable to work with SIDs when testing security
      # Replace the entity name from Get-Acl with a SID where possible.
      entity_id = get_sid(entity.split("\\")[-1])
      @results[entity_id] = permissions
    end
  end

  def get_sid(entity_name)
    group_sids = inspec.command("wmic group where 'Name=\"#{entity_name}\"' get Name\",\"SID /format:csv").stdout.strip.split("\r\n\r\n")[1..-1].map { |entry| entry.split(',') }
    return group_sids[0][2] unless group_sids.empty?
    user_sids = inspec.command("wmic useraccount where 'Name=\"#{entity_name}\"' get Name\",\"SID /format:csv").stdout.strip.split("\r\n\r\n")[1..-1].map { |entry| entry.split(',') }
    return user_sids[0][2] unless user_sids.empty?
    entity_name
  end
end
