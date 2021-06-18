class SecurityIdentifier < Inspec.resource(1)
  name 'security_identifier'
  supports platform: 'windows'
  desc 'Resource that returns a Security Identifier for a given entity name in Windows. Because different entities can have the same name (e.g. a user and group can both be called \'devops\') the resource requires the type of the entity (:user, :group) to be stated to avoid an ambiguous test. If the entity type is unknown (e.g. when working with SCAP content that names an entity but does not declare its type) you may give the type as :unspecified to explicitly state that you need the resource to try to determine a SID when the entity type is not known.'
  example "
    describe security_policy do
      its(\"SeRemoteInteractiveLogonRight\") { should_not include security_identifier(group: 'Guests') }
    end
  "

  def initialize(opts = {})
    supported_opt_keys = [:user, :group, :unspecified]
    raise "Invalid security_identifier param '#{opts}'. Please pass a hash with these supported keys: #{supported_opt_keys}" unless opts.respond_to?(:keys)
    raise "Unsupported security_identifier options '#{opts.keys - supported_opt_keys}'. Supported keys: #[supported_opt_keys]" unless (opts.keys - supported_opt_keys).empty?
    raise 'Specifying more than one of :user :group or :unspecified for security_identifier is not supported' unless opts.keys && ((opts.keys & supported_opt_keys).length == 1)
    if opts[:user]
      @type = :user
      @name = opts[:user]
    end
    if opts[:group]
      @type = :group
      @name = opts[:group]
    end
    if opts[:unspecified]
      @type = :unspecified
      @name = opts[:unspecified]
    end
    raise 'Specify one of :user :group or :unspecified for security_identifier' unless @name
    @sids = nil
  end

  def sid
    fetch_sids unless @sids
    @sids[@name] || @name
  end

  def fetch_sids
    @sids = {}
    case @type
    when :group
      sid_data = wmi_results_array("wmic group where 'Name=\"#{@name}\"' get Name\",\"SID /format:csv")
    when :user
      sid_data = wmi_results_array("wmic useraccount where 'Name=\"#{@name}\"' get Name\",\"SID /format:csv")
    when :unspecified
      # try group first, then user
      sid_data = wmi_results_array("wmic group where 'Name=\"#{@name}\"' get Name\",\"SID /format:csv")
      if sid_data.empty?
        sid_data = wmi_results_array("wmic useraccount where 'Name=\"#{@name}\"' get Name\",\"SID /format:csv")
      end
    else
      raise "Unhandled entity type '#{@type}'"
    end
    sid_data.each { |sid| @sids[sid[1]] = sid[2] }
  end

  def wmi_results_array(query)
    inspec.command(query).stdout.strip.split("\r\n\r\n")[1..-1].map { |entry| entry.split(',') }
  end
end
