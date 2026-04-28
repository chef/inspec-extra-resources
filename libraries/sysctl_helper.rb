# Helper methods for sysctl parameter checking
class SysctlHelper < Inspec.resource(1)
  name 'sysctl_helper'
  supports platform: 'linux'
  desc 'Helper resource to check sysctl parameters with correct systemd-sysctl precedence.'

  def check_sysctl_parameter(parameter_name, expected_values)
    parameter_regex = parameter_name.gsub('.', '[./]')
    
    # 1. Gather all configs into a map: { "filename" => "full_path" }
    # Processing directories from Lowest to Highest priority allows overwriting (masking)
    # Order: /lib < /usr/lib < /usr/local/lib < /run < /etc
    config_map = {}
    # here we define the sysctl.d directories in order of precedence
    sysctl_dirs = ['/lib/sysctl.d/', '/usr/lib/sysctl.d/', '/usr/local/lib/sysctl.d/', '/run/sysctl.d/', '/etc/sysctl.d/']
    
    # More efficient: Check all directories in one command instead of individual calls
    find_cmd = "sudo find #{sysctl_dirs.join(' ')} -maxdepth 1 -type f -name '*.conf' 2>/dev/null"
    inspec.command(find_cmd).stdout.each_line do |line|
      filepath = line.strip
      next if filepath.empty?
      filename = File.basename(filepath)
      config_map[filename] = filepath
    end

    # 2. Sort filenames lexicographically (systemd execution order)
    sorted_files = config_map.keys.sort.map { |name| config_map[name] }

    # 3. Append /etc/sysctl.conf (Legacy override, processed last)
    # Using sudo to check existence
    if inspec.command("sudo test -f /etc/sysctl.conf").exit_status == 0
      sorted_files << '/etc/sysctl.conf'
    end

    # 4. Check UFW (Highest Precedence - overrides even sysctl)
    ufw_config = nil
    ufw_cmd = inspec.command("sudo grep '^IPT_SYSCTL=' /etc/default/ufw")
    if ufw_cmd.exit_status == 0
       ufw_path = ufw_cmd.stdout.split('=')[1].strip
       if ufw_path && !ufw_path.empty?
         # If UFW defines a custom sysctl file, that file is the absolute authority
         # We add it to the VERY END of our list so it checked last (winning)
         sorted_files << ufw_path
       end
    end

    # 5. Find the winner by checking files in execution order.
    # The LAST file to set the value is the winner.
    winning_file = nil
    winning_value = nil
    all_configs = []
    
    sorted_files.each do |file_path|
      # Use sudo cat to read content to avoid permission issues
      content = inspec.command("sudo cat #{file_path}").stdout
      
      content.each_line do |line|
        # Match parameter definition (ignoring comments handled by regex implementation? No, strict line/comment check is better)
        # Standard regex for "param = value"
        if line.match?(/^\s*#{parameter_regex}\s*=\s*\S+/)
          value = line.match(/^\s*#{parameter_regex}\s*=\s*(\S+)/)[1]
          
          # Capture config entry
          all_configs << { file: file_path, value: value }
          
          # Since we are iterating in Execution Order, the last value seen is the current system state
          winning_file = file_path
          winning_value = value
        end
      end
    end

    # Calculate results
    ufw_entry = all_configs.find { |c| c[:file].include?('ufw') }
    
    {
      winning_file: winning_file,
      winning_value: winning_value,
      all_configs: all_configs,
      expected_values: expected_values,
      ufw_config: ufw_entry,
      # Check if winning file is in a recommended location
      in_recommended_location: winning_file&.match?(%r{^/etc/sysctl\.d/|^/run/sysctl\.d/})
    }
  end
end