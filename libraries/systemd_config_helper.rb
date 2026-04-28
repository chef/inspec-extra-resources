# Helper methods for systemd configuration file checking
# Follows CIS benchmark methodology using systemd-analyze cat-config
class SystemdConfigHelper < Inspec.resource(1)
  name 'systemd_config_helper'
  supports platform: 'linux'
  desc 'Helper resource to check systemd configuration parameters with correct systemd drop-in precedence.'

  # Get systemd configuration option value from highest precedence file
  def get_systemd_config_value(conf_file, block_name, option_name)
    # 1. Find systemd-analyze binary location
    systemd_analyze = inspec.command("readlink -e /bin/systemd-analyze || readlink -e /usr/bin/systemd-analyze").stdout.strip

    # 2. Process drop-in configuration files using systemd-analyze cat-config (if available)
    unless systemd_analyze.empty?
      # Get all config file paths from systemd-analyze output
      cat_config_cmd = "#{systemd_analyze} cat-config #{conf_file} 2>/dev/null | tac | grep -Pio '^\\s*#\\s*\\/[^#\\n\\r\\s]+\\.conf\\b'"
      config_files = inspec.command(cat_config_cmd).stdout.lines.map { |line| line.strip.sub(/^#\s*/, '') }.reject(&:empty?)

      # 3. Iterate through config files in precedence order (first match wins)
      config_files.each do |file_path|
        # Extract the [BlockName] section content using awk pattern
        section_content = extract_systemd_section(file_path, block_name)
        
        # Find option line within section (case-insensitive, last occurrence wins within same file)
        option_line = section_content.lines.grep(/^\s*#{Regexp.escape(option_name)}\s*=\s*\S+\b/i).last

        if option_line
          option_value = option_line.split('=', 2)[1]&.strip
          
          # Return immediately on first valid value found (highest precedence)
          if option_value && !option_value.empty?
            return {
              file: file_path,
              value: option_value
            }
          end
        end
      end
    end

    # 4. Fallback to default configuration file if no drop-in configs found
    default_file = "/etc/#{conf_file}"
    
    if inspec.file(default_file).exist?
      # Extract section content from default file
      section_content = extract_systemd_section(default_file, block_name)
      
      # For default file, accept first occurrence including commented lines
      option_line = section_content.lines.grep(/^\s*(#)?\s*#{Regexp.escape(option_name)}\s*=\s*\S+\b/i).first

      if option_line
        # Remove comment marker if present
        cleaned_line = option_line.sub(/^\s*#\s*/, '')
        option_value = cleaned_line.split('=', 2)[1]&.strip

        if option_value && !option_value.empty?
          return {
            file: default_file,
            value: option_value
          }
        end
      end
    end

    # 5. No configuration found - return nil values
    {
      file: nil,
      value: nil
    }
  end

  private

  # Extract content from a specific INI section in a configuration file
  def extract_systemd_section(file_path, block_name)
    content = inspec.file(file_path).content
    return '' if content.nil? || content.empty?

    section_lines = []
    in_target_section = false

    content.each_line do |line|
      # Check if entering target section
      if line.match?(/^\s*\[#{Regexp.escape(block_name)}\]/)
        in_target_section = true
        next
      end

      # Check if entering a different section (exit target section)
      if line.match?(/^\s*\[.+\]/)
        in_target_section = false
        next
      end

      # Collect lines within target section
      section_lines << line if in_target_section
    end

    section_lines.join
  end
end