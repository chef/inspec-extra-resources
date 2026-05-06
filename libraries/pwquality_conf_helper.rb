class LastValue < Inspec.resource(1)
  name 'pwquality_conf_helper'
  supports platform: 'linux'
  desc 'Helper resource to check settings in the /etc/security/pwquality.conf configuration file and files in /etc/security/pwquality.conf.d/ directory.'

  # ---------------------------------------
  # Helper: extract last value from a file
  # ---------------------------------------
  def last_value_from_file(path, parameter)
    return nil unless inspec.file(path).exist?

    content = inspec.file(path).content
    return nil if content.nil? || content.empty?

    matches = content.scan(/^\s*#{parameter}\s*=\s*(-?\d+)\b/i)
    return nil if matches.empty?

    matches.flatten.last.to_i
  end

  # ---------------------------------------
  # Helper: extract last value from .d/*.conf
  # last file in canonical order wins
  # ---------------------------------------
  def last_value_from_conf_d(dir_path, parameter)
    return nil unless inspec.directory(dir_path).exist?

    conf_files = inspec.command("ls -1 #{dir_path}/*.conf 2>/dev/null | sort").stdout.split("\n").map(&:strip)
    return nil if conf_files.empty?

    last_val = nil
    conf_files.each do |f|
      v = last_value_from_file(f, parameter)
      last_val = v unless v.nil?
    end

    last_val
  end

  ## helper method to find the effective value of a parameter
  def effective_value(file_val, dir_val)

    effective_value_parameter =
    if !file_val.nil?
      file_val
    else
      dir_val
    end

    effective_value_parameter
  end
end