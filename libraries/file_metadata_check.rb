class FileMetadataCheck < Inspec.resource(1)
  name 'file_metadata_check'
  supports platform: 'linux'
  desc 'Helper resource to check file metadata such as permissions, ownership, and group ownership against expected values.'

  def access_failures_for(path:, mode:, owner:, group:, user:, primary_group:, mask:)
    out = []
    max_allowed = (0o777 & ~mask)

    if (mode & mask) != 0
      out << %(  - File: "#{path}" is mode: "#{mode.to_s(8)}" and should be mode: "#{max_allowed.to_s(8)}" or more restrictive)
    end
    if owner != user
      out << %(  - File: "#{path}" owned by: "#{owner}" and should be owned by "#{user}")
    end
    if group != primary_group
      out << %(  - File: "#{path}" group owned by: "#{group}" and should be group owned by "#{primary_group}")
    end
    out
  end

end