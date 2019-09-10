class Plist < Inspec.resource(1)
  name 'plist'
  supports platform: 'darwin'
  desc 'plist files (also known as property files) store data, often user and system settings. The files may be text or binary.'
  example "
  describe plist('/System/Library/CoreServices/SystemVersion.plist') do
    it { should exist }
    its('ProductName') { should eq 'Mac OS X' }
  end
  "

  def initialize(path, opts = {})
    @path = path
    @xpath = opts[:xpath]
    @json_data = nil
    @xml_data = nil
  end

  def to_s
    "plist #{@path}" + (@xpath ? " with xpath: #{@xpath}" : '') 
  end

  def exists?
    if @path =~ /\$HOME/
      expand_home = inspec.command('echo $HOME').stdout.strip
      return inspec.file(@path.gsub('$HOME', expand_home)).exist?
    end
    inspec.file(@path).exist?
  end

  def method_missing(*args) 
    load_json
    required_key = args[0].is_a?(Array) ? args[0].map { |x| x.to_s } : args[0].to_s
    @json_data.dig(*required_key)
  end

  def xpath_value
    raise Inspec::Exceptions::ResourceFailed ':xpath must be specified in options hash to use xpath_value' unless @xpath
    load_xml
    result = @xml_data.xpath(@xpath)
    result.respond_to?(:text) ? result.text : result
  end

  private

  def load_json
    begin
      @json_data ||= JSON.parse(inspec.command("plutil -convert json -o - #{@path}").stdout) 
    rescue => e
      raise Inspec::Exceptions::ResourceFailed, "Failed to read plist data for '#{@path}': #{e.message}"
    end
  end

  def load_xml
    begin
      @xml_data ||= Nokogiri::XML.parse(inspec.command("plutil -convert xml1 -o - #{@path}").stdout)
    rescue => e
      raise Inspec::Exceptions::ResourceFailed, "Failed to read plist data for '#{@path}': #{e.message}"
    end
  end
end
