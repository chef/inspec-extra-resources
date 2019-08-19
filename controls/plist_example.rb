# copyright: 2018, The Authors

title "Examples for the plist resource"

control 'Basic example' do
  describe plist('/System/Library/CoreServices/SystemVersion.plist') do
    it { should exist }
    its('ProductName') { should eq 'Mac OS X' }
  end
end

control 'A non-existent property name should be testable' do
  describe plist('/System/Library/CoreServices/SystemVersion.plist') do
    it { should exist }
    its('PretendProperty') { should_not eq 'Pretend Expected Value' }
  end
end

control 'Version comparison' do
  describe plist('/System/Library/CoreServices/SystemVersion.plist') do
    its('ProductVersion') { should cmp < '10.14.0' }
  end
end

control 'Xpath example' do
  describe plist('/Library/Preferences/com.apple.SoftwareUpdate.plist', xpath: 'name(/plist/dict/key[text()=\'AutomaticCheckEnabled\']/following-sibling::*[1])') do
    its('xpath_value') { should eq 'true' }
  end
end
