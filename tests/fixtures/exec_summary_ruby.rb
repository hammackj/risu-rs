require 'rexml/document'
file = ARGV[0]
doc = REXML::Document.new(File.read(file))

hosts = doc.elements.to_a('//ReportHost')
items = doc.elements.to_a('//ReportItem')

severity = Hash.new(0)
items.each do |ri|
  s = ri.attributes['severity'].to_i
  severity[s] += 1
end

host_counts = Hash.new(0)
hosts.each do |h|
  name = h.attributes['name']
  h.elements.each('ReportItem') do |ri|
    sev = ri.attributes['severity'].to_i
    host_counts[name] += 1 if sev > 0
  end
end
top_hosts = host_counts.sort_by { |_,v| -v }[0,5]

plugin_counts = Hash.new(0)
items.each do |ri|
  sev = ri.attributes['severity'].to_i
  next if sev == 0
  pname = ri.elements['plugin_name']&.text
  plugin_counts[pname] += 1 if pname
end
top_plugins = plugin_counts.sort_by { |_,v| -v }[0,5]

auth = 0; unauth = 0
hosts.each do |h|
  h.elements.each('ReportItem[@pluginID="19506"]') do |ri|
    text = ri.elements['plugin_output']&.text.to_s
    text.split("\n").each do |line|
      key,val = line.split(':',2)
      next unless key && val
      if key.strip.downcase == 'credentialed checks'
        if val.downcase.include?('yes')
          auth += 1
        else
          unauth += 1
        end
      end
    end
  end
end

conf_hosts = []
hosts.each do |h|
  h.elements.each('ReportItem') do |ri|
    pname = ri.elements['plugin_name']&.text
    if pname == 'Conficker Worm Detection (uncredentialed check)'
      conf_hosts << h.attributes['name']
    end
  end
end

puts 'Exec Summary'
puts "## Scan Summary\nHosts: #{hosts.size}\nItems: #{items.size}"
puts "## Severity Breakdown\nCritical: #{severity[4]}\nHigh: #{severity[3]}\nMedium: #{severity[2]}\nLow: #{severity[1]}\nInfo: #{severity[0]}"
puts (["## Top Hosts"] + top_hosts.map { |name, c| "- #{name}: #{c}" }).join("\n")
puts (["## Remediation Summary"] + top_plugins.map { |name, c| "- #{name}: #{c}" }).join("\n")
puts "## Authentication Status\nAuthenticated hosts: #{auth}\nUnauthenticated hosts: #{unauth}"
if conf_hosts.empty?
  puts 'No Conficker infections detected.'
else
  puts (["## Conficker Infections"] + conf_hosts.map { |n| "- #{n}" }).join("\n")
end
