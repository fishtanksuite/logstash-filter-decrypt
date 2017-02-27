Gem::Specification.new do |s|
  s.name = 'logstash-filter-decrypt'
  s.version = '0.0.2'
  s.licenses = ['Apache License (2.0)']
  s.summary = "Decrypt Filter for XOR Trojan"
  s.description     = "This is a Logstash Filter to be installed on a logstash instance"
  s.authors = ["Silvan Adrian, Fabian Binna"]
  s.email = 'silvan.adrian@gmail.com'
  s.homepage = ""
  s.require_paths = ["lib"]

  # Files
  s.files = Dir['lib/**/*','spec/**/*','vendor/**/*','*.gemspec','*.md','CONTRIBUTORS','Gemfile','LICENSE','NOTICE.TXT']
   # Tests
  s.test_files = s.files.grep(%r{^(test|spec|features)/})

  # Special flag to let us know this is actually a logstash plugin
  s.metadata = { "logstash_plugin" => "true", "logstash_group" => "filter" }

  # Gem dependencies
  s.add_runtime_dependency "logstash-core-plugin-api", "~> 2.0"
  s.add_development_dependency 'logstash-devutils' , '~> 0'
end
