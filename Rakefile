require 'rake/testtask'

Rake::TestTask.new(:test) { |t| t.libs << 'lib' << 'test'; t.pattern = 'test/**/*_test.rb' }
task default: :test
