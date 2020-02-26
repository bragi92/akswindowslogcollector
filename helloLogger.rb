require 'openssl'


key = OpenSSL::PKey::RSA.new(2048)

puts "Hello World"

puts key