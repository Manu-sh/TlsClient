#!/usr/bin/ruby

require 'net/https'

ARGV.each do |url|
	uri = URI.parse(url)
	request = Net::HTTP.new(uri.host, uri.port)
	request.use_ssl = true
	request.verify_mode = OpenSSL::SSL::VERIFY_PEER
	puts "#{request.get("/").body}"
end
