#!/bin/env ruby
## caller.rb

require 'net/http'
require 'pry'

BASE = 'http://redpanda.htb:8080/img'

def get(name)
  url = sprintf('%s/%s.jpg', BASE, name)
  uri = URI.parse(url)

  http = Net::HTTP.new(uri.host, uri.port)
  request = Net::HTTP::Get.new(uri.request_uri)

  response = http.request(request)

  response.code.eql?('200')
end

names = File.read('./names-lc.txt').split("\n")

results = Hash.new

puts sprintf('total names[%d]', names.size)

names.each do |n|
  r = get(n)
  if r
    results[n] = true
    puts sprintf('name[%s] found', n)
  end
end


