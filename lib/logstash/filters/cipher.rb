# encoding: utf-8
require 'base64'
require 'uri'
class Cipher
  def initialize(prefix,payload,keys,keywords)
    @prefix=prefix
    @payload=payload
    @keys=keys
    @keywords=keywords
  end

  #Extract according to prefix
  def extract(payload)
    return payload[@prefix.length..@payload.length]
  end

  #Decode Payload and unescape Characters
  def decode(payload)
    return Base64.decode64(URI.unescape(payload))
  end

  def match(payload,prefix,keys,keywords)
    #Match, Payload
    result = [false,'']
      payload = decode(extract(payload))
      keys.each do |key|
        begin
          payload = decrypt(payload, Base64.decode64(key))
          keywords.each do |keyword|
            if payload.include? keyword
              result[0] = true
              result[1] = payload.to_s
              break
            end
          end
        rescue
          return result
        end
      end

      return result
  end

end