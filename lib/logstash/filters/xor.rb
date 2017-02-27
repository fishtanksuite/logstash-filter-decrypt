# encoding: utf-8
class Xor < Cipher

  def decrypt(data, key)
    data.length.times { |e|
      data[e] = (key[e % key.length].ord ^ data[e].ord).chr;
    }
    return data
  end

  #Decrypt Payload and match it against Keywords
  def xordecrypt
    return match(@payload,@prefix,@keys,@keywords)
  end

end