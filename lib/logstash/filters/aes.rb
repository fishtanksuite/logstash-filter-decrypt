require 'openssl'
class Aes < Cipher

  def decrypt(data,key)
    aes = OpenSSL::Cipher.new('AES-128-CBC')
    aes.decrypt
    aes.key = key
    return aes.update(data)
  end

  def aesdecrypt
    return match(@payload,@prefix,@keys,@keywords)


  end
end