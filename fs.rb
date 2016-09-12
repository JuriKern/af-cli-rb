require "pathname"
require "openssl"

class FS < Struct.new(:path)
  attr_accessor :file_path, :file_source, :file_encrypted, :file_state, :file_ext_name

  FILE_STATE_OPENED    = 1
  FILE_STATE_ENCRYPTED = 2
  FILE_STATE_DECRYPTED = 3
  FILE_STATE_COMMITED  = 4

  def open
    if path.nil? || path.empty?
      return false
    end

    self.file_path = File.expand_path(path)

    if !File.file?(file_path)
      return false
    end

    File.open(file_path, "r") do |f|
      f.flock(File::LOCK_SH)
      self.file_source = f.read
      f.close
    end

    self.file_state = FILE_STATE_OPENED

    true
  end

  def encrypt(pass_phrase, salt)
    if file_state != FILE_STATE_OPENED
      return false
    end

    if File.extname(file_path) == file_ext_name
      return false
    end

    encryptor = OpenSSL::Cipher.new("AES-256-CBC")
    encryptor.encrypt
    encryptor.pkcs5_keyivgen(pass_phrase, salt)

    self.file_source = encryptor.update(file_source)
    self.file_source << encryptor.final

    self.file_state = FILE_STATE_ENCRYPTED

    true
  end

  def decrypt(pass_phrase, salt)
    if file_state != FILE_STATE_OPENED
      return false
    end

    if File.extname(file_path) != file_ext_name
      return false
    end

    decryptor = OpenSSL::Cipher.new('AES-256-CBC')
    decryptor.decrypt
    decryptor.pkcs5_keyivgen(pass_phrase, salt)

    self.file_source = decryptor.update(file_source)
    self.file_source << decryptor.final

    self.file_state = FILE_STATE_DECRYPTED

    true
  end

  def commit
    File.open(file_path, File::RDWR, 0644) do |f|
      f.flock(File::LOCK_EX)
      f.rewind
      f.write(file_source)
      f.flush
      f.truncate(f.pos)
      f.close
    end

    case file_state
    when FILE_STATE_ENCRYPTED
      File.rename(file_path, "#{file_path}#{file_ext_name}")
    when FILE_STATE_DECRYPTED
      File.rename(file_path, File.join(
        File.dirname(file_path),
        File.basename(file_path, File.extname(file_path))
      ))
    end

    self.file_state = FILE_STATE_COMMITED

    true
  end
end

fs = FS.new("~/test-af.txt")
fs.file_ext_name = ".crypted"
if fs.open &&
  fs.encrypt("secretpassphrase", "saltsalt") &&
  fs.commit

  puts "OK, I'm encrypted"
  puts fs.file_source
end

fs = FS.new("~/test-af.txt.crypted")
fs.file_ext_name = ".crypted"
if fs.open &&
  fs.decrypt("secretpassphrase", "saltsalt") &&
  fs.commit

  puts "OK, I'm decrypted"
  puts fs.file_source
end
