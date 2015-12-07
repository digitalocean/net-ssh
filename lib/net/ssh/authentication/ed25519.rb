require 'rbnacl'
require 'rbnacl/libsodium'
require 'rbnacl/signatures/ed25519/verify_key'

# Credit to @mfazekas for the implementation: https://github.com/net-ssh/net-ssh/pull/228
# Note: This is only written to return a fingerprint from a public key.
module ED25519
  class PubKey
    def initialize(data)
      @verify_key = RbNaCl::Signatures::Ed25519::VerifyKey.new(data)
    end

    def self.read_keyblob(buffer)
      PubKey.new(buffer.read_string)
    end

    def to_blob
      Net::SSH::Buffer.from(:string, 'ssh-ed25519', :string, @verify_key.to_bytes).to_s
    end

    def fingerprint
      @fingerprint ||= OpenSSL::Digest::MD5.hexdigest(to_blob).scan(/../).join(':')
    end
  end
end
