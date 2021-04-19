# frozen_string_literal: true

require 'hkdf'

class Token
  # The scheme for URI-encoded tokens, set by RFC 8959.
  SCHEME = 'token'

  # The domain associated with these secrets. Changing this will
  # invalidate derived subkeys as it's part of the data included in the
  # HDKF invocation.
  DOMAIN = # insert your authentication domain here

  # The hashing algorithm to use when using HKDF to derive subkeys.
  # Changing this will invalidate derived subkeys.
  ALGORITHM = 'BLAKE2b512'

  # The minimum entropy (in bytes) allowed for cryptographic tokens.
  MINIMUM_ENTROPY = 16 # 128 bits

  # The scheme to use for the URI-encoded token.
  attr_reader :scheme

  # The domain to use for the URI-encoded token.
  attr_reader :domain

  # The context under which this token is valid.
  attr_reader :context

  # Optionally, an associated username or identifier for the token.
  attr_reader :username

  #
  # Returns a randomly-generated secure token with the given bits of
  # `entropy` for a specific `context` and `username`.
  #
  def self.generate(entropy, context, username: nil)
    self.from_bytes(
      SecureRandom.bytes(entropy),
      context,
      username: username,
    )
  end

  #
  # Returns a regex to match tokens of the given entropy and either any
  # supported `context` or a speficic, fixed `context`.
  #
  def self.regexp(entropy, context = nil, scheme: SCHEME, domain: DOMAIN)
    %r{
      \A
      (?<scheme>   #{Regexp.escape(scheme)} ) ://
      (?<username> [a-zA-Z0-9\-_.@]* ) :
      (?<token>    [a-f0-9]{#{Regexp.escape((entropy * 2).to_s)}} ) @
      (?<domain>   #{Regexp.escape(domain)} ) /
      (?<context>  #{context ? Regexp.escape(context) : "[a-zA-Z0-9\\-._/]+"} )
      \z
    }x
  end

  #
  # Instantiates a token from any supported non-ambiguous format.
  #
  def self.[](token)
    return token if
      token.is_a?(self)

    uri = Addressable::URI.parse(token)

    self.from_hex(
      uri.password,
      uri.path.delete_prefix('/'),
      scheme:   uri.scheme,
      domain:   uri.host,
      username: uri.user,
    )
  end

  def self.from_bytes(bytes, context, username: nil, scheme: SCHEME, domain: DOMAIN)
    self.new(
      bytes,
      context,
      scheme:   scheme,
      domain:   domain,
      username: username,
    )
  end

  #
  # Instantiates a token from hex-encoded cryptographic bytes, given a
  # scheme, domain, context, and username.
  #
  def self.from_hex(hex, context, username: nil, scheme: SCHEME, domain: DOMAIN)
    raise ArgumentError, 'token must be lowercase hex-encoded bytes' unless
      hex.match?(%r{ \A (?: [a-f0-9]{2} )+ \z }x)

    self.new(
      [hex].pack('H*'),
      context,
      scheme:   scheme,
      domain:   domain,
      username: username,
    )
  end

  class << self
    protected :new
  end

  #
  # Instantiates a token from parts.
  #
  def initialize(token, context, scheme:, domain:, username:)
    raise ArgumentError, 'refusing to encode a token with fewer than 128 bits of entropy' if
      token.bytesize < MINIMUM_ENTROPY

    raise ArgumentError, 'context must be present' if
      context.blank?

    @scheme   = scheme.freeze
    @domain   = domain.freeze
    @context  = context.freeze
    @username = username.freeze
    @token    = token.freeze

    self.freeze

    # sanity-check that we actually match the format we've committed to
    raise ArgumentError, 'be less creative with your context and username' unless
      self.class.regexp(self.length, scheme: scheme, domain: domain).match(self.to_s)
  end

  #
  # Generates an authenticator from a master key for the provided token.
  # Calling `authenticate!` on a token and authentictator will return
  # `true` if the token was the original input that generated the
  # authenticator and will raise otherwise.
  #
  # ```ruby
  # master   = Token.generate(64, 'api_key_root')
  # api_key1 = Token.generate(32, 'api_key')
  # api_key2 = Token.generate(32, 'api_key')
  #
  # authenticator = master.authenticator(api_key1)
  #
  # master.authenticate!(api_key1, authenticator) # => true
  # master.authenticate!(api_key2, authenticator) # => ArgumentError
  # ```
  #
  def authenticator(token, context = "#{token.context}/authenticator")
    raise ArgumentError, 'token must be from the same scheme and domain' unless
      self.related?(token)

    # SECURITY: the full token is passed in as the HKDF salt so the
    # authenticator is tightly bound to all of the token's metadata and
    # not only the cryptographic bytes within
    self.subkey token.length, context,
      username: token.username,
      salt:     token.to_s
  end

  #
  # Verifies that `token` was originally used to generate
  # `authenticator` (given this master key). Returns true if so,
  # otherwise raises an `ArgumentError`.
  #
  def authenticate!(token, authenticator)
    # SECURITY: we use the computed authenticator as the LHS of the
    # comparison to ensure that we use constant-time comparison
    raise ArgumentError, 'provided token could not be authenticated' unless
      self.authenticator(token, authenticator.context) == authenticator

    true
  end

  #
  # Derives a subkey from this key with the given `entropy`. Given the
  # same inputs an identical subkey will be derived. A random `salt` may
  # be provided to generate unique subkeys.
  #
  def subkey(entropy, context, username: self.username, salt: nil)
    # SECURITY: unambiguously encode scheme / domain / context /
    # username with a fixed-width length-prefixed format to prevent
    # things like `"context" + "username" == "contex" + "tusername"`.`
    info_parts  = [self.scheme, self.domain, context, username]
    info_format = info_parts.flat_map { |_| %w[Q> A*] }.join
    info        = info_parts.flat_map { |s| [s.to_s.length, s.to_s] }.pack(info_format)

    # SECURITY: use the full representation of self as the IKM to ensure
    # the output subkey is tightly bound to all of the token's metadata
    # and not only the cyrptographic bytes within
    token = HKDF.new(self.to_s,
      algorithm: ALGORITHM,
      info:      info,
      salt:      salt,
    ).next_bytes(entropy)

    self.class.from_bytes(
      token,
      context,
      scheme:   self.scheme,
      domain:   self.domain,
      username: username,
    )
  end

  #
  # Securely compares two tokens for equality.
  #
  def ==(other)
    ActiveSupport::SecurityUtils.secure_compare(self.to_s, other.to_s)
  end

  #
  # Returns true if two tokens are in the same scheme and domain.
  #
  def related?(other)
    self.scheme == other.scheme && self.domain == other.domain
  end

  #
  # Returns true if two tokens are in the same scheme, domain, and context.
  #
  def sibling?(other)
    self.related?(other) && self.context == other.context
  end

  #
  # Returns the bytes of entropy contained within the token.
  #
  def length
    @token.length
  end

  #
  # Renders the token with the cryptographic bytes removed.
  #
  def inspect
    self.to_uri.tap { |uri| uri.password = '[REDACTED]' }.to_s.inspect
  end

  #
  # Returns just the cryptographic bytes contained within the token.
  #
  def to_bytes
    @token
  end

  #
  # Returns just the cryptographic bytes contained within the token,
  # encoded as hex.
  #
  def to_hex
    @token.unpack1('H*')
  end

  #
  # Renders the token in its canonical URI format as a string.
  #
  def to_s
    self.to_uri.to_s
  end

  #
  # Renders the raw cryptographic bytes contained within the token. This
  # is so that tools like `OpenSSL` which may expect this to simply be
  # raw bytes can work directly with tokens.
  #
  def to_str
    self.to_bytes
  end

  #
  # Renders the token in its canonical URI format. The host component of
  # the URI is the token's domain, the path is its context, and the
  # userinfo are the username and hex-encoded cryptographic bytes,
  # respectively.
  #
  def to_uri
    Addressable::URI.new(
      scheme:   self.scheme,
      user:     self.username,
      password: self.to_hex,
      host:     self.domain,
      path:     self.context,
    )
  end
end
