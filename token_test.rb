# frozen_string_literal: true

require 'test_helper'

class TokenTest < ActiveSupport::TestCase
  def master_key
    @_master_key ||= Token.generate(64, self.context, username: self.username)
  end

  def context
    @_context ||= self.gen_context
  end

  def username
    @_username ||= self.gen_username
  end

  def gen_hex(entropy = 16)
    SecureRandom.hex(entropy)
  end

  def gen_bytes(entropy = 16)
    SecureRandom.bytes(entropy)
  end

  def gen_context
    Faker::Internet.slug
  end

  def gen_username
    Faker::Internet.username
  end

  def generate(
    entropy,
    context = self.gen_context,
    username: self.gen_username
  )
    Token.generate(entropy, context, username: username)
  end

  test 'cannot be instantiated with less than 128 bits of entropy' do
    assert_raises(ArgumentError) { self.generate(15) }
    assert_raises(ArgumentError) { Token.from_bytes self.gen_bytes(15), 'ctx' }
    assert_raises(ArgumentError) { Token.from_hex   self.gen_hex(15),   'ctx' }
  end

  test 'cannot be instantiated with invalid hex' do
    assert_raises(ArgumentError) { Token.from_hex('af01bg', 'ctx') }
    assert_raises(ArgumentError) { Token.from_hex('af01b',  'ctx') }
  end

  test 'cannot be instantiated with an empty context' do
    assert_raises(ArgumentError) { self.generate(16, '')  }
    assert_raises(ArgumentError) { self.generate(16, nil) }
    assert_raises(ArgumentError) { Token.from_bytes self.gen_bytes, ''  }
    assert_raises(ArgumentError) { Token.from_bytes self.gen_bytes, nil }
    assert_raises(ArgumentError) { Token.from_hex   self.gen_hex,   ''  }
    assert_raises(ArgumentError) { Token.from_hex   self.gen_hex,   nil }
  end

  test '::generate creates tokens of the given length' do
    token1 = self.generate(16)
    token2 = self.generate(16)
    token3 = self.generate(32)
    token4 = self.generate(64)

    assert_equal 16, token1.length
    assert_equal 16, token2.length
    assert_equal 32, token3.length
    assert_equal 64, token4.length
  end

  test '::generate creates unique tokens with identical inputs' do
    tokens = Array.new(32) { self.generate(16, self.context, username: self.username) }
    copies = tokens.dup

    tokens.each do |token|
      copies.shift
      copies.each { |other| refute_equal(token, other) }
    end
  end

  test '::generate creates tokens with the provided attributes' do
    token = self.generate(128, self.context, username: self.username)

    assert_equal self.context,  token.context
    assert_equal self.username, token.username
  end

  test '#authenticator creates a token dervied from the provided token' do
    token         = self.generate(16)
    authenticator = self.master_key.authenticator(token)

    assert_equal token.length,   authenticator.length
    assert_equal token.username, authenticator.username
    assert_equal token.context,  authenticator.context.delete_suffix('/authenticator')
    refute_equal token.to_bytes, authenticator.to_bytes
  end

  test '#authenticator returns the same authenticator given identical inputs' do
    token = self.generate(32)

    assert_equal(
      self.master_key.authenticator(token),
      self.master_key.authenticator(token),
    )
  end

  test '#authenticator raises if the master key and token are from unrelated domains' do
    domain     = Faker::Internet.domain_name
    token      = self.generate(16)
    master_key = Token.from_bytes(self.gen_bytes, self.gen_context, domain: domain)

    assert_raises(StandardError) { master_key.authenticator(token) }
  end

  test '#authenticate! returns true if the authenticator matches the token' do
    token         = self.generate(16)
    authenticator = self.master_key.authenticator(token)

    assert self.master_key.authenticate!(token, authenticator)
  end

  test '#authenticate! raises if the authenticator does not match the token' do
    token1 = self.generate(16, self.context, username: self.username)
    token2 = self.generate(16, self.context, username: self.username)
    token3 = Token.from_bytes(token1.to_bytes, self.gen_context, username: self.username)
    token4 = Token.from_bytes(token1.to_bytes, self.context,     username: self.gen_username)

    authenticator = self.master_key.authenticator(token1)

    assert_raises(ArgumentError) { self.master_key.authenticate!(token2, authenticator) }
    assert_raises(ArgumentError) { self.master_key.authenticate!(token3, authenticator) }
    assert_raises(ArgumentError) { self.master_key.authenticate!(token4, authenticator) }
  end

  test '#authenticate! raises if the master key, token, and authenticator are provided out-of-order' do
    token         = self.generate(16)
    authenticator = self.master_key.authenticator(token)

    assert_raises(ArgumentError) { self.master_key.authenticate!(authenticator, token) }
    assert_raises(ArgumentError) { token.authenticate!(master_key, authenticator) }
    assert_raises(ArgumentError) { token.authenticate!(authenticator, master_key) }
    assert_raises(ArgumentError) { authenticator.authenticate!(master_key, token) }
    assert_raises(ArgumentError) { authenticator.authenticate!(token, master_key) }
  end

  test '#subkey creates identical keys for identical inputs' do
    key1 = self.master_key.subkey(32, self.context, username: self.username, salt: 'salt')
    key2 = self.master_key.subkey(32, self.context, username: self.username, salt: 'salt')

    assert_equal key1, key2
  end

  test '#subkey creates different keys for different contexts' do
    key1 = self.master_key.subkey(32, self.gen_context)
    key2 = self.master_key.subkey(32, self.gen_context)

    refute_equal key1, key2
  end

  test '#subkey creates different keys for different usernames' do
    key1 = self.master_key.subkey(32, self.context, username: self.gen_username)
    key2 = self.master_key.subkey(32, self.context, username: self.gen_username)

    refute_equal key1, key2
  end

  test '#subkey creates different keys from different salts' do
    key1 = self.master_key.subkey(32, self.context, username: self.username, salt: self.gen_hex)
    key2 = self.master_key.subkey(32, self.context, username: self.username, salt: self.gen_hex)

    refute_equal key1, key2
  end

  test '#inspect redacts private key material' do
    token   = self.generate(32)
    inspect = token.inspect
    secret  = inspect.scan(%r{ [\w\-\[\]_.]+ }x)[2]

    assert_equal '[REDACTED]', secret
  end
end
