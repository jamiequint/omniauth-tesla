# lib/omniauth/strategies/tesla.rb
require 'omniauth-oauth2'
require 'multi_json'

module OmniAuth
  module Strategies
    class Tesla < OmniAuth::Strategies::OAuth2
      option :name, 'tesla'

      # Tesla's OAuth endpoints:
      option :client_options, {
        site: 'https://auth.tesla.com',
        authorize_url: 'https://auth.tesla.com/oauth2/v3/authorize',
        token_url: 'https://fleet-auth.prd.vn.cloud.tesla.com/oauth2/v3/token'
      }

      # Default scopes (adjust as needed for user_data, etc.):
      option :scope, 'openid offline_access user_data'

      # Default audience required for Tesla token exchange:
      option :audience, 'https://fleet-api.prd.na.vn.cloud.tesla.com'

      option :authorize_params, {
        response_type: 'code'
      }

      # Define class-level accessors for OAuth configuration
      class << self
        attr_accessor :client_id, :client_secret, :site, :authorize_url, :token_url, :audience
      end

      # Initialize class-level accessors with instance-level options
      def initialize(*args, &block)
        super
        self.class.client_id ||= options.client_id
        self.class.client_secret ||= options.client_secret
        self.class.site ||= options.client_options.site
        self.class.authorize_url ||= options.client_options.authorize_url
        self.class.token_url ||= options.client_options.token_url
        self.class.audience ||= options.audience
      end

      # Override authorize_params to include necessary parameters
      def authorize_params
        super.tap do |params|
          # In case someone sets a custom scope in the provider config.
          params[:scope] ||= options[:scope]
          # Explicitly include client_id
          params[:client_id] = options.client_id
        end
      end

      # Add audience into the token request
      def token_params
        super.tap do |params|
          # Required parameters for Tesla token exchange
          params[:grant_type]    = 'authorization_code'
          params[:code]          = request.params['code']
          params[:client_id]     = options.client_id
          params[:client_secret] = options.client_secret
          params[:audience]      = options[:audience]
          params[:redirect_uri]  = callback_url
        end
      end

      # Override build_access_token if necessary
      def build_access_token
        verifier = request.params['code']
        client.auth_code.get_token(
          verifier,
          token_params,
          deep_symbolize(options.auth_token_params || {})
        )
      end

      # UID is vault_uuid from the user info response
      uid { raw_info.dig('response', 'vault_uuid') }

      # User info retrieved from Tesla's API
      info do
        response_data = raw_info['response'] || {}
        {
          email:              response_data['email'],
          full_name:          response_data['full_name'],
          profile_image_url:  response_data['profile_image_url']
        }
      end

      # Extra information (raw user info)
      extra do
        { raw_info: raw_info }
      end

      # Fetch user info from /api/1/users/me
      def raw_info
        @raw_info ||= begin
          url = 'https://fleet-api.prd.na.vn.cloud.tesla.com/api/1/users/me'

          response = access_token.get(url, headers: {
            'Content-Type' => 'application/json'
          })

          MultiJson.load(response.body)
        rescue ::OAuth2::Error => e
          warn "OmniAuth Tesla raw_info error: #{e.response&.body}"
          {}
        end
      end

      # Store access_token info (token, refresh_token, expires, etc.)
      credentials do
        hash = { 'token' => access_token.token }
        hash['refresh_token'] = access_token.refresh_token if access_token.refresh_token
        hash['expires_at']    = access_token.expires_at if access_token.expires?
        hash['expires']       = access_token.expires?
        hash
      end

      # Override callback_url if necessary
      def callback_url
         full_host + script_name + callback_path
      end

      # Optionally log the request phase
      def request_phase
        super
      end

      # Class-level helper to refresh an access token using a saved refresh_token
      def self.refresh_with(refresh_token)
        client = ::OAuth2::Client.new(
          self.client_id,
          self.client_secret,
          site: self.site,
          authorize_url: self.authorize_url,
          token_url: self.token_url
        )

        token_obj = ::OAuth2::AccessToken.new(client, '', refresh_token: refresh_token)
        new_token = token_obj.refresh!
        new_token
      rescue ::OAuth2::Error => e
        # Use a generic warning for logging since Rails.logger may not be available
        warn "Tesla refresh error: #{e.message}"
        nil
      end
    end
  end
end

# Add camelization for the Tesla strategy
OmniAuth.config.add_camelization 'tesla', 'Tesla'