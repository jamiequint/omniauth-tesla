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

      # If you need to tweak how scopes or additional params are passed:
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
        params = super.tap do |params|
          # Required parameters for Tesla token exchange
          params[:grant_type] = 'authorization_code'
          params[:code] = request.params['code']
          params[:client_id] = options.client_id
          params[:client_secret] = options.client_secret
          params[:audience] = options[:audience]
          params[:redirect_uri] = callback_url
        end
        
        params
      end

      # You might also need to override build_access_token
      def build_access_token
        verifier = request.params['code']
        client.auth_code.get_token(
          verifier,
          token_params,
          deep_symbolize(options.auth_token_params || {})
        )
      end

      # Tesla's /api/1/users/me returns:
      # {
      #   "response": {
      #     "email": "test-user@tesla.com",
      #     "full_name": "Testy McTesterson",
      #     "profile_image_url": "...",
      #     "vault_uuid": "b5c443af-a286-49eb-a4ad-35a97963155d"
      #   }
      # }
      #
      # We'll use vault_uuid as the `uid` if present.
      uid { raw_info.dig('response', 'vault_uuid') }

      info do
        response_data = raw_info['response'] || {}
        {
          email:            response_data['email'],
          full_name:        response_data['full_name'],
          profile_image_url: response_data['profile_image_url']
        }
      end

      extra do
        # Provide the entire user hash for debugging or additional use.
        { raw_info: raw_info }
      end

      # Fetch user info from /api/1/users/me
      # By default, OmniAuth::Strategies::OAuth2 includes the
      # access token as a Bearer token in the Authorization header.
      def raw_info
        @raw_info ||= begin
          url = 'https://fleet-api.prd.na.vn.cloud.tesla.com/api/1/users/me'
          
          response = access_token.get(url, headers: {
            'Content-Type' => 'application/json'
          })
          
          MultiJson.load(response.body)
        rescue ::OAuth2::Error => e
          puts "DEBUG - Error response: #{e.response&.body}"
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

      # Override callback_url if your callback URL is not the default that OmniAuth calculates.
      # The default behavior is to use full_host + script_name + callback_path,
      # which is typically correct and matches what OmniAuth sends as redirect_uri.
      #
      def callback_url
         full_host + script_name + callback_path
      end

      # You might also want to log in the request phase
      def request_phase
        super
      end

      # Class-level helper to refresh an access token using a saved refresh_token
      def self.refresh_with(refresh_token)
        # Load default options from OmniAuth's config (or override as needed)
        opts = OmniAuth::Strategies::Tesla.options

        client = ::OAuth2::Client.new(
          opts.client_id,
          opts.client_secret,
          opts.client_options.to_h
        )

        token_obj = ::OAuth2::AccessToken.new(client, '', refresh_token: refresh_token)
        new_token = token_obj.refresh!
        new_token
      rescue ::OAuth2::Error => e
        Rails.logger.error("Tesla refresh error: #{e.message}")
        nil
      end

    end
  end
end

OmniAuth.config.add_camelization 'tesla', 'Tesla'