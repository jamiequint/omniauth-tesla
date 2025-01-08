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
          # Ensure spaces are encoded as %20 instead of +
          params[:scope] = URI.encode_www_form_component(params[:scope]).gsub('+', '%20')
        end
      end

      # Add audience into the token request
      def token_params
        super.tap do |params|
          # Tesla requires 'audience' in the token exchange.
          params[:audience] = options[:audience]
        end
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
        @raw_info ||= access_token.get('/api/1/users/me').parsed
      rescue ::OAuth2::Error => e
        # If for some reason we can’t fetch user info (e.g. insufficient scope),
        # fallback to empty hash or handle error as needed.
        {}
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
      # def callback_url
      #   full_host + script_name + callback_path
      # end
    end
  end
end

OmniAuth.config.add_camelization 'tesla', 'Tesla'