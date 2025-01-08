require 'omniauth-oauth2'

module OmniAuth
  module Strategies
    class Tesla < OmniAuth::Strategies::OAuth2
      option :name, 'tesla'

      # Tesla's OAuth endpoints as documented:
      option :client_options, {
        site: 'https://auth.tesla.com',
        authorize_url: 'https://auth.tesla.com/oauth2/v3/authorize',
        token_url: 'https://fleet-auth.prd.vn.cloud.tesla.com/oauth2/v3/token'
      }

      # Default scopes:
      option :scope, 'openid offline_access'
      # Other Tesla scopes you might need: vehicle_device_data, vehicle_cmds, etc.

      # By default, Tesla requires an audience in the token exchange.
      # We'll provide a default but allow override:
      option :audience, 'https://fleet-api.prd.na.vn.cloud.tesla.com'

      # OmniAuth automatically includes response_type=code and passes
      # your :scope, :client_id, :redirect_uri, etc.
      option :authorize_params, {
        response_type: 'code'
      }

      # If you need to tweak how scopes or additional params are passed:
      def authorize_params
        super.tap do |params|
          # Ensure scope is set from your middleware config or fallback to default
          params[:scope] ||= options[:scope]
          # If you need more custom params for Tesla, you can set them here.
        end
      end

      # OmniAuth’s OAuth2 strategy automatically sends client_id, client_secret,
      # code, grant_type, and redirect_uri. We add audience here.
      def token_params
        super.tap do |params|
          # Since the Tesla token endpoint requires 'audience', we use our default
          # unless it's explicitly overridden in the middleware config.
          params[:audience] = options[:audience]
        end
      end

      # The uid method typically returns a unique user identifier.
      # If you decode Tesla's id_token, you can parse 'sub' here.
      uid { raw_info['sub'] }

      # The info hash typically contains user info if you have a userinfo endpoint
      # or have decoded the id_token. Since Tesla doesn’t provide a userinfo endpoint,
      # we leave this blank (or decode the ID token if you like).
      info do
        {}
      end

      extra do
        { raw_info: raw_info }
      end

      # If you decode the ID token or call a future userinfo endpoint, populate raw_info:
      def raw_info
        {}
      end

      # credentials block to store token and refresh_token
      credentials do
        hash = { 'token' => access_token.token }
        hash['refresh_token'] = access_token.refresh_token if access_token.refresh_token
        hash['expires_at']    = access_token.expires_at if access_token.expires?
        hash['expires']       = access_token.expires?
        hash
      end

      # Override callback_url if your callback URL is not the default that OmniAuth calculates:
      #
      #   OmniAuth automatically sets `redirect_uri` to this callback_url
      #   as part of the OAuth flow. If your app sits behind a proxy or
      #   you need a different callback route, override `callback_url` here.
      #
      # def callback_url
      #   full_host + script_name + callback_path
      # end
    end
  end
end

OmniAuth.config.add_camelization 'tesla', 'Tesla'