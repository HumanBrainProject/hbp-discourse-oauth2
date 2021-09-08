require 'omniauth/strategies/oauth2'
require 'multi_json'
require 'pp'

# This parser is needed in order to handle hal json responses returned by idm/v1 endpoints
require 'oauth2/response'
::OAuth2::Response.register_parser(:hal_json, ['application/hal+json']) do |body|
  MultiJson.load(body) rescue body
end

module OmniAuth
  module Strategies
    class Hbpoauth2 < OmniAuth::Strategies::OAuth2
      class NoRawData < StandardError; end

      API_VERSION = '5.2'

      DEFAULT_SCOPE = 'openid'

      option :name, 'hbpoauth2'

      option :client_options, {
        :site          => 'https://services.humanbrainproject.eu/',
        :authorize_url => 'https://services.humanbrainproject.eu/oidc/authorize',
        :token_url     => 'https://services.humanbrainproject.eu/oidc/token',
      }

      option :authorize_options, [:scope, :display]

      uid { raw_info['id'].to_s }

      info do
        {
          :name       => raw_info['username'],
          :nickname   => raw_info['displayName'],
          :email      => raw_info['emails'].first['value'],
          :first_name => raw_info['givenName'],
          :last_name  => raw_info['familyName'],
        }
      end

      extra do
        {
          'raw_info' => raw_info
        }
      end

      def raw_info
        access_token.options[:mode] = :query
        access_token.options[:param_name] = :access_token
        @raw_info ||= begin
          result = access_token.get('/idm/v1/api/user/me').parsed
        end
      end

      def callback_url
        full_host + script_name + callback_path
      end

      def authorize_params
        super.tap do |params|
          # just a copypaste from ominauth-facebook
          %w[display state scope].each do |v|
            if request.params[v]
              params[v.to_sym] = request.params[v]

              # to support omniauth-oauth2's auto csrf protection
              session['omniauth.state'] = params[:state] if v == 'state'
            end
          end

          params[:scope] ||= DEFAULT_SCOPE
        end
      end

      private

      def callback_phase
        super
      rescue NoRawData => e
        fail!(:no_raw_data, e)
      rescue Exception => e
        puts e.message
        puts e.backtrace.inspect
      end
    end
  end
end
