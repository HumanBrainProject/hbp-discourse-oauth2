require 'omniauth/strategies/oauth2'
require 'multi_json'
require 'pp'

# This parser is needed in order to handle hal json responses returned by idm/v1 endpoints
#require 'oauth2/response'
#::OAuth2::Response.register_parser(:hal_json, ['application/hal+json']) do |body|
#  MultiJson.load(body) rescue body
#end

module OmniAuth
  module Strategies
    class Hbpoauth2 < OmniAuth::Strategies::OAuth2
      class NoRawData < StandardError; end

      API_VERSION = '5.2'

      DEFAULT_SCOPE = 'openid profile email'

      option :name, 'hbpoauth2'

      option :client_options, {
        :site          => 'https://iam.ebrains.eu/',
        :authorize_url => 'https://iam.ebrains.eu/auth/realms/hbp/protocol/openid-connect/auth',
        :token_url     => 'https://iam.ebrains.eu/auth/realms/hbp/protocol/openid-connect/token',
      }

      option :authorize_options, [:scope, :display]

      uid { raw_info['preferred_username'].to_s }

      info do
        {
          :name       => raw_info['preferred_username'],
          :nickname   => raw_info['firstName'] + " " + raw_info['lastName'],
          :email      => raw_info['email'],
          :first_name => raw_info['given_name'],
          :last_name  => raw_info['family_name'],
        }
      end

      extra do
        {
          'raw_info' => raw_info
        }
      end

    	def raw_info
    	  @raw_info ||= begin
    	    # 
    	    # todo build the URI from the settings
    	    #
    		uri = URI.parse("https://iam.ebrains.eu/auth/realms/hbp/protocol/openid-connect/userinfo")
    		#uri = URI.parse("https://services.humanbrainproject.eu/oidc/userinfo")
    		request = Net::HTTP::Get.new(uri)
    		request['Authorization'] = 'Bearer ' + access_token.token
    
    		response = Net::HTTP.start(uri.host, uri.port, :use_ssl => uri.scheme == 'https') do |http|
    		  http.request(request)
    		end
    		Rails.logger.info "RESPONSE = #{response.body}"
    		JSON.parse(response.body)
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
