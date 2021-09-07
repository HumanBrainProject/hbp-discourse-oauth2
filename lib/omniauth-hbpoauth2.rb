require "omniauth"
require_relative "omniauth-hbpoauth2/version"
require_relative "omniauth/strategies/hbpoauth2"

OmniAuth.config.add_camelization 'hbpoauth2', 'Hbpoauth2'
