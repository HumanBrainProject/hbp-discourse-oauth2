require_relative 'lib/omniauth-hbpoauth2'
#Re-uses the Oauth2UserInfo model for storing data regarding user

class HbpAuthenticator < ::Auth::Authenticator

  def name
    'hbpoauth2'
  end

  def after_authenticate(auth_token)
    result = Auth::Result.new

    oauth2_provider = auth_token[:provider]

    # grap the info we need from omni auth
    data = auth_token[:info]
    oauth2_uid = data[:name]

    result.name = name = data[:nickname]
    result.username = user = data[:name]
    result.email = email = data[:email]

    oauth2_user_info = Oauth2UserInfo.find_by(uid: oauth2_uid, provider: oauth2_provider)
    if !oauth2_user_info && user = Oauth2UserInfo.find_by(email: email)
      oauth2_user_info = Oauth2UserInfo.create(uid: oauth2_uid,
                                               user_id: user.id,
                                               provider: oauth2_provider,
                                               name: name,
                                               email: email)
    end

    result.user = oauth2_user_info.try(:user)
    result.extra_data = {
      uid: oauth2_uid,
      provider: oauth2_provider
    }

    result
  end

  def after_create_account(user, auth)
    puts 'user', user.inspect
    puts 'auth', auth.inspect
    data = auth[:extra_data]
    Oauth2UserInfo.create(
      uid: data[:uid],
      provider: data[:provider],
      name: auth[:name],
      email: auth[:email],
      user_id: user.id
    )
  end

  def register_middleware(omniauth)
    omniauth.provider :hbpoauth2, :setup => lambda { |env|
      strategy = env['omniauth.strategy']
      #stored in config/settings.yml
      strategy.options[:client_id] = SiteSetting.hbp_client_id
      strategy.options[:client_secret] = SiteSetting.hbp_client_secret
    }
  end
end


auth_provider :frame_width => 920,
              :frame_height => 800,
              :authenticator => HbpAuthenticator.new

register_css <<CSS

.btn-social.hbpoauth2 {
  background: #666666;
}

CSS
