require "omniauth-oauth2"

module OmniAuth
  module Strategies
    class Nylas < OmniAuth::Strategies::OAuth2
      option :name, "nylas"
      option :client_options, {
        :site          => "https://api.nylas.com",
        :authorize_url => "/oauth/authorize",
        :token_url     => "/oauth/token"
      }
      option :client_id, ENV["NYLAS_APP_ID"]
      option :client_secret, ENV["NYLAS_APP_SECRET"]
      option :token_options, [:client_id, :client_secret]

      uid { access_token.params["account_id"] }

      info do
        {
          "account_id" => access_token.params["account_id"],
          "email"      => access_token.params["email_address"],
          "provider"   => access_token.params["provider"]
        }
      end
    end
  end
end
