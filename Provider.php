<?php

namespace Opentickettech\Socialite;

use SocialiteProviders\Manager\OAuth2\AbstractProvider;
use SocialiteProviders\Manager\OAuth2\User;

class Provider extends AbstractProvider
{
    const IDENTIFIER = "OPENTICKETTECH";

    public function getAccessTokenRefreshResponse ($refreshToken) {
        $response = $this->getHttpClient()->post($this->getTokenUrl(), [
            "headers"     => ["Accept" => "application/json"],
            "form_params" => $this->getTokenRefreshFields($refreshToken),
        ]);

        return json_decode($response->getBody(), true);
    }

    protected function getAuthUrl ($state) {
        return $this->buildAuthUrlFromBase("https://auth.openticket.tech/token/authorize", $state);
    }

    protected function getTokenUrl () {
        return "https://auth.openticket.tech/token";
    }

    public function userFromToken($token) {
        return $this->getUserByToken($token);
    }

    protected function getUserByToken ($token) {
        $userUrl = "https://auth.openticket.tech/user/me";

        $response = $this->getHttpClient()->get(
            $userUrl, $this->getRequestOptions($token)
        );

        $user = json_decode($response->getBody(), true);

        return $user;
    }

    protected function mapUserToObject (array $user) {
        // TODO - Implement
        throw new \BadMethodCallException("This function has not been implemented yet");
    }

    protected function getTokenFields ($code) {
        return array_merge(parent::getTokenFields($code), [
            "grant_type" => "authorization_code",
        ]);
    }

    protected function getTokenRefreshFields ($refreshToken) {
        return [
            "client_id"     => $this->clientId,
            "client_secret" => $this->clientSecret,
            "refresh_token" => $refreshToken,
            "grant_type"    => "refresh_token",
        ];
    }

    /**
     * Get the default options for an HTTP request.
     *
     * @param string $token
     * @return array
     */
    protected function getRequestOptions($token)
    {
        return [
            'headers' => [
                'Accept' => 'application/json',
                'Authorization' => 'Bearer '.$token,
            ],
        ];
    }
}
