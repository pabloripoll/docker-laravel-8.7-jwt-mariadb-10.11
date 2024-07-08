<?php

namespace Tests\Feature;

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Foundation\Testing\WithFaker;
use Tests\TestCase;
use Mockery;

class UserBasicsTest extends TestCase
{
    /**
     * User login faild.
     *
     * @return void
     */
    public function test_user_login_failed()
    {
        $loginData = [
            'user'      => 'anyuser@example.com',
            'password'  => '123456'
        ];

        $response = $this->json('POST', '/api/v1/sign-in', $loginData);

        return $response
            ->assertStatus(401)
            ->assertJsonPath('error', true)
            ;
    }

    /**
     * User login faild.
     *
     * @return void
     */
    public function test_password_login_failed()
    {
        $loginData = [
            'user'      => 'anyuser@example.com',
            'password'  => '123456'
        ];

        $response = $this->json('POST', '/api/v1/sign-in', $loginData);

        return $response
            ->assertStatus(401)
            ->assertJsonPath('error', true)
            ;
    }
}
