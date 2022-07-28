<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\Models\User;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Validator;

class UserController extends Controller
{
    /**
     * Users register
     *
     * @param  \Illuminate\Http\Request $request
     * @return \Illuminate\Http\Response
     */
    public function register(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'name'      => 'required',
            'email'     => 'required|email|unique:users',
            'password'  => 'required|confirmed'
        ]);

        if ($validator->fails()) {
            $resError = $validator->errors(); // https://laravel.com/docs/8.x/validation
            goto end;
        }

        end:
        if (isset($resError)) {
            return response()->json($resError);

        } else {
            $user = new User();
            $user->name     = $request->name;
            $user->email    = $request->email;
            $user->password = Hash::make($request->password);
            $user->save();

            return response()->json([
                'status'    => 1,
                'message'   => 'user has been registered',
                'id'        => $user->id
            ]);
        }
    }

    /**
     * Users login
     *
     * @param  \Illuminate\Http\Request $request
     * @return \Illuminate\Http\Response
     */
    public function login(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'email'     => 'required|email',
            'password'  => 'required'
        ]);

        if ($validator->fails()) {
            $resError = $validator->errors(); // https://laravel.com/docs/8.x/validation
            goto end;
        }

        $user = User::where('email', '=', $request->email)->first();
        if (!isset($user->id)) {
            $resError = [
                'status'    => 0,
                'message'   => 'user does not exists',
            ];
        } else {
            if (Hash::check($request->password, $user->password)) {                
                $token = $user->createToken('auth_token')->plainTextToken;

            } else {
                $resError = [
                    'status'    => 0,
                    'message'   => 'the password is incorrect',
                ];
            }
        }
        
        end:
        if (isset($resError)) {
            return response()->json($resError, 404);

        } else {
            return response()->json([
                'status'        => 1,
                'message'       => 'login success',
                'access_token'  => $token,
                'token_type'    => 'Bearer',
            ]);
        }
    }

    /**
     * Users profile
     *
     * @param  \Illuminate\Http\Request $request
     * @return \Illuminate\Http\Response
     */
    public function userProfile()
    {
        return response()->json([
            'data' => auth()->user()
        ]); 
    }

    /**
     * Users logout
     *
     * @param  \Illuminate\Http\Request $request
     * @return \Illuminate\Http\Response
     */
    public function logout()
    {
        $user_id = auth()->user()->id;

        auth()->user()->tokens()->delete();

        return response()->json([
            'message'   => "session $user_id has been closed"
        ]); 
    }
}
