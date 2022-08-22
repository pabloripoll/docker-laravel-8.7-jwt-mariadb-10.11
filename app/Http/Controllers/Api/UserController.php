<?php

namespace App\Http\Controllers\Api;

use App\Models\User;
use JWTAuth;
use Illuminate\Http\Request;
use App\Http\Controllers\Controller;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Cookie;
use Illuminate\Support\Facades\Validator;
use Tymon\JWTAuth\Exceptions\JWTException;

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
        // include password_confirmation input
        $request->only('user', 'password', 'password_confirmation', 'name');        
        $request['email'] = $request['user']; // form wont send email input - user will be able to change it backoffice

        $validator = Validator::make($request->all(), [
            'user'      => 'required|string|max:128|unique:users,user',
            'user'      => 'unique:users,email',
            'password'  => 'required|string|min:6|confirmed',
            'email'     => 'required|string|max:128|unique:users,email',
            'name'      => 'required|string|min:3|max:128',
        ]);

        if ($validator->fails()) {
            $error      = json_decode(json_encode($validator->errors()), true);
            $resError   = [];
            !isset($error['name']) ?     : $resError = ['input' => 'name', 'message' => $error['name'][0]];
            !isset($error['email']) ?    : $resError = ['input' => 'email', 'message' => $error['email'][0]];
            !isset($error['password']) ? : $resError = ['input' => 'password_confirmation', 'message' => $error['password'][0]];
            !isset($error['user']) ?     : $resError = ['input' => 'user', 'message' => $error['user'][0]];
            goto end;
        }
        
        $newUser = new User();
        $newUser->user          = $request['user'];
        $newUser->password      = Hash::make($request['password']);
        $newUser->is_admin      = 0; // default value
        $newUser->is_customer   = 1; // default value
        $newUser->email         = $request['user'];
        $newUser->name          = $request['name'];
        $newUser->save();

        end:
        if (isset($resError)) {
            $resError['error'] = true;
            $resErrorCode = isset($resErrorCode) ? : 401;
            return response()->json($resError, $resErrorCode);

        } else {
            $userType = 'customer'; // default value
            return response()->json([
                'id'            => $newUser->id,
                'email'         => $newUser->email,
                'name'          => $newUser->name,
                'type'          => $userType
            ], 201);
        }
    }

    /**
     * User login
     *
     * @param  \Illuminate\Http\Request $request
     * @return \Illuminate\Http\Response
     */
    public function authenticate(Request $request)
    {
        $auth = $request->only('user', 'password');

        $user = User::where('user', '=', $request->user)->first();
        if (!isset($user->id)) {
            $resError = [
                'input'     => 'user',
                'message'   => 'user does not exists'
            ];
            goto end;
        }

        $passwordCheck = Hash::check($auth['password'], $user->password);
        if (!$passwordCheck) {
            $resError = [
                'input'     => 'password',
                'message'   => 'password does not match'
            ];
            goto end;
        }
        
        try {
            if (!$token = JWTAuth::attempt($auth)) {
                $resError = ['message' => 'invalid_auth'];
                goto end;
            }
        } catch (JWTException $e) {
            $resError = ['message' => 'could_not_create_token'];
            goto end;
        }

        end:
        if (isset($resError)) {
            $resError['error'] = true;
            $resErrorCode = isset($resErrorCode) ? : 401;
            return response()->json($resError, $resErrorCode);

        } else {
            $userType = $user->is_admin == 1 ? 'admin' : 'customer'; 
            return response()->json([      
                'id'            => $user->id,
                'name'          => $user->name,
                'type'          => $userType,
                'token_key'     => $token,
                'token_type'    => 'Bearer',
                'token_expires' => auth()->factory()->getTTL() * 60
            ]);
        }
    }

    /**
     * User profile
     *
     * @param  \Illuminate\Http\Request $request
     * @return \Illuminate\Http\Response
     */
    public function getAuthenticatedUser($id)
    {
        try {
            if (!$user = JWTAuth::parseToken()->authenticate()) {
                $resError = ['message' => 'user_not_found'];
                goto end;
            }

        } catch (Tymon\JWTAuth\Exceptions\TokenExpiredException $e) {
            $resError = ['message' => 'token_expired'];
            $resErrorCode = $e->getStatusCode();
            goto end;

        } catch (Tymon\JWTAuth\Exceptions\TokenInvalidException $e) {
            $resError = ['message' => 'token_invalid'];
            $resErrorCode = $e->getStatusCode();
            goto end;

        } catch (Tymon\JWTAuth\Exceptions\JWTException $e) {
            $resError = ['message' => 'token_absent'];
            $resErrorCode = $e->getStatusCode();
            goto end;
            
        }

        $user = User::where('id', '=', $id)->first();
        if (!isset($user->id)) {
            $resError = [
                'input'     => 'user',
                'message'   => 'user does not exists'
            ];
            goto end;
        }

        end:
        if (isset($resError)) {
            $resError['error'] = true;
            $resErrorCode = isset($resErrorCode) ? : 401;
            return response()->json($resError, $resErrorCode);

        } else {
            $userType   = $user->is_admin == 1 ? 'admin' : 'customer';
            $token      = request()->bearerToken();
            return response()->json([      
                'id'            => $user->id,
                'name'          => $user->name,
                'type'          => $userType,
                'token_key'     => $token,
                'token_type'    => 'Bearer',
                'token_expires' => auth()->factory()->getTTL() * 60
            ]);
        }
    }
    
    /**
     * Log the user out (Invalidate the token).
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function logout()
    {
        JWTAuth::invalidate(JWTAuth::getToken());
        
        return response()->json([
            'logout'    => true,
            'message'   => 'user has been logout'
        ]);
    }
}
