<?php

namespace App\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Password;
use Illuminate\Validation\ValidationException;

class AuthController extends Controller
{

    public function __construct()
    {
        $this->middleware('guest')->except('logout');
    }

    /**
     * @param  Request  $request
     *
     * @return JsonResponse
     * @throws ValidationException
     */
    public function login(Request $request): JsonResponse
    {
        $request->validate([
                               'name'   => 'prohibited',
                               'email'  => 'required|email',
                               'secret' => 'required|min:6',
                           ]);

        $credentials = [
            'email'    => $request->input('email'),
            'password' => $request->input('secret'),
        ];

        if (!Auth::attempt($credentials)) {
            return $this->error('Credentials not match', 401);
        }

        return $this->success(['token' => auth()->user()->createToken('API Token')->plainTextToken,]);
    }

    protected function error(string $message, int $code, $data = null): JsonResponse
    {
        return response()
            ->json([
                       'status'  => 'Error',
                       'message' => $message,
                       'data'    => $data,
                   ],
                   $code);
    }

    protected function success(array|string $data, string $message = null, int $code = 200): JsonResponse
    {
        return response()
            ->json([
                       'status'  => 'Success',
                       'message' => $message,
                       'data'    => $data,
                   ],
                   $code);
    }

    /**
     * @return string[]
     */
    public function logout(Request $request): array
    {
        if (auth()->user()) {
            auth()->user()->tokens()->delete();
        }

        Auth::guard('web')->logout();
        $request->session()->invalidate();
        $request->session()->regenerateToken();

        return ['message' => 'Tokens Revoked.',];
    }
}
