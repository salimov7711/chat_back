<?php

use App\Http\Controllers\api\UserController;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

Route::get('/user', function (Request $request) {
    return $request->user();
})->middleware('auth:sanctum');


Route::group(['prefix' => 'auth'], function () {
    Route::post('/register', [UserController::class, 'store']);
    Route::post('/login', [UserController::class, 'login']);
    Route::get('/logout', [UserController::class, 'logout'])->middleware('auth:sanctum');
});



