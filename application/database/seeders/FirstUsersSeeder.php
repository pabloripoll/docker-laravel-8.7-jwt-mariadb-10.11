<?php

namespace Database\Seeders;

use Illuminate\Database\Seeder;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use App\Models\User;

class FirstUsersSeeder extends Seeder
{
    /**
     * Run the database seeders.
     * php artisan db:seed --class=FirstUserSeeder
     * 
     * @return void
     */
    public function run()
    {
        $user = new User();
        $user->user         = 'adminuser@apistore.com';
        $user->password     = Hash::make('Admin1234');
        $user->is_admin     = 1;
        $user->is_customer  = 0;
        $user->email        = 'adminuser@apistore.com';
        $user->name         = 'James McKeown';
        $user->save();
        
        $user = new User();
        $user->user         = 'customer@example.com';
        $user->password     = Hash::make('Cust1234');
        $user->is_admin     = 0;
        $user->is_customer  = 1;
        $user->email        = 'customer@example.com';
        $user->name         = 'John Doe';
        $user->save();
    }
}