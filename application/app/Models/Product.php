<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class Product extends Model
{
    use HasFactory;
    protected $fillable = [
        'category_1',
        'category_2',
        'category_3',
        'category_4',
        'price',
        'stock',
        'name'
    ];
}
