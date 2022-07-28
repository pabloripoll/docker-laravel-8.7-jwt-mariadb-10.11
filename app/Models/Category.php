<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class Category extends Model
{
    use HasFactory;

    protected $fillable = [
        'status',
        'level',
        'position',
        'category_1',
        'category_2',
        'category_3',
        'category_4',        
        'name',
        'name_slug',
    ];

    /**
     * The table associated with the model.
     *
     * @var string
     */
    protected $table = 'products_categories';
}
