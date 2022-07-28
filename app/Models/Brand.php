<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class Brand extends Model
{
    use HasFactory;
    
    protected $fillable = [
        'status',
        'position',
        'name',
        'name_slug',
    ];

    /**
     * The table associated with the model.
     *
     * @var string
     */
    protected $table = 'products_brands';
    
}
