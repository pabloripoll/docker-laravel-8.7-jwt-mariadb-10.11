<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

class CreateProductsCategoriesTable extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up()
    {
        Schema::create('products_categories', function (Blueprint $table) {
            $table->id();
            $table->boolean('status');
            $table->integer('level');
            $table->integer('position');
            $table->integer('category_1')->nullable();
            $table->integer('category_2')->nullable();
            $table->integer('category_3')->nullable();
            $table->integer('category_4')->nullable();            
            $table->string('name', 128);
            $table->string('name_slug', 128);
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down()
    {
        Schema::dropIfExists('products_categories');
    }
}
