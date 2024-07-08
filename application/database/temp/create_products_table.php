<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

class CreateProductsTable extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up()
    {
        Schema::create('products', function (Blueprint $table) {
            $table->id();
            $table->boolean('status');
            $table->integer('category_1')->nullable();
            $table->integer('category_2')->nullable();
            $table->integer('category_3')->nullable();
            $table->integer('category_4')->nullable();
            $table->integer('brand');
            $table->integer('model');
            $table->float('price')->nullable();
            $table->integer('stock');
            $table->string('name', 128)->nullable();
            $table->string('name_slug', 128)->nullable();
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
        Schema::dropIfExists('products');
    }
}
