<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\Models\Brand;
use Illuminate\Support\Str;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Validator;

class BrandController extends Controller
{
    /**
     * GET
     * Display a listing of the resource.
     *
     * @param  \Illuminate\Http\Request $request
     * @return \Illuminate\Http\Response
     */
    public function index(Request $request)
    {
        $table = (fn() => $this->table)->call(new Brand); // https://stackoverflow.com/a/66277441
        
        $result = DB::table($table);

        $statusOptions = [0, 1];
        $result = isset($request->status) && in_array($request->status, $statusOptions) ? $result->where('status', $request->status) : $result->where('status', 1);

        return response()->json($result->get());
    }

    /**
     * POST
     * Store a newly created resource in storage.
     *
     * @param  \Illuminate\Http\Request $request
     * @return \Illuminate\Http\Response
     */
    public function create(Request $request)
    {        
        $validator = Validator::make($request->all(), [
            'name' => 'required|unique:products_brands|max:2|max:128'
        ]);
 
        if ($validator->fails()) {
            $resError = $validator->errors();
            goto end;
        }

        end:
        if (isset($resError)) {
            return response()->json($resError);

        } else {
            $request = (object) $request->all();

            $slug = Str::slug($request->name, '-'); // https://laravel.com/docs/8.x/helpers#method-str-slug

            $brand = new Brand();
            $brand->status      = 0;
            $brand->position    = 0;
            $brand->name        = $request->name;
            $brand->name_slug   = $slug;
            $brand->save();

            return response()->json(['id' => $brand->id]);
        }
        
    }

    /**
     * GET
     * Display the specified resource.
     *
     * @param  int  $id
     * @return \Illuminate\Http\Response
     */
    public function read($id)
    {
        if (!is_numeric($id)) {
            return response()->json(['message' => 'id is not numeric']);
        }

        $brand = Brand::find($id);
        unset($brand->id);

        return response()->json($brand);
    }

    /**
     * PUT x-www-form-urlencoded
     * Update the specified resource in storage.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  int  $id
     * @return \Illuminate\Http\Response
     */
    public function update(Request $request, $id)
    {
        if (!is_numeric($id)) {
            $resError = ['message' => 'id is not numeric'];
            goto end;
        }

        $brand = Brand::find($id);
        if (!$brand) {
            $resError = ['message' => "id $id not found"];
            goto end;
        }

        if (isset($request->name)) {
            $validator = Validator::make($request->all(), [
                'name' => 'required|unique:products_brands|max:128'
            ]);        
            if ($validator->fails()) {
                $resError = $validator->errors();
                goto end;
            }                
            $brand->name = $request->name;
            $brand->name_slug = Str::slug($request->name, '-');
        }

        if (isset($request->status)) {
            $statusOptions = [0, 1];
            if (!in_array($request->status, $statusOptions)) {
                $resError = ['message' => 'status value can only be 0 or 1'];
                goto end;
            } else {
                $brand->status = $request->status;
            }            
        }

        if (isset($request->position)) {
            if (!is_numeric($request->position)) {
                $resError = ['message' => 'position value is not numeric'];
                goto end;
            } else {
                $brand->position = $request->position;
            }
        }

        end:
        if (isset($resError)) {
            return response()->json($resError);

        } else {
            $brand->save();

            return response()->json(['success' => "id $id has been updated"]);
        }

    }

    /**
     * DELETE
     * Remove the specified resource from storage.
     *
     * @param  int  $id
     * @return \Illuminate\Http\Response
     */
    public function delete($id)
    {
        if (!is_numeric($id)) {
            $resError = ['message' => 'id is not numeric'];
            goto end;
        }

        $brand = Brand::find($id);
        if (!$brand) {
            $resError = ['message' => "id $id not found"];
            goto end;
        }

        // check if any product has this brand

        end:
        if (isset($resError)) {
            return response()->json($resError);

        } else {
            $brand->delete();

            return response()->json(['success' => "id $id has been deleted"]);
        }
        
    }
}
