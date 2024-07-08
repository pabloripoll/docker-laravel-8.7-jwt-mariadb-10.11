<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\Models\Category;
use Illuminate\Support\Str;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Validator;


class CategoryController extends Controller
{
    /**
     * Listing
     * 
     * @param  \Illuminate\Http\Request $request
     */
    private function listing($columns, $condition, $orderBy)
    {
        $positionOptions = ['0-9', '9-0', 'a-z', 'z-a'];
        $pos = !in_array($orderBy, $positionOptions) ? $positionOptions[0] : $orderBy;
        if ($pos == 'a-z') $categories = Category::where($condition)->orderBy('name')->get($columns);
        if ($pos == 'z-a') $categories = Category::where($condition)->orderByDesc('name')->get($columns);
        if ($pos == '0-9') $categories = Category::where($condition)->orderBy('position')->get($columns);
        if ($pos == '9-0') $categories = Category::where($condition)->orderByDesc('position')->get($columns);

        return $categories;
    }

    /**
     * GET
     * Display a listing of the resource.
     *
     * @param  \Illuminate\Http\Request $request
     * @return \Illuminate\Http\Response
     */
    public function index(Request $request)
    {
        $condition  = [];
        $columns    = '*';

        $statusOptions = [0, 1];
        $condition[] = !isset($request->status) || !in_array($request->status, $statusOptions) ? ['status', '=', 1] : ['status', '=', $request->status];

        // categories
        $category_1 = 0;
        $category_2 = 0;
        $category_3 = 0;
        $category_4 = 0; // default value because there's no 5th category level
        if (isset($request->categories)) {
            $array = explode('.', preg_replace("/[^0-9.]/", '', $request->categories));
            if (count($array) == 4) {
                $category_1 = $array[0];
                $category_2 = $array[1];
                $category_3 = $array[2];
                $category_4 = $array[3];
            }
            $condition[] = ['category_1', '=', $category_1];
            $condition[] = ['category_2', '=', $category_2];
            $condition[] = ['category_3', '=', $category_3];
            $condition[] = ['category_4', '=', $category_4];
        } else {
            $condition[] = ['level', '=', 1];
        }

        $orderBy = !isset($request->position) ? '' : $request->position;

        $categories = $this->listing($columns, $condition, $orderBy);

        return response()->json($categories);
    }

    /**
     * GET
     * Display a listing of the resource.
     *
     * @param  \Illuminate\Http\Request $request
     * @return \Illuminate\Http\Response
     */
    public function indextree(Request $request)
    {
        $condition  = [];
        $columns    = ['id', 'name', 'name_slug'];

        $statusOptions = [0, 1];
        $condition[] = !isset($request->status) || !in_array($request->status, $statusOptions) ? ['status', '=', 1] : ['status', '=', $request->status];

        $condition[] = ['level', '=', 1];

        $orderBy = !isset($request->position) ? '' : $request->position;

        $categories = $this->listing($columns, $condition, $orderBy);

        $array = json_decode($categories, true);
        foreach ($array as $key => $cat_1) {
            $condition = [];
            $condition[] = ['category_1', '=', $cat_1['id']];
            $categories = $this->listing($columns, $condition, $orderBy);
            $array[$key]['subcategories'] = $categories;
        }

        $categories = $array;
        
        return response()->json($categories);
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
        $request = (object) $request->all();

        $levelOptions = [1, 2, 3, 4];
        if (!isset($request->level) || !in_array($request->level, $levelOptions) || !is_numeric($request->level)) {
            $resError = ['message' => 'category level is not set properly'];
            goto end;
        }

        if ($request->level > 1 && !isset($request->parent_id)) {
            $resError = ['message' => 'if category level is greater than 1 and parent category id must be set'];
            goto end;
        }

        if (isset($request->parent_id) && !is_numeric($request->parent_id)) {
            $resError = ['message' => 'parent category id is not numeric'];
            goto end;
        }

        // categories
        $category_1 = 0;
        $category_2 = 0;
        $category_3 = 0;
        $category_4 = 0; // default value because there's no 5th category level
        if (isset($request->parent_id)) {
            $parentCategory = Category::find($request->parent_id);
            if (!$parentCategory) {
                $resError = ['message' => 'parent category not found'];
                goto end;
            }
            $category_1 = $request->level == 2 ? $parentCategory->id : $parentCategory->category_1;
            $category_2 = $request->level == 3 ? $parentCategory->id : $parentCategory->category_2;
            $category_3 = $request->level == 4 ? $parentCategory->id : $parentCategory->category_3;
        }

        if (!isset($request->name) || empty($request->name) || strlen($request->name) > 128 || !ctype_alnum($request->name)  ) { // https://www.php.net/manual/en/book.ctype.php
            $resError = ['message' => 'there must be a category name with only letters and numbers between 3 and 128 lenght chars'];
            goto end;
        }

        $conditions = [];
        $conditions[] = ['level', '=', $request->level];
        $conditions[] = ['category_1', '=', $category_1];
        $conditions[] = ['category_2', '=', $category_2];
        $conditions[] = ['category_3', '=', $category_3];
        $conditions[] = ['category_4', '=', $category_4];
        $conditions[] = ['name', '=', $request->name];
        $result = Category::where($conditions)->first();
        if (!empty($result)) {
            $resError = ['message' => "category already exists"];
            goto end;
        }

        end:
        if (isset($resError)) {
            return response()->json($resError);

        } else {

            $slug = Str::slug($request->name, '-');

            $category = new Category();
            $category->status       = 1;
            $category->level        = $request->level;
            $category->position     = 0;
            $category->category_1   = $category_1;
            $category->category_2   = $category_2;
            $category->category_3   = $category_3;
            $category->category_4   = $category_4;           
            $category->name         = $request->name;
            $category->name_slug    = $slug;
            
            $category->save();

            return response()->json(['id' => $category->id]);
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

        $category = Category::find($id);
        unset($category->id);

        return response()->json($category);
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

        $category = Category::find($id);
        if (!$category) {
            $resError = ['message' => "id $id not found"];
            goto end;
        }

        $request = (object) $request->all();
        
        if (isset($request->status)) {
            $statusOptions = [0, 1];
            if (!in_array($request->status, $statusOptions)) {
                $resError = ['message' => 'status value can only be 0 or 1'];
                goto end;
            } else {
                $category->status = $request->status;
            }            
        }

        if (isset($request->position)) {
            if (!is_numeric($request->position)) {
                $resError = ['message' => 'position value is not numeric'];
                goto end;
            } else {
                $category->position = $request->position;
            }
        }

        if (isset($request->name)) {
            if (empty($request->name) || strlen($request->name) < 3 || strlen($request->name) > 128 || !ctype_alnum($request->name)) {
                $resError = ['message' => 'there must be a category name with only letters and lenght from 3 to 128 chars'];
                goto end;
            } else {
                $slug = Str::slug($request->name, '-');
                $category->name         = $request->name;
                $category->name_slug    = $slug;
            }            
        }

        $category->save();
        
        end:
        if (isset($resError)) {
            return response()->json($resError);
        } else {
            return response()->json(['id' => "id $id has been updated"]);
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

        $category = Category::find($id);
        if (!$category) {
            $resError = ['message' => "id $id not found"];
            goto end;
        }

        if ($category->level < 4) {
            $conditions = [];
            $conditions[] = ['level', '=', ($category->level + 1)];
            $category->level != 1 ? : $conditions[] = ['category_1', '=', $category->id];
            $category->level != 2 ? : $conditions[] = ['category_2', '=', $category->id];
            $category->level != 3 ? : $conditions[] = ['category_3', '=', $category->id];            
            $result = Category::where($conditions)->first();
            if (!empty($result)) {
                $resError = ['message' => "category has sub-categories and cannot be deleted"];
                goto end;
            }
        }

        // check if any product has this category

        end:
        if (isset($resError)) {
            return response()->json($resError);

        } else {
            $category->delete();

            return response()->json(['success' => "id $id has been deleted"]);
        }        
    }

}
