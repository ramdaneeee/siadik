<?php

defined('BASEPATH') OR exit('No direct script access allowed');
require 'vendor/autoload.php';

use chriskacerguis\RestServer\RestController;

class Auth extends RestController 
{
    function __construct()
  {
    parent::__construct();

		$this->load->model('AuthModel');
  }

  public function index_post()
    {
        $config = array(
            array(
                'field' => 'username',
                'label' => 'Username',
                'rules' => 'required'
            ),
            array(
                'field' => 'password',
                'label' => 'Password',
                'rules' => 'required'
            )
        );
    
        $this->form_validation->set_data($this->post());
        $this->form_validation->set_rules($config);

        if(!$this->form_validation->run()){
            $this->response(['status' => false, 'error' => $this->form_validation->error_array()], 400);
        }else{

            $where  = array(
                'username' => $this->post('username')
            );
            
            $user   = $this->AuthModel->cekAuth($where);

            if($user->num_rows() == 0){
                $this->response(['status' => false, 'error' => 'Username tidak ditemukan'], 400);
            } else {
                $auth = $user->row();

                $payload = array(
                    'id_user' => $auth->id_user,
                    'level' => strtolower($auth->level),
                    'username' => $auth->username
                );

                $session = array(
                    'key'   => AUTHORIZATION::generateToken($payload),
                    'level' => strtolower($auth->level)
                );
                
                if(hash_equals($this->post('password'), $auth->password)){
                    if($auth->aktif != 'Y'){
                        $this->response(['status' => false, 'error' => 'User sudah tidak aktif'], 400);
                    } else {
                        $data = array(
                            'id_user' => $auth->id_user,
                            'referensi' => 'Login',
                            'deskripsi' => 'Berhasil melakukan Login'
                        );

                        // $this->LogModel->add($data);
                        $this->response(['status' => true, 'message' => 'Berhasil login. Selamat Datang di SIPF', 'data' => $session], 200);
                    }
                } else {
                    $this->response(['status' => false, 'error' => 'Password salah'], 400);
                }
            }
        }  
    }
  // Login
    // function login_user_post()
    // {
    //     $username = $this->post('username');
    //     $password = $this->post('password');
    //     $where = array(
    //         'username' => $username,
    //         'password' => $password
    //         );
    //     $user = $this->AuthModel->loginUser($username);

    //     foreach($user->result() as $key){
    //         $password    = $key->password;
    //         $session = array(
    //           'id_user'        => $key->id_user,
    //           'nama_lengkap'   => $key->nama_lengkap,
    //           'username'       => $key->username,
    //           'password'       => $key->password,
    //           'telepon'        => $key->telepon,
    //           'aktif'          => $key->aktif,
    //           'level'          => $key->level
    //         );
    //     $this->response(['status' => true, 'message' => 'Berhasil menampilkan user', 'data' => $session], 200);
    //     }
    // }

}
 ?>
