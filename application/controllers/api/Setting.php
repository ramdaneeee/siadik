<?php
defined('BASEPATH') OR exit('No direct script access allowed');

require 'vendor/autoload.php';

use chriskacerguis\RestServer\RestController;

class Setting extends RestController {

    function __construct()
    {
        parent::__construct();

        $this->token    = $this->input->get_request_header('Siadik-Token', TRUE);
        $this->auth     = AUTHORIZATION::validateToken($this->token);

        $this->load->model('AuthModel');
    }

    public function verify_user_get()
    {
        if(!$this->auth){
            $this->response(['status' => false, 'error' => 'Invalid Token'], 400);
        } else {
            $where  = array('id_user' => $this->auth->id_user);
            $user   = $this->AuthModel->cekAuth($where);

            if($user->num_rows() == 0){
                $this->response(['status' => false, 'error' => 'User tidak ditemukan'], 400);
            } else {
                $auth = $user->row();

                $payload = array(
                    'id_user' => $auth->id_user,
                    'username' => $auth->username,
                    'password' => $auth->password,
                    'telepon' => $auth->telepon,
                    'aktif' => $auth->aktif,
                    'level' => strtolower($auth->level)
                );

                $this->response(['status' => true, 'message' => 'Berhasil verifikasi user', 'data' => $payload], 200);
            }

            
        }
    }

    public function change_password_put()
    {
        if(!$this->auth){
            $this->response(['status' => false, 'error' => 'Invalid Token'], 400);
        } else {
            $otorisasi = $this->auth;

            $config = array(
                array(
                    'field' => 'old_password',
                    'label' => 'Password Lama',
                    'rules' => 'required|trim'
                ),
                array(
                    'field' => 'new_password',
                    'label' => 'Password Baru',
                    'rules' => 'required|trim'
                ),
                array(
                    'field' => 'retype_password',
                    'label' => 'Ulangi Password',
                    'rules' => 'required|trim|matches[new_password]'
                )
            );
        
            $this->form_validation->set_data($this->put());
            $this->form_validation->set_rules($config);

            if(!$this->form_validation->run()){
                $this->response(['status' => false, 'error' => $this->form_validation->error_array()], 400);
            }else{
                $where  = array('id_user' => $otorisasi->id_user);
                $fetch  = $this->AuthModel->cekAuth($where);

                if($fetch->num_rows() == 0){
                    $this->response(['status' => false, 'error' => 'User tidak ditemukan'], 400);
                } else {
                    $user = $fetch->row();

                    if(hash_equals($this->put('old_password'), $user->password)){
                        $data   = array(
                            'password' => $this->put('new_password')
                        );

                        $update = $this->AuthModel->updateAuth($where, $data);

                        if(!$update){
                            $this->response(array('status' => false, 'error' => 'Gagal mengganti password'), 500);
                        } else {
                            $this->response(array('status' => true, 'message' => 'Berhasil mengganti password'), 200);
                        }
                    } else {
                        $this->response(['status' => false, 'error' => 'Password salah'], 400);
                    }
                }
            }
        }
    }

    public function edit_profile_put()
    {
        if(!$this->auth){
            $this->response(['status' => false, 'error' => 'Invalid Token'], 400);
        } else {
            $otorisasi = $this->auth;

            $config = array(
                array(
                    'field' => 'nama_lengkap',
                    'label' => 'Nama Lengkap',
                    'rules' => 'required|trim'
                ),
                array(
                    'field' => 'telepon',
                    'label' => 'Telepon',
                    'rules' => 'required|trim'
                )
            );
        
            $this->form_validation->set_data($this->put());
            $this->form_validation->set_rules($config);

            if(!$this->form_validation->run()){
                $this->response(['status' => false, 'error' => $this->form_validation->error_array()], 400);
            }else{
                $where  = array('id_user' => $otorisasi->id_user);

                $data   = array(
                    'nama_lengkap' => $this->put('nama_lengkap'),
                    'telepon' => $this->put('telepon'),
                );

                $update = $this->AuthModel->updateAuth($where, $data);

                if(!$update){
                    $this->response(array('status' => false, 'error' => 'Gagal mengedit profile'), 500);
                } else {
                    $this->response(array('status' => true, 'message' => 'Berhasil mengedit profile'), 200);
                }
            }
        }
    }

    public function logout_get()
    {
        if(!$this->auth){
            $this->response(['status' => false, 'error' => 'Invalid Token'], 400);
        } else {
            
            $this->response(array('status' => true, 'message' => 'Berhasil logout'), 200);
        }
    }

    

}
