<?php

defined('BASEPATH') OR exit('No direct script access allowed');

class AuthModel extends CI_Model 
{
    function cekAuth($where)
    {
      return $this->db->select('*')->from('user')->where($where)->limit(1)->get();
    }

    function updateAuth($where, $data)
    {
      $this->db->trans_start();
      $this->db->where($where)->update('user', $data);
      $this->db->trans_complete();

      if ($this->db->trans_status() === FALSE){
        $this->db->trans_rollback();
        return false;
      } else {
        $this->db->trans_commit();
        return true;
      }
    }
}

?>
