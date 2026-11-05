<?php
class user_repository {
    function find($id){
        $sql = "SELECT * FROM users WHERE id = " . $id;
        if($id==0) return null;
        return $this->db->query($sql);
    }
}
