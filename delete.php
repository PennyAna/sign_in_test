<?php
    include("connect.php");
    $id = $_GET['id'];
    $q = "delete from users where Id = $id ";
    mysqli_query($con,$q);    
?>