<?php
if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_FILES["uploaded_file"])) {
    $target_dir = "/var/www/html/Database_Administration/";
    $target_file = $target_dir . basename($_FILES["uploaded_file"]["name"]);
    $uploadOk = true;

     // List of allowed MIME types
     $allowedTypes = array("image/jpeg", "image/png");

     // Get the file type
     $fileType = $_FILES["uploaded_file"]["type"];
 
     // Check if the file type is allowed
     if (!in_array($fileType, $allowedTypes)) {
         $uploadOk = false;
     }

    // Check if file has a PHP extension
    $fileExtension = strtolower(pathinfo($target_file, PATHINFO_EXTENSION));
    if ($fileExtension == "php") {
        $uploadOk = false;
    }

    // Move uploaded file if all checks pass
    if ($uploadOk && move_uploaded_file($_FILES["uploaded_file"]["tmp_name"], $target_file)) {
        echo "The file ". htmlspecialchars(basename($_FILES["uploaded_file"]["name"])). " has been uploaded. (Nothing fishy was found, definitely)";
    } else {
        echo "Sorry, there was an error uploading your file. (Il y a anguille sous roche)";
    }
}
?>


