<?php 

// Include config file
require_once "config.php";

session_start();

// cek kalau udah login
if(isset($_SESSION['loggedin']) && $_SESSION['loggedin'] == true) {
    header("Location: index.html");
    exit();
}

$email_err = $password_err = "";

// submit form
if($_SERVER['REQUEST_METHOD'] == 'POST') {

    $email = trim($_POST['email']);
    $password = trim($_POST['password']);

    // validasi email
    if(empty($email) || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $email_err = "Invaild email!";
    }

    // validasi password
    if(empty($password)) {
        $password_err = "Password can't be empty!";
    }

    // kalau tidak ada error baru login
    if(empty($email_err) && empty($password_err)) {

        // Prepare sql statement
        $sql = "SELECT * FROM users WHERE Email = ? AND Password = ?";

        // prepare statement dan bind parameter
        $stmt = mysqli_prepare($link, $sql);
        mysqli_stmt_bind_param($stmt, 'ss', $param_email, $param_pass);

        // set parameters
        $param_email = $email;
        $param_pass = $password;

        // execute sql
        if(mysqli_stmt_execute($stmt)) {
            // berhasil execute statement

            // store result
            mysqli_stmt_store_result($stmt);

            if(mysqli_stmt_num_rows($stmt) == 1) {
                // sudah berhasil login

                // memasukkan hasil query kedalam variabel
                mysqli_stmt_bind_result($stmt, $userid);
                mysqli_stmt_fetch($stmt);

                $_SESSION['loggedin'] = true;
                $_SESSION['userid'] = $userid;

                // redirect ke halaman utama
                header("Location: index.html");
            }
            else {
                // password salah
                $password_err = "Invalid credentials!";
            }

        } else {
            // gagal execute statement
            echo "<script type='text/javascript'>alert('Something went wrong, please try again later...');</script>";
        }

        // close statement
        mysqli_stmt_close($stmt);

    }
}

?>

<!DOCTYPE html>
<html lang="en">
<head>
    <!-- Required meta tags -->
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">

    <!-- Bootstrap CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.0.0-beta1/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-giJF6kkoqNQ00vy+HMDP7azOuL0xtbfIcaT9wjKHr8RbDVddVHyTfAAsrekwKmP1" crossorigin="anonymous">

    <!-- Font -->
    <script src="https://kit.fontawesome.com/af40733f6e.js" crossorigin="anonymous"></script>
    <link rel="preconnect" href="https://fonts.gstatic.com">
    <link href="https://fonts.googleapis.com/css2?family=Noto+Sans+KR:wght@300;400&display=swap" rel="stylesheet">

    <!-- CSS -->
    <link rel="stylesheet" href="css/login.css">

    <title>Login</title>
</head>
<body style="background-image:url(imgs/main_in.jpg); background-size:cover;">
<main class="form-login text-center">
        <a href="index.html"><img class="mb-4" src="imgs/logo.png" alt="" width="80" height="80"></a>

        <h1 class="h3 mb-3 fw-normal">Login</h1>

        <form action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post">

            <div class="form-group py-2 <?php echo (!empty($email_err)) ? 'has-error' : ''; ?>">
                <input type="text" name="email" class="form-control" placeholder="Email">
                    <span class="help-block"><?php echo $email_err; ?></span>
            </div>

            <div class="form-group py-2 <?php echo (!empty($password_err)) ? 'has-error' : ''; ?>">
                <input type="password" name="password" class="form-control" placeholder="Password">
                    <span class="help-block"><?php echo $password_err; ?></span>
            </div>
            
            <div class="form-group">
                <input type="submit" class="btn btn-primary" value="Submit">
            </div>
        </form>
    </main>
</body>
</html>