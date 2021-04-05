<?php
// Include config file
require_once "config.php";
function console_log($output, $with_script_tags = true) {
    $js_code = 'console.log(' . json_encode($output, JSON_HEX_TAG) .');';
    if ($with_script_tags) {
        $js_code = '<script>' . $js_code . '</script>';
    }
    echo $js_code;
}
// Define variables and initialize with empty values
$username = $email = $phone  = $password = $confirm_password = $Gender = "";
$username_err = $email_err = $phone_err = $Gender_err = $password_err = $confirm_password_err = "";

// Processing form data when form is submitted
if($_SERVER["REQUEST_METHOD"] == "POST"){

    // Validate username
    if(empty(trim($_POST["username"]))){
        $username_err = "Please enter a username.";
    } else{
        if (strlen(trim($_POST["username"])) < 5 && strlen(trim($_POST["username"])) > 15) {
            $username_err = "Invalid length.";
        } else {
            $username = trim($_POST["username"]);
        }
    }
    // Validate Gender
    if(isset($_POST['Gender'])){
      
        $Check[] = $_POST['Gender'];
        if (count($Check) > 1) {
            $Gender_err = "Please Check one box.";
        } else {
            $Gender = $_POST["Gender"];
        }
    }

    // Validate email
    if(empty(trim($_POST["email"]))){
        $email_err = "Please enter a username.";
    } else{
        if (!filter_var(trim($_POST["email"]), FILTER_VALIDATE_EMAIL)) {
            $email_err = "Invalid email format.";
        } else {
            $email = trim($_POST["email"]);
        }
    }

    // Validate phone
    if(empty(trim($_POST["phone"]))) {
        $phone_err = "Please enter a username.";
    } else {
        //eliminate every char except 0-9
        $justNums = preg_replace("/[^0-9]/", '', trim($_POST["phone"]));

        //if we have 10 digits left, it's probably valid.
        if (strlen($justNums) < 10) {
            $phone_err = "Invalid phone format.";
        } else {
            $phone = trim($_POST["phone"]);
        }
    }


    // Validate password
    if(empty(trim($_POST["password"]))){
        $password_err = "Please enter a password.";
    } elseif(strlen(trim($_POST["password"])) < 6){
        $password_err = "Password must have atleast 6 characters.";
    } else{
        $password = trim($_POST["password"]);
    }

    // Validate confirm password
    if(empty(trim($_POST["confirm_password"]))){
        $confirm_password_err = "Please confirm password.";
    } else{
        $confirm_password = trim($_POST["confirm_password"]);
        if(empty($password_err) && ($password != $confirm_password)){
            $confirm_password_err = "Password did not match.";
        }
    }

    // Check input errors before inserting in database
    if(empty($username_err) && empty($email_err) && empty($phone_err) && empty($password_err) && empty($confirm_password_err)){

        // Prepare an insert statement
        $sql = "INSERT INTO users (userid, username, email, notelp, password, gender) VALUES (?, ?, ?, ?, ?, ?)";

        if($stmt = mysqli_prepare($link, $sql)){
            // Bind variables to the prepared statement as parameters
            mysqli_stmt_bind_param($stmt, "ssssss", $param_id, $param_username, $param_email, $param_phone, $param_password, $param_gender);

            // Set parameters
            $uniqid = uniqid();
            $param_id = substr($uniqid, 0, 5);
            $param_username = $username;
            $param_email = $email;
            $param_phone = $phone;
            $param_password = $password;
            $param_gender = $Gender;


            // Attempt to execute the prepared statement
            if(mysqli_stmt_execute($stmt)){
                // Redirect to login page
                header("location: login.php");
            } else{
                $message =  "Something went wrong. Please try again later.";
                echo "<script type='text/javascript'>alert('$message');</script>";
            }

            // Close statement
            mysqli_stmt_close($stmt);
        }
    }


    // Close connection
    mysqli_close($link);
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
    <link rel="stylesheet" href="css/signin.css">
</head>
<body style="background-image:url(imgs/main_in.jpg); background-size:cover;">
    <main class="form-signin text-center">
        <a href="index.html"><img class="mb-4" src="imgs/logo.png" alt="" width="80" height="80"></a>
        <h1 class="h3 mb-3 fw-normal">Register</h1>
        <p>Please fill this form to create an account.</p>
        <form action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post">
            <div class="form-group py-2 <?php echo (!empty($username_err)) ? 'has-error' : ''; ?>">
                <input type="text" name="username" class="form-control" placeholder="Username" value="<?php echo $username; ?>">
                    <span class="help-block"><?php echo $username_err; ?></span>
            </div>
            <div class="form-group py-2 <?php echo (!empty($Gender_err)) ? 'has-error' : ''; ?>">
              <input type="checkbox" name="Gender" value="M">
                <label for="Gender"> Male</label>
              <input type="checkbox" name="Gender" value="F">
                <label for="Gender"> Female</label>
                  <span class="help-block"><?php echo $Gender_err; ?></span>
            </div>
            <div class="form-group py-2 <?php echo (!empty($email_err)) ? 'has-error' : ''; ?>">
                <input type="text" name="email" class="form-control" placeholder="Email" value="<?php echo $email; ?>">
                    <span class="help-block"><?php echo $email_err; ?></span>
            </div>
            <div class="form-group py-2 <?php echo (!empty($phone_err)) ? 'has-error' : ''; ?>">
                <input type="text" name="phone" class="form-control" placeholder="Phone" value="<?php echo $phone; ?>">
                    <span class="help-block"><?php echo $phone_err; ?></span>
            </div>

            <div class="form-group py-2 <?php echo (!empty($password_err)) ? 'has-error' : ''; ?>">
                <input type="password" name="password" class="form-control" placeholder="Password">
                    <span class="help-block"><?php echo $password_err; ?></span>
            </div>
            <div class="form-group py-2 <?php echo (!empty($confirm_password_err)) ? 'has-error' : ''; ?>">
                <input type="password" name="confirm_password" class="form-control" placeholder="Confirm password">
                    <span class="help-block"><?php echo $confirm_password_err; ?></span>
            </div>
            <div class="form-group">
                <input type="submit" class="btn btn-primary" value="Submit">
                <input type="reset" class="btn btn-default" value="Reset">
            </div>
            <p>Already have an account? <a href="login.php">Login here</a>.</p>
        </form>
    </main>
</body>
</html>
