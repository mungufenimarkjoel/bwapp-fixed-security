<?php

/*

bWAPP, or a buggy web application, is a free and open source deliberately insecure web application.
It helps security enthusiasts, developers and students to discover and to prevent web vulnerabilities.
bWAPP covers all major known web vulnerabilities, including all risks from the OWASP Top 10 project!
It is for security-testing and educational purposes only.

Enjoy!

Malik Mesellem
Twitter: @MME_IT

bWAPP is licensed under a Creative Commons Attribution-NonCommercial-NoDerivatives 4.0 International License (http://creativecommons.org/licenses/by-nc-nd/4.0/). Copyright © 2014 MME BVBA. All rights reserved.

*/

include("security.php");
include("security_level_check.php");
include("functions_external.php");
include("selections.php");

// Sets the directory
$directory = "documents";

// ========== FIXED CODE - Secure File Download ==========
// Downloads a file
if(isset($_GET["file"])) 
{
    $requested_file = $_GET["file"];
    
    // ========== SECURITY FIX #1: Whitelist allowed files ==========
    // Define exactly which files are allowed to be downloaded
    $allowed_files = [
        "documents/readme.txt",
        "documents/user_manual.pdf",
        "documents/terms_and_conditions.txt",
        "documents/privacy_policy.txt",
        "documents/license.txt"
    ];
    
    // ========== SECURITY FIX #2: Sanitize and validate ==========
    // Remove any path traversal attempts
    $safe_file = basename($requested_file);
    
    // Construct the full path safely
    $full_path = "./" . $directory . "/" . $safe_file;
    
    // Normalize the path to resolve any ../ sequences
    $real_path = realpath($full_path);
    
    // Define the allowed directory base path
    $base_dir = realpath("./" . $directory);
    
    // ========== SECURITY FIX #3: Validate file is within allowed directory ==========
    if ($real_path !== false && strpos($real_path, $base_dir) === 0) {
        
        // Also check if the file is in the whitelist
        $relative_path = str_replace($base_dir . "/", "", $real_path);
        
        if (in_array($directory . "/" . $relative_path, $allowed_files) || in_array($relative_path, $allowed_files)) {
            
            // Checks if the file exists
            if(is_file($real_path)) 
            {
                // Debugging
                // echo $file;      
                
                header("Content-Description: File Transfer");
                header("Content-Type: application/octet-stream");
                header("Content-Disposition: attachment; filename=" . basename($real_path));
                header("Content-Transfer-Encoding: binary");
                header("Expires: 0");
                header("Cache-Control: must-revalidate");
                header("Pragma: public");
                header("Content-Length: " . filesize($real_path));

                ob_clean();
                flush();
                readfile($real_path) or die("Couldn't open file.");
                exit;
            }
            else
            {
                die("File not found.");
            }
        }
        else
        {
            // Log unauthorized access attempt
            error_log("Unauthorized file access attempt: " . $requested_file . " from " . $_SERVER['REMOTE_ADDR']);
            die("Access denied. You are not authorized to download this file.");
        }
    }
    else
    {
        // Log path traversal attempt
        error_log("Path traversal attempt blocked: " . $requested_file . " from " . $_SERVER['REMOTE_ADDR']);
        die("Invalid file path.");
    }
}

?>
<!DOCTYPE html>
<html>
    
<head>
        
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">

<!--<link rel="stylesheet" type="text/css" href="https://fonts.googleapis.com/css?family=Architects+Daughter">-->
<link rel="stylesheet" type="text/css" href="stylesheets/stylesheet.css" media="screen" />
<link rel="shortcut icon" href="images/favicon.ico" type="image/x-icon" />

<!--<script src="//html5shiv.googlecode.com/svn/trunk/html5.js"></script>-->
<script src="js/html5.js"></script>

<title>bWAPP - Missing Functional Level Access Control</title>

</head>

<body>
    
<header>

<h1>bWAPP</h1>

<h2>an extremely buggy web app !</h2>

</header>    

<div id="menu">
      
    <table>
        
        <tr>
            
            <td><a href="portal.php">Bugs</a></td>
            <td><a href="password_change.php">Change Password</a></td>
            <td><a href="user_extra.php">Create User</a></td>
            <td><a href="security_level_set.php">Set Security Level</a></td>
            <td><a href="reset.php" onclick="return confirm('All settings will be cleared. Are you sure?');">Reset</a></td>            
            <td><a href="credits.php">Credits</a></td>
            <td><a href="http://itsecgames.blogspot.com" target="_blank">Blog</a></td>
            <td><a href="logout.php" onclick="return confirm('Are you sure you want to leave?');">Logout</a></td>
            <td><font color="red">Welcome <?php if(isset($_SESSION["login"])){echo ucwords($_SESSION["login"]);}?></font></td>
            
        </tr>
        
    </table>   
   
</div> 

<div id="main">
    
    <h1>Restrict Folder Access</h1>

    <p>Only authorized users have access to the <i><?php echo $directory ?></i> folder.</p>

    <p>Log off and try to access files in this directory...</p>

    <?php

    switch($_COOKIE["security_level"])
    {

        case "0" :            

            // ========== SECURITY FIX #4: Never delete .htaccess at low level ==========
            // Instead, we'll still show files but with proper validation
            // Deletes the '.htaccess' file (REMOVED FOR SECURITY - we want protection at all levels)
            // if(file_exists($directory . "/.htaccess"))
            // {    
            //     unlink($directory . "/.htaccess");
            // }
            
            // Create .htaccess for protection even at "low" level
            $fp = fopen($directory . "/.htaccess", "w");
            fputs($fp, "Deny from all\n", 200);
            fputs($fp, "<FilesMatch '\.(jpg|jpeg|png|gif|pdf|txt)$'>\n", 200);
            fputs($fp, "    Allow from all\n", 200);
            fputs($fp, "</FilesMatch>", 200);
            fclose($fp);

            $dp = opendir($directory);

            while($line = readdir($dp))
            {

                if($line != "." && $line != ".." && $line != ".htaccess")
                {

                    // ========== SECURITY FIX #5: Use secure download handler ==========
                    echo "<a href=\"restrict_folder_access.php?file=" . urlencode($directory . "/" . $line) . "\">" . htmlspecialchars($line) . "</a><br />";

                }

            }        
            break;

        case "1" :  

            // Creates the '.htaccess' file
            $fp = fopen($directory . "/.htaccess", "w");
            fputs($fp, "Deny from all\n", 200);
            fputs($fp, "<FilesMatch '\.(jpg|jpeg|png|gif|pdf|txt)$'>\n", 200);
            fputs($fp, "    Allow from all\n", 200);
            fputs($fp, "</FilesMatch>", 200);
            fclose($fp);

            $dp = opendir($directory);

            while($line = readdir($dp))
            {

                if($line != "." && $line != ".." && $line != ".htaccess")
                {

                    echo "<a href=\"restrict_folder_access.php?file=" . urlencode($directory . "/" . $line) . "\">" . htmlspecialchars($line) . "</a><br />";

                }

            }

            break;

        case "2" :

            // Creates the '.htaccess' file
            $fp = fopen($directory . "/.htaccess", "w");
            fputs($fp, "deny from all\n", 200);
            fputs($fp, "<FilesMatch '\.(jpg|jpeg|png|gif|pdf|txt)$'>\n", 200);
            fputs($fp, "    Allow from all\n", 200);
            fputs($fp, "</FilesMatch>", 200);
            fclose($fp);

            $dp = opendir($directory);

            while($line = readdir($dp))
            {

                if($line != "." && $line != ".." && $line != ".htaccess")
                {

                    echo "<a href=\"restrict_folder_access.php?file=" . urlencode($directory . "/" . $line) . "\">" . htmlspecialchars($line) . "</a><br />";

                }

            }

            break;

        default :

            // ========== SECURITY FIX #6: Apply protection at default level too ==========
            // Create .htaccess for protection
            $fp = fopen($directory . "/.htaccess", "w");
            fputs($fp, "Deny from all\n", 200);
            fputs($fp, "<FilesMatch '\.(jpg|jpeg|png|gif|pdf|txt)$'>\n", 200);
            fputs($fp, "    Allow from all\n", 200);
            fputs($fp, "</FilesMatch>", 200);
            fclose($fp);

            $dp = opendir($directory);

            while($line = readdir($dp))
            {

                if($line != "." && $line != ".." && $line != ".htaccess")
                {

                    echo "<a href=\"restrict_folder_access.php?file=" . urlencode($directory . "/" . $line) . "\">" . htmlspecialchars($line) . "</a><br />";

                }

            }   

            break;

    }

    ?>


</div>
    
<div id="side">    
    
    <a href="http://twitter.com/MME_IT" target="blank_" class="button"><img src="./images/twitter.png"></a>
    <a href="http://be.linkedin.com/in/malikmesellem" target="blank_" class="button"><img src="./images/linkedin.png"></a>
    <a href="http://www.facebook.com/pages/MME-IT-Audits-Security/104153019664877" target="blank_" class="button"><img src="./images/facebook.png"></a>
    <a href="http://itsecgames.blogspot.com" target="blank_" class="button"><img src="./images/blogger.png"></a>

</div>     
    
<div id="disclaimer">
          
    <p>bWAPP is licensed under <a rel="license" href="http://creativecommons.org/licenses/by-nc-nd/4.0/" target="_blank"><img style="vertical-align:middle" src="./images/cc.png"></a> &copy; 2014 MME BVBA / Follow <a href="http://twitter.com/MME_IT" target="_blank">@MME_IT</a> on Twitter and ask for our cheat sheet, containing all solutions! / Need an exclusive <a href="http://www.mmebvba.com" target="_blank">training</a>?</p>
   
</div>
    
<div id="bee">
    
    <img src="./images/bee_1.png">
    
</div>
    
<div id="security_level">
  
    <form action="<?php echo($_SERVER["SCRIPT_NAME"]);?>" method="POST">
        
        <label>Set your security level:</label><br />
        
        <select name="security_level">
            
            <option value="0">low</option>
            <option value="1">medium</option>
            <option value="2">high</option> 
            
        </select>
        
        <button type="submit" name="form_security_level" value="submit">Set</button>
        <font size="4">Current: <b><?php echo $security_level?></b></font>
        
    </form>   
    
</div>
    
<div id="bug">

    <form action="<?php echo($_SERVER["SCRIPT_NAME"]);?>" method="POST">
        
        <label>Choose your bug:</label><br />
        
        <select name="bug">
   
<?php

// Lists the options from the array 'bugs' (bugs.txt)
foreach ($bugs as $key => $value)
{
    
   $bug = explode(",", trim($value));
   
   // Debugging
   // echo "key: " . $key;
   // echo " value: " . $bug[0];
   // echo " filename: " . $bug[1] . "<br />";
   
   echo "<option value='$key'>$bug[0]</option>";
 
}

?>


        </select>
        
        <button type="submit" name="form_bug" value="submit">Hack</button>
        
    </form>
    
</div>
      
</body>
    
</html>