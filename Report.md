# Report of XSS Vulnerabilities

### Alberto Giust ID 211460
### Security Testing
### Project: inventory-management-system

## True Positives

- **xss_dashboard.php_10_min** outputs the username in the orders table. If the username is a HTML formatted string, it will be printed as it is without controls, so it can be used insert malicious code. The **User Wise Order** is only seen by the admin.
  - **Attack vector**: change the username from user setting with HTML code
  - **Fix**: output the username after it has been sanitized with `htmlentities($orderResult['username'])`
- **xss_fetchBrand.php_1_min** outputs the brand name, the availability and a button to edit or remove it. It is a xss vulnerability because the brand name with HTML malicious code.
  - **Attack vector**: create a brand with this name `<h1>Malicious</h1>`. It will be formatted as an `<h1>` item.
  - **Fix**: sanitize the name of the brand with `htmlentities`.
- **xss_fetchCategories.php_1_min** fetchs al the categories created. The user with the right riviligies can inject malicious code in the category name and this will be printed as HTML formatted text. It is a vulnerability
  - **Attack vector**: create a new category with this name: `<h1>Malicious</h1>`
  - **Fix**: sanitize the output of tht query (`row[1]` contains the name of the category, so you have to call `htmlentities` on it). 
- **xss_product.php_1_min**: this is a true sink because the query fetches all the brand to populate the select item for the creation of a new product. As a result, the attacker can create a brand with javascript code that won't be printed in the select option, but it will be executed when the page will be created. 
  - **Attack vector**: create a brand with malicious javascript code in the name (`Malicious<script>alert("Hello)</script>"`) and load the product page. An alert message will be printed on the screen.
  - **Fix**: sanitize the name of the brand with `htmlentities()`. However, in the product page the the list of brands are fetched two times so two alert dialogs will be shown. To completely fix this vulnerability it's needed to fix both of the outputs, this one and the one at line 267, which is found by pixy in the `xss_product.php_3_min` file. After fixing this vulnerability, no more alert dialogs will be shown, and the test will fail.


## False Positives

- **xss_dashboard.php_3_min**: the echo function prints out the number of rows returned by the SQL query. There is no user input printed because this number is calculated by `mysqli_num_rows()` function. 
- **xss_dashboard.php_4_min**: the echo function prints out the number of rows returned by the SQL query, using `mysqli_num_rows()`.
- **xss_dashboard.php_5_min**: the echo function prints out the number of rows returned by the SQL query, using `mysqli_num_rows()`
- **xss_dashboard.php_11_min**: there is no way to exploit the total order amount to inject some malicious code. If you try to add a new product with amount that has html code in it, and then you try to create an order from it, you won't be able to see this order anywhere after it has been created (probably because the amount during the creation is set  to `Nan`). 
- **xss_index.php_2_min**: `$_SERVER['PHP_SELF']` is set up from the webserver, and no user input is printed out.
- **xss_createBrand.php_1_min**: `echo json_encode($valid);` outputs a string not written by the user that asserts that the query has been succesful.
- **xss_removeBrand.php_1_min**: `echo json_encode($valid);` outputs a strig that states the result status of an execution of a query. This string is not written by the user.
- **xss_editBrand.php_1_min**: the echo funtion outputs a string not written by the user.
- **xss_fetchSelectedBrand.php_1_min**: `echo json_encode($row);` is used to return a json oject used to populate the editBrand pop-up dialog box. However in the input text the text is not formated as HTML so the attacker can't exploit this echo call to insert malicious code, and the admin will be able to see the source code inserted by the attacker.
![fetch selected Brand](./images/fetchselectedBrand.png)
- **xss_editBrand.php_1_min**: it outputs a not modifiable string to confirm the quesy has been performed
- **xss_createCategories.php_1_min**: the echo function prints a pre defined string used to tell the user the if the query has been performed
- **xss_removeCategories.php_1_min**: the echo function prints if the query has been performed correctly or not. The user can't insert custom value for this string.
- **fetchSelectedCategories.php_1_min**: the echo function populates the editCategory pop-up dialog, but the the name of the category is not formatted in HTML, but in palin text, so the attacke can't exploits this sink.
- **xss_editCategories.php_1_min**: the echo function outputs a string written by the webmaster to confirm the edit category action has been performed correctly.
- 