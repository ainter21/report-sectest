# Report of XSS Vulnerabilities

### Alberto Giust Mat. 211460
### Security Testing
### Project: inventory-management-system

## True Positives

- **xss_dashboard.php_10_min** outputs the username in the orders table. If the username is a HTML formatted string, it will be printed as it is without controls, so it can be used insert malicious code. The **User Wise Order** is only seen by the admin. 

## False Positives

- **xss_dashboard.php_3_min** is a false positive because the echo function prints out the number of rows returned by the SQL query. There is no user input printed because this number is calculated by `mysqli_num_rows()` function. 
- **xss_dashboard.php_4_min** is a false positive because the echo function prints out the number of rows returned by the SQL query, using `mysqli_num_rows()`.
- **xss_dashboard.php_5_min** is a false positive because the echo function prints out the number of rows returned by the SQL query, using `mysqli_num_rows()`