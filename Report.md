# Report of XSS Vulnerabilities

### Alberto Giust Mat. 211460
### Security Testing
### Project: inventory-management-system

## True Positives

## False Positives

- **xss_dashboard.php_3_min** is a false positive because the echo function prints out the number of rows returned by the SQL query. There is no user input printed because this number is calculated by `mysqli_num_rows()` function. 