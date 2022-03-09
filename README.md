This app uses an API request to fetch data from a database of www.haveibeenpwned.com to match hash values against the provided by the user (via sys in CMD) 'possible' passwords to see how many times they were leaked in other organizations. 

API format: GET https://api.pwnedpasswords.com/range/{first 5 hash chars}
API source: https://haveibeenpwned.com/API/v3

To run this app (in CMD on Windows 10):  python3 checkmypass_app.py [your_password]
