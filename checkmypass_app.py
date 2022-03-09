import requests
import hashlib
import sys


def api_request_data(query_char=""):
    """
    Checks the API connection and returns the all matched HASHES from database
    :param query_char: str - first 5 char of HASHED password
    :return:
    """
    _url = 'https://api.pwnedpasswords.com/range/' + query_char
    api_response = requests.get(_url)

    return api_response


def get_pass_num_leaks(api_res, hash_to_check=""):
    """
    Checking API response against provided 5 char HASH value
    :param api_res: class Response - API response from leaked database
    :param hash_to_check: str - hashed password without first 5 characters
    :return: int - the number of time the provided password was leaked
    """
    list_all_matched_hashes = api_res.text.split("\r\n")
    matched_hash = [i.split(":") for i in list_all_matched_hashes if i.split(":")[0] == hash_to_check]

    try:

        return int(matched_hash[0][-1])
    except IndexError:

        return 0


def convert_get_api_request(password=""):
    """
    Converts password into HASH value
    :param password: str - password to check against the leaked database
    :return: func - the call of another function to check the count of leaks
    """
    pass_encoded = password.encode('utf-8')
    pass_hash = hashlib.sha1(pass_encoded).hexdigest().upper()
    hash_head_5char, hash_tail_rest = pass_hash[:5], pass_hash[5:]

    http_res = api_request_data(hash_head_5char)

    if http_res.status_code != 200:
        raise RuntimeError('something gone wrong... please double check the connection,'
                           ' input values, and try it again.')

    return get_pass_num_leaks(http_res, hash_tail_rest)


def main(args):
    """
    Accepts password(s) and check(s) its weaknesses
    :param args: list - possible passwords to check against the database breach
    :return: str - check status
    """
    for check_password in args:
        response = convert_get_api_request(check_password)

        if response == 0:
            print(f"\nno leaks were found for provided password. good one to use it.")
        else:
            print(f"\nprobably, it's a good idea to spend more time to find a better password.")
        print(f"Password: {check_password}  \nwas leaked: {response} times")

    return '\napp is exited. thank you for using!'


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
